"""Canonical, redacted, deterministic scan report construction."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
import hashlib
import json
from pathlib import PurePath
import re
from typing import Any, Iterable, Mapping

from .config import Limits


REPORT_SCHEMA_VERSION = 1
_EXCERPT_LIMIT = 160
_SEVERITIES = frozenset(("critical", "high", "medium", "low", "info", "unknown"))
_SEVERITY_ORDER = {value: index for index, value in enumerate(("critical", "high", "medium", "low", "info", "unknown"))}
_RULE_SEVERITIES = {
    "SECRET001": "critical", "SECRET002": "medium", "PY001": "high",
    "PY002": "high", "PY003": "high", "PY004": "high",
}
_PEM = re.compile(r"-----BEGIN (?:[A-Z0-9 ]* )?PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9 ]* )?PRIVATE KEY-----|\Z)", re.IGNORECASE | re.DOTALL)
_CREDENTIAL = re.compile(r"(?im)(\b[A-Za-z_][A-Za-z0-9_]*(?:token|secret|password|api[_-]?key)[A-Za-z0-9_]*\s*=\s*)[^\r\n]+")
_URL_CREDENTIALS = re.compile(r"([a-z][a-z0-9+.-]*://)[^/@\s:]+(?::[^/@\s]*)?@", re.IGNORECASE)
_ABSOLUTE_PATH = re.compile(r"(?:(?:[A-Za-z]:[\\/])|(?:\\\\)|/)[^\s|`<>]*")


class ReportError(ValueError):
    """Raised when untrusted analyzer output cannot become a safe report."""


def canonical_bytes(report: Mapping[str, Any]) -> bytes:
    """Serialize report JSON deterministically, without whitespace variation."""
    return json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_report(
    state: Mapping[str, Any],
    adapter_results: Iterable[Mapping[str, Any] | object] = (),
    *,
    limits: Limits | Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """Build the only report source of truth from durable state and adapter outcomes.

    The state-owned integer fields are copied exactly.  This routine never accepts a
    root path and therefore cannot put one into the artifact.
    """
    state_data = _mapping(state, "state")
    active_limits = _limits(limits if limits is not None else state_data.get("limits", {}))
    checks = [_check(value) for value in adapter_results]
    checks.sort(key=lambda item: (item["id"], item["version"], item["provenance"]))
    findings = [_finding(finding, check) for check in checks for finding in check.pop("_findings")]
    findings = _deduplicate(findings)
    uncertainty = _uncertainty(checks)
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "scan_id": _string(state_data.get("scan_id"), "scan_id"),
        "revision": _integer(state_data.get("revision"), "revision"),
        "state": _string(state_data.get("state"), "state"),
        "head": _head(state_data.get("head")),
        "limits": _integer_mapping(state_data.get("limits", {}), "limits"),
        "progress": _integer_mapping(state_data.get("progress", {}), "progress"),
        "checks": checks,
        "findings": findings,
        "uncertainty": uncertainty,
        "notice": "canonical report; paths and evidence are redacted",
    }
    _bound_findings(report, active_limits["findings"])
    _bound_json(report, active_limits["json_bytes"])
    return report


def make_report(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Compatibility name for the canonical report constructor."""
    return build_report(*args, **kwargs)


build_canonical_report = build_report


def _mapping(value: Mapping[str, Any] | object, label: str) -> dict[str, Any]:
    if is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)
    if not isinstance(value, Mapping):
        raise ReportError(f"{label} must be an object")
    return dict(value)


def _limits(value: Limits | Mapping[str, int]) -> dict[str, int]:
    if isinstance(value, Limits):
        return {name: getattr(value, name) for name in value.__dataclass_fields__}
    result = _integer_mapping(value, "limits")
    for name in ("findings", "json_bytes"):
        if name not in result or result[name] < 1:
            raise ReportError(f"limits.{name} must be a positive integer")
    return result


def _integer_mapping(value: object, label: str) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise ReportError(f"{label} must be an object")
    result: dict[str, int] = {}
    for key, item in value.items():
        if not isinstance(key, str) or type(item) is not int or item < 0:
            raise ReportError(f"{label} must contain non-negative integer values")
        result[key] = item
    return result


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReportError(f"{label} must be a non-empty string")
    return value


def _integer(value: object, label: str) -> int:
    if type(value) is not int or value < 1:
        raise ReportError(f"{label} must be a positive integer")
    return value


def _head(value: object) -> str | None:
    """Preserve a known commit or an explicit unborn/missing HEAD."""
    if value is None:
        return None
    if not isinstance(value, str) or len(value) not in (40, 64):
        raise ReportError("head must be a Git object id or null")
    return value


def _check(value: Mapping[str, Any] | object) -> dict[str, Any]:
    item = _mapping(value, "adapter result")
    identity = _string(item.get("id"), "adapter id")
    version = _integer(item.get("version"), "adapter version")
    status = _string(item.get("status"), "adapter status")
    provenance = _safe_text(item.get("provenance", f"{identity}@{version}"))
    raw_findings = item.get("findings", ())
    if not isinstance(raw_findings, (list, tuple)):
        raise ReportError("adapter findings must be an array")
    return {
        "id": identity,
        "version": version,
        "status": status,
        "inspected_files": _nonnegative(item.get("inspected_files", 0), "inspected_files"),
        "excluded_files": _nonnegative(item.get("excluded_files", 0), "excluded_files"),
        "reason": _safe_text(item["reason"]) if item.get("reason") is not None else None,
        "provenance": provenance,
        "_findings": list(raw_findings),
    }


def _nonnegative(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ReportError(f"{label} must be a non-negative integer")
    return value


def _finding(value: object, check: Mapping[str, Any]) -> dict[str, Any]:
    raw = _mapping(value, "finding")
    rule = _string(raw.get("rule"), "finding rule")
    path = _safe_path(raw.get("path", ""))
    location = _location(raw.get("location", {}))
    evidence_source = raw.get("evidence", {})
    evidence_raw = _mapping(evidence_source, "finding evidence") if evidence_source else {}
    evidence = {
        "kind": _safe_text(evidence_raw.get("kind", "text")),
        "excerpt": _safe_text(evidence_raw.get("excerpt", raw.get("excerpt", ""))),
        "provenance": _safe_text(evidence_raw.get("provenance", check["provenance"])),
    }
    severity = raw.get("severity", _RULE_SEVERITIES.get(rule, "unknown"))
    if severity not in _SEVERITIES:
        severity = "unknown"
    identity = {
        "analyzer": check["provenance"], "rule": rule, "path": path,
        "location": location, "evidence": evidence["excerpt"],
    }
    finding_id = hashlib.sha256(canonical_bytes(identity)).hexdigest()[:24]
    return {
        "id": finding_id, "rule": rule, "severity": severity, "path": path,
        "location": location, "evidence": evidence, "occurrences": 1,
    }


def _safe_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        return "[REDACTED_PATH]"
    candidate = value.replace("\\", "/")
    path = PurePath(candidate)
    if path.is_absolute() or re.match(r"^[A-Za-z]:", candidate) or candidate.startswith(("/", "//")):
        return "[REDACTED_PATH]"
    pieces = candidate.split("/")
    if any(part in ("", ".", "..") for part in pieces):
        return "[REDACTED_PATH]"
    return "/".join(_safe_text(part, 120) for part in pieces)


def _location(value: object) -> dict[str, int]:
    source = _mapping(value, "finding location")
    names = ("start_line", "start_column", "end_line", "end_column")
    result = {name: _nonnegative(source.get(name, 0), name) for name in names}
    return result


def _safe_text(value: object, maximum: int = _EXCERPT_LIMIT) -> str:
    if not isinstance(value, str):
        return "[REDACTED]"
    text = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", value)
    text = _PEM.sub("[REDACTED PRIVATE KEY]", text)
    text = _CREDENTIAL.sub(r"\1[REDACTED]", text)
    text = _ABSOLUTE_PATH.sub("[REDACTED_PATH]", text)
    text = text.replace("\x00", "[NUL]").replace("\r", " ").replace("\n", " ")
    return text[:maximum]


def _deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[Any, ...], dict[str, Any]] = {}
    for finding in findings:
        key = (finding["evidence"]["provenance"], finding["rule"], finding["path"],
               tuple(finding["location"].items()), finding["evidence"]["excerpt"])
        if key in merged:
            merged[key]["occurrences"] += 1
        else:
            merged[key] = finding
    return sorted(merged.values(), key=lambda item: (
        _SEVERITY_ORDER[item["severity"]], item["path"], item["location"]["start_line"],
        item["location"]["start_column"], item["rule"], item["id"],
    ))


def _uncertainty(checks: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    result = []
    for check in checks:
        if check["status"] not in ("clean", "findings"):
            result.append({"check": check["provenance"], "status": check["status"],
                           "reason": check["reason"] or "INCOMPLETE_SCOPE"})
    return result


def _add_omission(report: dict[str, Any], reason: str, omitted: int) -> None:
    item = {"check": "report@1", "status": "partial", "reason": reason}
    if item not in report["uncertainty"]:
        report["uncertainty"].append(item)
    report["notice"] = f"partial report: {reason}; omitted={omitted}"


def _bound_findings(report: dict[str, Any], maximum: int) -> None:
    omitted = max(0, len(report["findings"]) - maximum)
    if omitted:
        del report["findings"][maximum:]
        _add_omission(report, "FINDING_LIMIT", omitted)


def _bound_json(report: dict[str, Any], maximum: int) -> None:
    removed = 0
    while len(canonical_bytes(report)) > maximum and report["findings"]:
        report["findings"].pop()
        removed += 1
    if removed:
        _add_omission(report, "JSON_BYTE_LIMIT", removed)
    if len(canonical_bytes(report)) > maximum:
        raise ReportError("canonical report exceeds JSON byte limit before findings")
