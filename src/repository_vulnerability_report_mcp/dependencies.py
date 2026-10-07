"""Exact-pin dependency parsing and a deliberately constrained OSV client."""

from __future__ import annotations

from dataclasses import dataclass
import json
import ssl
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .analyzers import AdapterResult, _result
from .config import OSV_ORIGIN


@dataclass(frozen=True, slots=True)
class Package:
    ecosystem: str
    name: str
    version: str


def parse_requirements(path: str, text: str) -> tuple[AdapterResult, tuple[Package, ...]]:
    packages: list[Package] = []
    excluded = 0
    reasons: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("-e ", "--editable ")):
            excluded += 1; reasons.append("EDITABLE")
        elif "@" in line or "://" in line:
            excluded += 1; reasons.append("VCS_OR_LOCAL")
        elif ";" in line:
            excluded += 1; reasons.append("MARKER_OUT_OF_SCOPE")
        elif "==" in line and line.count("==") == 1:
            name, version = (part.strip() for part in line.split("=="))
            if name and version and not any(token in version for token in "<>!~=*"):
                packages.append(Package("PyPI", name, version))
            else:
                excluded += 1; reasons.append("NONEXACT_PIN")
        else:
            excluded += 1; reasons.append("NONEXACT_PIN")
    status = "partial" if excluded and packages else "skipped" if excluded else "clean"
    return _result("python_requirements", status, inspected=1, excluded=excluded,
                   reason=",".join(sorted(set(reasons))) or None), tuple(packages)


def parse_package_lock(path: str, text: str) -> tuple[AdapterResult, tuple[Package, ...]]:
    try:
        payload = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return _result("npm_lock", "skipped", excluded=1, reason="UNKNOWN_LOCK_FORMAT"), ()
    if not isinstance(payload, dict) or not isinstance(payload.get("lockfileVersion"), int):
        return _result("npm_lock", "skipped", excluded=1, reason="UNKNOWN_LOCK_FORMAT"), ()
    source = payload.get("packages")
    if not isinstance(source, dict):
        source = payload.get("dependencies")
    if not isinstance(source, dict):
        return _result("npm_lock", "skipped", excluded=1, reason="UNKNOWN_LOCK_FORMAT"), ()
    packages: list[Package] = []
    excluded = 0
    for key, item in source.items():
        if key == "" or not isinstance(item, dict):
            continue
        name = item.get("name") or (key.rsplit("node_modules/", 1)[-1] if "node_modules/" in key else key)
        version = item.get("version")
        if isinstance(name, str) and isinstance(version, str) and version and not version.startswith(("file:", "git+", "http:")) and not any(c in version for c in "*<>~^|"):
            packages.append(Package("npm", name, version))
        else:
            excluded += 1
    status = "partial" if excluded and packages else "skipped" if excluded else "clean"
    return _result("npm_lock", status, inspected=1, excluded=excluded,
                   reason="NONEXACT_OR_LOCAL" if excluded else None), tuple(packages)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def query_osv(packages: tuple[Package, ...], *, enabled: bool = False, timeout_seconds: float = 5.0,
              max_requests: int = 100, response_bytes: int = 1_048_576, opener=None) -> AdapterResult:
    """Query only package coordinates; disabled/offline/error outcomes are never clean."""
    if not enabled:
        return _result("osv", "skipped", reason="DISABLED")
    if not packages:
        return _result("osv", "skipped", reason="NO_EXACT_PACKAGES")
    if len(packages) > max_requests:
        return _result("osv", "partial", reason="REQUEST_LIMIT")
    endpoint = urlsplit(OSV_ORIGIN)
    if endpoint.scheme != "https" or endpoint.netloc != "api.osv.dev":
        return _result("osv", "error", reason="INVALID_ORIGIN")
    transport = opener or build_opener(_NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
    findings: list[dict[str, object]] = []
    try:
        for package in packages:
            body = json.dumps({"package": {"ecosystem": package.ecosystem, "name": package.name}, "version": package.version}).encode("utf-8")
            request = Request(OSV_ORIGIN, data=body, headers={"Content-Type": "application/json"}, method="POST")
            with transport.open(request, timeout=timeout_seconds) as response:
                raw = response.read(response_bytes + 1)
            if len(raw) > response_bytes:
                return _result("osv", "partial", reason="RESPONSE_LIMIT")
            decoded = json.loads(raw.decode("utf-8"))
            if not isinstance(decoded, dict) or not isinstance(decoded.get("vulns", []), list):
                return _result("osv", "error", reason="MALFORMED_RESPONSE")
            for vuln in decoded["vulns"]:
                if isinstance(vuln, dict) and isinstance(vuln.get("id"), str):
                    findings.append({"rule": "OSV", "severity": "unknown", "package": package.name,
                                     "evidence": {"kind": "advisory", "excerpt": "OSV advisory", "provenance": "osv@1"}, "advisory": vuln["id"]})
    except (TimeoutError, URLError, OSError):
        return _result("osv", "offline", reason="NETWORK_UNAVAILABLE")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return _result("osv", "error", reason="MALFORMED_RESPONSE")
    return _result("osv", "findings" if findings else "clean", inspected=len(packages), findings=findings)
