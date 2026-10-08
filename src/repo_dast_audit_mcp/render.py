"""Deterministic Markdown rendering of canonical report JSON only."""

from __future__ import annotations

from html import escape as html_escape
from typing import Any, Mapping

from .config import Limits
from .report import ReportError, canonical_bytes


def escape_markdown(value: object) -> str:
    """Render all repository-controlled text as inert text inside table cells."""
    text = html_escape(str(value), quote=False)
    text = text.replace("\\", "\\\\").replace("|", "\\|")
    text = text.replace("`", "\\`").replace("[", "\\[").replace("]", "\\]")
    text = text.replace("\r", " ").replace("\n", " ")
    return text.replace("```", "\\`\\`\\`")


def render_markdown(report: Mapping[str, Any], *, markdown_bytes: int | None = None) -> str:
    """Render a checked canonical report. Never reads analyzer inputs or state."""
    _validate_report(report)
    limit = markdown_bytes if markdown_bytes is not None else _limit(report, "markdown_bytes")
    if type(limit) is not int or limit < 1:
        raise ReportError("markdown byte limit must be a positive integer")
    lines = [
        "# Repository DAST audit report", "",
        f"Scan: `{escape_markdown(report['scan_id'])}`  ",
        f"Revision: {report['revision']}  ",
        f"State: {escape_markdown(report['state'])}",
        "HEAD: `{}`".format(escape_markdown(report["head"] or "unborn/missing")), "",
        "## Findings", "", "| Severity | Rule | Path | Location | Evidence | Occurrences |",
        "| --- | --- | --- | --- | --- | ---: |",
    ]
    for finding in report["findings"]:
        location = finding["location"]
        row = "| {severity} | {rule} | {path} | {line}:{column} | {evidence} | {occurrences} |".format(
            severity=escape_markdown(finding["severity"]), rule=escape_markdown(finding["rule"]),
            path=escape_markdown(finding["path"]), line=location["start_line"], column=location["start_column"],
            evidence=escape_markdown(finding["evidence"]["excerpt"]), occurrences=finding["occurrences"],
        )
        if not _fits(lines + [row], limit):
            return _truncated(lines, limit, len(report["findings"]))
        lines.append(row)
    lines.extend(["", "## Coverage", ""])
    for check in report["checks"]:
        row = "- `{}`: {} (inspected {}, excluded {})".format(
            escape_markdown(check["provenance"]), escape_markdown(check["status"]),
            check["inspected_files"], check["excluded_files"],
        )
        if not _fits(lines + [row], limit):
            return _truncated(lines, limit, 0)
        lines.append(row)
    if report["uncertainty"]:
        lines.extend(["", "## Uncertainty", ""])
        for item in report["uncertainty"]:
            row = "- `{}`: {} ({})".format(escape_markdown(item["check"]), escape_markdown(item["status"]), escape_markdown(item["reason"]))
            if not _fits(lines + [row], limit):
                return _truncated(lines, limit, 0)
            lines.append(row)
    lines.extend(["", "## Notice", "", escape_markdown(report["notice"]), ""])
    if not _fits(lines, limit):
        return _truncated(lines[:12], limit, 0)
    return "\n".join(lines)


def render_report(report: Mapping[str, Any], *, limits: Limits | None = None) -> tuple[bytes, bytes]:
    """Return matching canonical JSON and Markdown bytes for one revision."""
    json_bytes = canonical_bytes(report)
    json_limit = limits.json_bytes if limits else _limit(report, "json_bytes")
    if len(json_bytes) > json_limit:
        raise ReportError("canonical report exceeds JSON byte limit")
    markdown = render_markdown(report, markdown_bytes=limits.markdown_bytes if limits else None)
    return json_bytes, markdown.encode("utf-8")


render_report_markdown = render_markdown


def _validate_report(report: Mapping[str, Any]) -> None:
    required = {"schema_version", "scan_id", "revision", "state", "head", "limits", "progress", "checks", "findings", "uncertainty", "notice"}
    if not isinstance(report, Mapping) or set(report) != required:
        raise ReportError("renderer requires canonical report JSON")
    if not isinstance(report["findings"], list) or not isinstance(report["checks"], list) or not isinstance(report["uncertainty"], list):
        raise ReportError("canonical report has invalid collections")


def _limit(report: Mapping[str, Any], name: str) -> int:
    limits = report["limits"]
    if not isinstance(limits, Mapping) or type(limits.get(name)) is not int:
        raise ReportError(f"canonical report lacks {name}")
    return limits[name]


def _fits(lines: list[str], limit: int) -> bool:
    return len(("\n".join(lines) + "\n").encode("utf-8")) <= limit


def _truncated(lines: list[str], limit: int, omitted: int) -> str:
    marker = "\n\n## Partial output\n\nMarkdown byte limit reached; output truncated explicitly."
    while lines and len(("\n".join(lines) + marker + "\n").encode("utf-8")) > limit:
        lines.pop()
    if not lines:
        raise ReportError("markdown byte limit cannot represent partial marker")
    return "\n".join(lines) + marker + "\n"
