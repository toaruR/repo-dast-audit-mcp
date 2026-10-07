"""Bounded local source analyzers with redacted, report-safe evidence."""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from pathlib import PurePath
import re
from typing import Iterable


_MAX_EXCERPT = 160
_PEM = re.compile(r"-----BEGIN (?:[A-Z0-9 ]* )?PRIVATE KEY-----", re.IGNORECASE)
_CREDENTIAL = re.compile(
    r"(?im)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*(?:token|secret|password|api[_-]?key)[A-Za-z0-9_]*)\s*=\s*([^\r\n]+)"
)
_URL_CREDENTIALS = re.compile(r"([a-z][a-z0-9+.-]*://)[^/@\s:]+(?::[^/@\s]*)?@", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class AdapterResult:
    """Complete, stable adapter outcome; findings never retain raw source."""

    id: str
    version: int
    status: str
    inspected_files: int
    excluded_files: int
    reason: str | None
    findings: tuple[dict[str, object], ...]
    provenance: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def _result(
    identity: str, status: str, *, inspected: int = 0, excluded: int = 0,
    reason: str | None = None, findings: Iterable[dict[str, object]] = (),
) -> AdapterResult:
    return AdapterResult(identity, 1, status, inspected, excluded, reason, tuple(findings), f"{identity}@1")


def _redact(value: str) -> str:
    """Return a bounded, non-sensitive marker rather than source content."""
    value = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", value)
    value = _PEM.sub("[REDACTED PRIVATE KEY]", value)
    return value[:_MAX_EXCERPT]


def _finding(rule: str, path: str, node: ast.AST, excerpt: str, severity: str) -> dict[str, object]:
    line = int(getattr(node, "lineno", 1))
    column = int(getattr(node, "col_offset", 0))
    end_line = int(getattr(node, "end_lineno", line))
    end_column = int(getattr(node, "end_col_offset", column))
    return {
        "rule": rule, "severity": severity, "path": _safe_path(path),
        "location": {"start_line": line, "start_column": column, "end_line": end_line, "end_column": end_column},
        "evidence": {"kind": "ast", "excerpt": _redact(excerpt), "provenance": "python_ast@1"},
    }


def _safe_path(path: str) -> str:
    """Analyzer inputs must be repository-relative; hide accidental roots."""
    candidate = PurePath(path)
    if candidate.is_absolute() or ":" in path or path.startswith(("/", "\\")):
        return "[REDACTED_PATH]"
    return path.replace("\\", "/")


def _name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def analyze_python_ast(path: str, text: str, *, max_bytes: int = 262_144, max_depth: int = 100, max_nodes: int = 50_000) -> AdapterResult:
    """Detect the intentionally small documented Python AST rule set."""
    if len(text.encode("utf-8")) > max_bytes:
        return _result("python_ast", "partial", excluded=1, reason="AST_BYTE_LIMIT")
    try:
        tree = ast.parse(text, filename=path)
    except (SyntaxError, ValueError, TypeError):
        return _result("python_ast", "partial", excluded=1, reason="AST_PARSE_ERROR")
    nodes = list(ast.walk(tree))
    if len(nodes) > max_nodes:
        return _result("python_ast", "partial", excluded=1, reason="AST_NODE_LIMIT")
    depths: dict[int, int] = {id(tree): 0}
    for parent in ast.walk(tree):
        parent_depth = depths.get(id(parent), 0)
        for child in ast.iter_child_nodes(parent):
            depths[id(child)] = parent_depth + 1
    if max(depths.values(), default=0) > max_depth:
        return _result("python_ast", "partial", excluded=1, reason="AST_DEPTH_LIMIT")

    findings: list[dict[str, object]] = []
    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        called = _name(node.func)
        if called in {"eval", "exec"} or (called and called.endswith(".eval")) or (called and called.endswith(".exec")):
            findings.append(_finding("PY001", path, node, f"call to {called}", "high"))
        elif called in {"pickle.load", "pickle.loads"}:
            findings.append(_finding("PY002", path, node, f"call to {called}", "high"))
        elif called == "yaml.load":
            findings.append(_finding("PY003", path, node, "call to yaml.load", "high"))
        elif called and (called == "subprocess" or called.startswith("subprocess.")):
            if any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords):
                findings.append(_finding("PY004", path, node, "subprocess call with shell=True", "high"))
    return _result("python_ast", "findings" if findings else "clean", inspected=1, findings=findings)


def analyze_secret_text(path: str, text: str) -> AdapterResult:
    """Find secret-shaped text while retaining only fixed redacted evidence."""
    findings: list[dict[str, object]] = []
    for match in _PEM.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        findings.append({"rule": "SECRET001", "severity": "critical", "path": _safe_path(path),
                         "location": {"start_line": line, "start_column": 0, "end_line": line, "end_column": 0},
                         "evidence": {"kind": "text", "excerpt": "[REDACTED PRIVATE KEY]", "provenance": "secret_text@1"}})
    for match in _CREDENTIAL.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        key = match.group(1)
        findings.append({"rule": "SECRET002", "severity": "medium", "path": _safe_path(path),
                         "location": {"start_line": line, "start_column": 0, "end_line": line, "end_column": 0},
                         "evidence": {"kind": "text", "excerpt": f"{key}=[REDACTED]", "provenance": "secret_text@1"}})
    return _result("secret_text", "findings" if findings else "clean", inspected=1, findings=findings)
