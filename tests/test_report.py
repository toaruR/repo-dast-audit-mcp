from __future__ import annotations

import unittest

from repository_vulnerability_report_mcp.report import ReportError, build_report, canonical_bytes


def _state() -> dict[str, object]:
    return {
        "scan_id": "123e4567-e89b-12d3-a456-426614174000", "revision": 4, "state": "partial",
        "head": None,
        "limits": {"findings": 10, "json_bytes": 8_000, "markdown_bytes": 8_000, "total_bytes": 99},
        "progress": {"files_total": 50, "files_completed": 49, "bytes_limit": 99, "bytes_read": 98,
                     "analyzers_completed": 2, "findings_emitted": 4, "progress_percent": 98},
    }


class ReportTests(unittest.TestCase):
    def test_report_is_deterministic_deduplicated_and_redacted(self) -> None:
        secret = "very-secret-value"
        finding = {"rule": "SECRET002", "path": "src/a.py", "location": {"start_line": 2, "start_column": 1, "end_line": 2, "end_column": 5}, "evidence": {"kind": "text", "excerpt": f"API_TOKEN={secret}", "provenance": "secret_text@1"}}
        adapters = [{"id": "secret_text", "version": 1, "status": "findings", "inspected_files": 1, "excluded_files": 0, "reason": None, "provenance": "secret_text@1", "findings": [finding, finding]}]
        first = build_report(_state(), adapters)
        second = build_report(_state(), adapters)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(first["findings"][0]["severity"], "medium")
        self.assertEqual(first["findings"][0]["occurrences"], 2)
        self.assertNotIn(secret, canonical_bytes(first).decode())
        self.assertEqual(first["progress"], _state()["progress"])

    def test_absolute_path_is_redacted_and_limits_are_explicit(self) -> None:
        state = _state()
        state["limits"] = {"findings": 1, "json_bytes": 8_000, "markdown_bytes": 8_000}
        adapter = {"id": "x", "version": 1, "status": "findings", "inspected_files": 1, "excluded_files": 0, "reason": None, "provenance": "x@1", "findings": [
            {"rule": "R1", "path": "C:/private/root/a.py", "location": {}, "evidence": {"excerpt": "one"}},
            {"rule": "R2", "path": "b.py", "location": {}, "evidence": {"excerpt": "two"}},
        ]}
        report = build_report(state, [adapter])
        self.assertEqual(report["findings"][0]["path"], "[REDACTED_PATH]")
        self.assertEqual(report["uncertainty"][-1]["reason"], "FINDING_LIMIT")

    def test_bad_analyzer_shape_is_rejected(self) -> None:
        with self.assertRaises(ReportError):
            build_report(_state(), [{"id": "x", "version": 1, "status": "clean", "findings": "bad"}])
