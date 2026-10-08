from __future__ import annotations

import unittest

from repo_dast_audit_mcp.render import escape_markdown, render_markdown, render_report
from repo_dast_audit_mcp.report import ReportError, build_report


def _report() -> dict[str, object]:
    state = {"scan_id": "123e4567-e89b-12d3-a456-426614174000", "revision": 2, "state": "completed", "limits": {"findings": 10, "json_bytes": 9_000, "markdown_bytes": 9_000}, "progress": {"files_total": 1, "files_completed": 1, "bytes_limit": 1, "bytes_read": 1, "analyzers_completed": 1, "findings_emitted": 1, "progress_percent": 100}}
    adapter = {"id": "x", "version": 1, "status": "findings", "inspected_files": 1, "excluded_files": 0, "reason": None, "provenance": "x@1", "findings": [{"rule": "R", "path": "a|b.py", "location": {}, "evidence": {"excerpt": "<tag> [x](url) ```"}}]}
    return build_report(state, [adapter])


class RenderTests(unittest.TestCase):
    def test_markdown_comes_only_from_report_and_escapes_repository_text(self) -> None:
        markdown = render_markdown(_report())
        self.assertIn("&lt;tag&gt;", markdown)
        self.assertIn("a\\|b.py", markdown)
        self.assertNotIn("[x](url)", markdown)
        json_bytes, markdown_bytes = render_report(_report())
        self.assertTrue(json_bytes and markdown_bytes)

    def test_renderer_rejects_noncanonical_input_and_marks_truncation(self) -> None:
        with self.assertRaises(ReportError):
            render_markdown({})
        report = _report()
        report["limits"]["markdown_bytes"] = 400
        markdown = render_markdown(report)
        self.assertIn("Partial output", markdown)

    def test_escape_markdown_is_inert(self) -> None:
        self.assertEqual(escape_markdown("<x>|`"), "&lt;x&gt;\\|\\`")
