from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from repo_dast_audit_mcp.config import ServerConfig
from repo_dast_audit_mcp.render import render_report
from repo_dast_audit_mcp.report import build_report
from repo_dast_audit_mcp.service import ScanService
from repo_dast_audit_mcp.state import revise


class ServiceTests(unittest.TestCase):
    def test_unknown_uuid_is_not_found_and_cancel_is_idempotent_for_terminal_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            service = ScanService(ServerConfig(cache_dir=Path(temporary).resolve()))
            result = service.get_scan("123e4567-e89b-12d3-a456-426614174000")
            self.assertTrue(result["isError"])
            self.assertEqual(result["structuredContent"]["code"], "E_NOT_FOUND")
            state = service.store.create(root="C:/repo", limits={name: getattr(service.config.limits, name)
                                                                  for name in service.config.limits.__dataclass_fields__})
            state = revise(state, state="completed", terminal_reason="COMPLETE")
            report, markdown = render_report(build_report(state, (), limits=service.config.limits), limits=service.config.limits)
            state = service.store.commit(state, report_json=report, report_markdown=markdown)
            first = service.cancel_scan(state["scan_id"])["structuredContent"]
            second = service.cancel_scan(state["scan_id"])["structuredContent"]
            self.assertEqual((first["state"], first["revision"]), ("completed", second["revision"]))

