from __future__ import annotations

import tempfile
import unittest

from repo_dast_audit_mcp.state import revise
from repo_dast_audit_mcp.store import ScanStore, StorageError


class StoreTests(unittest.TestCase):
    def test_terminal_generation_is_hash_checked_and_corruption_is_storage_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ScanStore(temporary, hmac_key=b"x" * 32)
            state = store.create(root="C:/repo", limits={"total_bytes": 10})
            terminal = revise(state, state="completed", terminal_reason="COMPLETE")
            committed = store.commit(terminal, report_json=b'{"ok":true}', report_markdown=b"# report\n")
            loaded, report, markdown = store.load(committed["scan_id"])
            self.assertEqual(loaded["report_sha256"], committed["report_sha256"])
            self.assertEqual((report, markdown), (b'{"ok":true}', b"# report\n"))
            report_path = store.records_dir / committed["scan_id"] / "generations" / "2" / "report.json"
            report_path.write_bytes(b"tampered")
            with self.assertRaises(StorageError) as raised:
                store.load(committed["scan_id"])
            self.assertEqual(raised.exception.code, "E_STORAGE")

    def test_recovery_interrupts_valid_active_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ScanStore(temporary, hmac_key=b"x" * 32)
            state = store.create(root="C:/repo", limits={"total_bytes": 10})
            running = revise(state, state="running")
            store.commit(running, report_json=b"{}", report_markdown=b"# draft\n")
            repaired = store.recover()
            self.assertEqual(repaired[0]["state"], "interrupted")
            self.assertEqual(repaired[0]["terminal_reason"], "PROCESS_RESTART")
