from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"


class SelfScanTests(unittest.TestCase):
    def test_current_repository_is_scanned_by_a_real_stdio_server(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            appdata = Path(temporary).resolve() / "external-server-data"
            environment = os.environ.copy()
            environment["LOCALAPPDATA"] = str(appdata)
            environment["PYTHONUTF8"] = "1"
            process = subprocess.Popen(
                [str(PYTHON), "-m", "repo_dast_audit_mcp.server"],
                cwd=ROOT,
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
            assert process.stdin is not None
            assert process.stdout is not None
            try:
                process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}) + "\n")
                process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "scan_repository", "arguments": {"root": str(ROOT)}}}) + "\n")
                process.stdin.flush()
                self.assertEqual(json.loads(process.stdout.readline())["result"]["protocolVersion"], "2024-11-05")
                first = json.loads(process.stdout.readline())
                result = first["result"]["structuredContent"]
                self.assertTrue(result["ok"])
                scan_id = result["scan_id"]
                terminal = result
                deadline = time.monotonic() + 70
                request_id = 3
                while terminal["state"] not in {"completed", "partial", "cancelled", "interrupted", "failed"} and time.monotonic() < deadline:
                    process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": "get_scan", "arguments": {"scan_id": scan_id}}}) + "\n")
                    process.stdin.flush()
                    terminal = json.loads(process.stdout.readline())["result"]["structuredContent"]
                    request_id += 1
                    time.sleep(0.02)
                self.assertIn(terminal["state"], {"completed", "partial"})
                report = terminal["report"]
                self.assertNotIn(str(ROOT), json.dumps(report))
                expected_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(report["head"], expected_head.stdout.strip() if expected_head.returncode == 0 else None)
                tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
                if not tracked:
                    self.assertEqual(terminal["state"], "partial")
                    self.assertTrue(any(item["reason"] == "EMPTY_INVENTORY" for item in report["uncertainty"]))
                records = appdata / "repo-dast-audit-mcp" / "records" / scan_id / "generations" / str(terminal["revision"])
                self.assertTrue((records / "report.json").is_file())
                self.assertTrue((records / "report.md").is_file())
                self.assertFalse((records / "report.json").is_relative_to(ROOT))
                durable_report = json.loads((records / "report.json").read_text(encoding="utf-8"))
                durable_markdown = (records / "report.md").read_text(encoding="utf-8")
                self.assertEqual(durable_report, report)
                self.assertIn("HEAD: `{}`".format(report["head"] or "unborn/missing"), durable_markdown)
                if not tracked:
                    self.assertIn("EMPTY_INVENTORY", durable_markdown)
            finally:
                if process.stdin is not None:
                    process.stdin.close()
                process.wait(timeout=10)
                stderr = process.stderr.read() if process.stderr is not None else ""
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
                self.assertEqual(process.returncode, 0, stderr)


if __name__ == "__main__":
    unittest.main()
