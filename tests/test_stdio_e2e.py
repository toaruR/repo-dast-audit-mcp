from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"


class StdioClient:
    """Tiny real-process client: every stdout line must be a JSON-RPC response."""

    def __init__(self, appdata: Path) -> None:
        environment = os.environ.copy()
        environment["LOCALAPPDATA"] = str(appdata)
        environment["PYTHONUTF8"] = "1"
        self.process = subprocess.Popen(
            [str(PYTHON), "-m", "repository_vulnerability_report_mcp.server"],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        assert self.process.stdin is not None
        assert self.process.stdout is not None

    def request(self, request_id: int, method: str, params: dict[str, object]) -> dict[str, object]:
        assert self.process.stdin is not None
        assert self.process.stdout is not None
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            stderr = self.process.stderr.read() if self.process.stderr is not None else ""
            raise AssertionError(f"stdio server exited before responding: {stderr}")
        return json.loads(line)

    def notify(self, method: str, params: dict[str, object]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": params}) + "\n")
        self.process.stdin.flush()

    def close(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()
        self.process.wait(timeout=10)
        stderr = self.process.stderr.read() if self.process.stderr is not None else ""
        if self.process.stdout is not None:
            self.process.stdout.close()
        if self.process.stderr is not None:
            self.process.stderr.close()
        if self.process.returncode != 0:
            raise AssertionError(f"stdio server exited {self.process.returncode}: {stderr}")


class StdioEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.appdata = self.base / "server-data"
        self.repository = self.base / "fixture"
        self.repository.mkdir()
        self._git("init")
        self._git("config", "user.email", "test@example.invalid")
        self._git("config", "user.name", "Test")
        self._git("config", "commit.gpgSign", "false")
        source = self.repository / "src"
        source.mkdir()
        (source / "vulnerable.py").write_text("API_TOKEN = 'very-secret-value'\nvalue = eval('1 + 1')\n", encoding="utf-8")
        (source / "safe.py").write_text("def add(left: int, right: int) -> int:\n    return left + right\n", encoding="utf-8")
        (self.repository / "requirements.txt").write_text("example-package==1.0.0\n", encoding="utf-8")
        for number in range(16):
            (source / f"cancel_{number}.py").write_text("# safe source\n" * 32_768, encoding="utf-8")
        self._git("add", ".")
        self._git("commit", "-m", "fixture")
        self.client = StdioClient(self.appdata)

    def tearDown(self) -> None:
        self.client.close()
        self.temporary.cleanup()

    def _git(self, *args: str) -> None:
        environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
        subprocess.run(["git", *args], cwd=self.repository, env=environment, check=True, capture_output=True, text=True)

    def _call(self, request_id: int, name: str, arguments: dict[str, object]) -> dict[str, object]:
        response = self.client.request(request_id, "tools/call", {"name": name, "arguments": arguments})
        self.assertIn("result", response)
        return response["result"]["structuredContent"]  # type: ignore[index,return-value]

    def _terminal_scan(self, scan_id: str, request_id: int) -> tuple[dict[str, object], int]:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            value = self._call(request_id, "get_scan", {"scan_id": scan_id})
            request_id += 1
            if value["state"] in {"completed", "partial", "cancelled", "interrupted", "failed"}:
                return value, request_id
            time.sleep(0.02)
        self.fail("scan did not reach a terminal state")

    def test_real_stdio_scan_restart_cancel_and_protocol_boundaries(self) -> None:
        initialized = self.client.request(1, "initialize", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "1"}})
        self.assertEqual(initialized["result"]["protocolVersion"], "2024-11-05")  # type: ignore[index]
        self.client.notify("notifications/initialized", {})
        listed = self.client.request(2, "tools/list", {})
        tools = listed["result"]["tools"]  # type: ignore[index]
        self.assertEqual([tool["name"] for tool in tools], ["scan_repository", "get_scan", "cancel_scan"])
        self.assertTrue(all(tool["inputSchema"]["$schema"] == "https://json-schema.org/draft/2020-12/schema" for tool in tools))

        invalid_schema = self.client.request(3, "tools/call", {"name": "scan_repository", "arguments": {"root": str(self.repository), "cache_dir": "forbidden"}})
        self.assertEqual(invalid_schema["error"]["code"], -32602)  # type: ignore[index]
        invalid_root = self._call(4, "scan_repository", {"root": str(self.base / "not-a-repository")})
        self.assertTrue(invalid_root["ok"] is False)
        self.assertEqual(invalid_root["code"], "E_ROOT")

        queued = self._call(5, "scan_repository", {"root": str(self.repository)})
        scan_id = queued["scan_id"]
        completed, next_id = self._terminal_scan(scan_id, 6)  # type: ignore[arg-type]
        self.assertIn(completed["state"], {"completed", "partial"})
        report = completed["report"]
        markdown = completed["markdown"]
        serialized = json.dumps(report)
        self.assertGreater(len(report["findings"]), 0)  # type: ignore[index]
        self.assertNotIn("very-secret-value", serialized)
        self.assertNotIn("very-secret-value", markdown)
        self.assertFalse(any(finding["path"] == "src/safe.py" for finding in report["findings"]))  # type: ignore[index]
        osv = [check for check in report["checks"] if check["id"] == "osv"]  # type: ignore[index]
        self.assertEqual([(check["status"], check["reason"]) for check in osv], [("skipped", "DISABLED")])

        generation = self.appdata / "repository-vulnerability-report-mcp" / "records" / str(scan_id) / "generations" / str(completed["revision"])
        report_path = generation / "report.json"
        markdown_path = generation / "report.md"
        self.assertTrue(report_path.is_file())
        self.assertTrue(markdown_path.is_file())
        self.assertFalse(report_path.is_relative_to(self.repository))
        self.assertNotIn("very-secret-value", report_path.read_text(encoding="utf-8"))

        self.client.close()
        self.client = StdioClient(self.appdata)
        recovered = self._call(next_id, "get_scan", {"scan_id": scan_id})
        next_id += 1
        self.assertEqual(recovered["state"], completed["state"])
        self.assertEqual(recovered["report"]["scan_id"], scan_id)  # type: ignore[index]

        repeated = self._call(next_id, "scan_repository", {"root": str(self.repository)})
        next_id += 1
        cancelled = self._call(next_id, "cancel_scan", {"scan_id": repeated["scan_id"]})
        next_id += 1
        self.assertIn(cancelled["state"], {"queued", "running", "cancelled", "completed", "partial"})
        terminal, _ = self._terminal_scan(repeated["scan_id"], next_id)  # type: ignore[arg-type]
        self.assertIn(terminal["state"], {"cancelled", "completed", "partial"})

        self.client.close()
        self.client = StdioClient(self.appdata)
        self.client.notify("notifications/cancelled", {"requestId": "will-not-match"})
        self.client.close()
        self.client = StdioClient(self.appdata)

        self.assertIsNotNone(shutil.which("git"))


if __name__ == "__main__":
    unittest.main()
