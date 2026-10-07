from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from repository_vulnerability_report_mcp.config import ServerConfig
from repository_vulnerability_report_mcp.protocol import JsonRpcProtocol
from repository_vulnerability_report_mcp.service import ScanService


class ToolCallTests(unittest.TestCase):
    def test_protocol_delegates_get_scan_to_service(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            service = ScanService(ServerConfig(cache_dir=Path(temporary).resolve()))
            protocol = JsonRpcProtocol(tool_handler=service.handle)
            response = protocol.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "get_scan", "arguments": {"scan_id": "123e4567-e89b-12d3-a456-426614174000"}}})
            self.assertTrue(response["result"]["isError"])
            self.assertEqual(response["result"]["structuredContent"]["code"], "E_NOT_FOUND")
