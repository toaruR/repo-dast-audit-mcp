from __future__ import annotations

from io import BytesIO, StringIO
import json
import unittest

from repository_vulnerability_report_mcp.config import Limits
from repository_vulnerability_report_mcp.protocol import JsonRpcProtocol, serve_stdio


class ProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = JsonRpcProtocol()

    def test_standard_json_rpc_errors_are_mapped(self) -> None:
        self.assertEqual(self.protocol.handle_frame(b"{")["error"]["code"], -32700)
        self.assertEqual(self.protocol.handle_message([])["error"]["code"], -32600)
        self.assertEqual(self.protocol.handle_message({"jsonrpc": "2.0", "id": 1, "method": "missing"})["error"]["code"], -32601)
        self.assertEqual(self.protocol.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}})["error"]["code"], -32602)

    def test_initialize_notifications_ping_and_tools_list(self) -> None:
        initialize = self.protocol.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(initialize["result"]["capabilities"], {"tools": {}})
        self.assertIsNone(self.protocol.handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        self.assertEqual(self.protocol.handle_message({"jsonrpc": "2.0", "id": 2, "method": "ping"})["result"], {})
        listed = self.protocol.handle_message({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
        self.assertEqual([tool["name"] for tool in listed["result"]["tools"]], ["scan_repository", "get_scan", "cancel_scan"])

    def test_cancellation_reaches_tool_handler(self) -> None:
        seen: list[bool] = []
        protocol = JsonRpcProtocol(tool_handler=lambda _name, _arguments, cancelled: seen.append(cancelled()) or {"content": []})
        protocol.handle_message({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 9}})
        response = protocol.handle_message({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "get_scan", "arguments": {"scan_id": "123e4567-e89b-12d3-a456-426614174000"}}})
        self.assertEqual(response["result"], {"content": []})
        self.assertEqual(seen, [True])

    def test_oversized_frame_is_bounded_protocol_error(self) -> None:
        protocol = JsonRpcProtocol(limits=Limits(frame_bytes=1))
        result = protocol.handle_frame(b"xx")
        self.assertEqual(result["error"], {"code": -32000, "message": "frame exceeds configured limit", "data": {"code": "E_FRAME_LIMIT"}})
        input_stream = BytesIO(b"xx\n")
        output_stream = StringIO()
        serve_stdio(protocol, input_stream, output_stream)
        self.assertEqual(json.loads(output_stream.getvalue())["error"]["data"]["code"], "E_FRAME_LIMIT")


if __name__ == "__main__":
    unittest.main()
