"""Bounded UTF-8 newline-delimited JSON-RPC transport for MCP stdio."""

from __future__ import annotations

import json
import math
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, BinaryIO, TextIO

from .config import Limits
from .schemas import InvalidToolArguments, TOOL_NAMES, tool_definitions, validate_tool_arguments


JSONRPC_VERSION = "2.0"
MCP_PROTOCOL_VERSION = "2024-11-05"

ToolHandler = Callable[[str, dict[str, Any], Callable[[], bool]], Any]


def _error(request_id: str | int | None, code: int, message: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": error}


def _is_request_id(value: Any) -> bool:
    return value is None or (isinstance(value,str) and len(value)<=256) or (type(value) is int and abs(value)<=2**53-1) or (type(value) is float and math.isfinite(value))


def _cancellation_key(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)



def strict_json(frame):
    depth=0; quoted=False; escaped=False
    for character in frame:
        if quoted:
            if escaped: escaped=False
            elif character=="\\": escaped=True
            elif character=='"': quoted=False
        elif character=='"': quoted=True
        elif character in "[{":
            depth+=1
            if depth>128: raise ValueError("JSON nesting limit")
        elif character in "]}": depth-=1
    def finite_number(value):
        number=float(value)
        if not math.isfinite(number): raise ValueError("Nonfinite JSON number")
        return number
    def bounded_integer(value):
        if len(value.lstrip("-"))>64: raise ValueError("JSON integer limit")
        return int(value)
    def reject_constant(_): raise ValueError("Nonfinite JSON number")
    def pairs(items):
        result={}
        for key,value in items:
            if key in result: raise ValueError("Duplicate JSON property")
            result[key]=value
        return result
    return json.loads(frame,parse_constant=reject_constant,parse_float=finite_number,parse_int=bounded_integer,object_pairs_hook=pairs)

@dataclass(slots=True)
class JsonRpcProtocol:
    """Process one JSON-RPC message at a time without writing diagnostics to stdout."""

    limits: Limits = field(default_factory=Limits)
    tool_handler: ToolHandler | None = None
    web_audit_enabled: bool = False
    _cancelled: set[str] = field(default_factory=set, init=False)

    def handle_frame(self, frame: bytes) -> dict[str, Any] | None:
        """Handle one newline-stripped UTF-8 frame and return a response if required."""
        if len(frame) > self.limits.frame_bytes:
            return _error(None, -32000, "frame exceeds configured limit", {"code": "E_FRAME_LIMIT"})
        try:
            message = strict_json(frame.decode("utf-8"))
        except (UnicodeDecodeError,ValueError,RecursionError):
            return _error(None, -32700, "parse error")
        return self.handle_message(message)

    def handle_message(self, message: Any) -> dict[str, Any] | None:
        """Handle a decoded JSON-RPC request or notification."""
        if not isinstance(message, dict) or message.get("jsonrpc") != JSONRPC_VERSION:
            return _error(None, -32600, "invalid request")
        method = message.get("method")
        if not isinstance(method, str):
            return _error(None, -32600, "invalid request")
        has_id = "id" in message
        request_id = message.get("id")
        if has_id and not _is_request_id(request_id):
            return _error(None, -32600, "invalid request")
        params = message.get("params", {})
        if not isinstance(params, dict):
            return None if not has_id else _error(request_id, -32602, "invalid params")
        if method == "notifications/cancelled":
            return self._cancel_notification(params, request_id if has_id else None, has_id)
        if not has_id:
            # MCP notifications are deliberately side-effect free here except cancellation.
            return None
        if method == "initialize":
            return self._initialize(request_id, params)
        if method == "ping":
            return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": {}}
        if method == "tools/list":
            if set(params).difference({"cursor"}) or ("cursor" in params and not isinstance(params["cursor"], str)):
                return _error(request_id, -32602, "invalid params")
            return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": {"tools": self._definitions()}}
        if method == "tools/call":
            return self._call_tool(request_id, params)
        return _error(request_id, -32601, "method not found")

    def _initialize(self, request_id: str | int | None, params: dict[str, Any]) -> dict[str, Any]:
        allowed = {"protocolVersion", "capabilities", "clientInfo"}
        if set(params).difference(allowed) or (
            "protocolVersion" in params and not isinstance(params["protocolVersion"], str)
        ):
            return _error(request_id, -32602, "invalid params")
        requested = params.get("protocolVersion", MCP_PROTOCOL_VERSION)
        version = requested if requested == MCP_PROTOCOL_VERSION else MCP_PROTOCOL_VERSION
        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": request_id,
            "result": {
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "repo-dast-audit-mcp", "version": "0.1.0"},
            },
        }

    def _cancel_notification(
        self, params: dict[str, Any], request_id: str | int | None, has_id: bool
    ) -> dict[str, Any] | None:
        if set(params).difference({"requestId", "reason"}) or "requestId" not in params or not _is_request_id(params["requestId"]):
            return _error(request_id, -32602, "invalid params") if has_id else None
        if "reason" in params and not isinstance(params["reason"], str):
            return _error(request_id, -32602, "invalid params") if has_id else None
        self._cancelled.add(_cancellation_key(params["requestId"]))
        return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": {}} if has_id else None

    def _definitions(self):
        if not self.web_audit_enabled: return tool_definitions()
        from .web_audit.contracts import definitions
        return tool_definitions() + definitions()

    def _call_tool(self, request_id: str | int | None, params: dict[str, Any]) -> dict[str, Any]:
        if set(params).difference({"name", "arguments"}) or not isinstance(params.get("name"), str):
            return _error(request_id, -32602, "invalid params")
        name = params["name"]
        from .web_audit.contracts import TOOL_NAMES as WEB_NAMES, ContractError, validate_input
        if name not in TOOL_NAMES and not (self.web_audit_enabled and name in WEB_NAMES):
            return _error(request_id, -32602, "invalid params")
        try:
            arguments = (validate_tool_arguments(name, params.get("arguments", {})) if name in TOOL_NAMES
                         else validate_input(name, params.get("arguments", {})))
        except (InvalidToolArguments, ContractError):
            return _error(request_id, -32602, "invalid params")
        if self.tool_handler is None:
            result: Any = {
                "isError": True,
                "content": [{"type": "text", "text": "tool execution is unavailable"}],
            }
        else:
            result = self.tool_handler(
                name, arguments, lambda: _cancellation_key(request_id) in self._cancelled
            )
        return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}


def serve_stdio(
    protocol: JsonRpcProtocol,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
) -> None:
    """Run newline-delimited JSON-RPC until EOF; stdout carries protocol messages only."""
    source = input_stream if input_stream is not None else sys.stdin.buffer
    sink = output_stream if output_stream is not None else sys.stdout
    maximum = protocol.limits.frame_bytes
    response: dict[str, Any] | None
    while True:
        frame = source.readline(maximum + 2)
        if frame == b"":
            return
        too_large = len(frame) > maximum + 1 or (len(frame) == maximum + 1 and not frame.endswith(b"\n"))
        if too_large:
            # Drain the rest of this physical line before accepting the next request.
            while frame and not frame.endswith(b"\n"):
                frame = source.readline(maximum + 2)
            response = _error(None, -32000, "frame exceeds configured limit", {"code": "E_FRAME_LIMIT"})
        else:
            response = protocol.handle_frame(frame[:-1] if frame.endswith(b"\n") else frame)
        if response is not None:
            encoded = json.dumps(response, ensure_ascii=False, separators=(",", ":"))
            if len(encoded.encode("utf-8")) > maximum:
                encoded = json.dumps(_error(response.get("id"), -32000, "response exceeds configured limit", {"code":"E_FRAME_LIMIT"}),separators=(",",":"))
            sink.write(encoded + "\n")
            sink.flush()
