"""Zero-dependency MCP JSON-RPC 2.0 over stdio server for `mcp-public-intel`."""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import TYPE_CHECKING, Any, Callable, TextIO

if TYPE_CHECKING:
    import httpx

from mcp_public_intel import __version__
from mcp_public_intel.tools import TOOL_DEFINITIONS, UnknownToolError, dispatch_tool

SERVER_NAME = "mcp-public-intel"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
DEFAULT_PROTOCOL_VERSION = "2025-03-26"

# Standard JSON-RPC 2.0 error codes
ERR_PARSE_ERROR = -32700
ERR_INVALID_REQUEST = -32600
ERR_METHOD_NOT_FOUND = -32601
ERR_INVALID_PARAMS = -32602
ERR_INTERNAL_ERROR = -32603

SERVER_INSTRUCTIONS = (
    "Zero-API-key live public intelligence tools for SEC EDGAR XBRL financials & Form D funding, "
    "Greenhouse/Lever/Ashby ATS job boards, Shopify store catalogs, Substack public posts, "
    "and Apple iTunes / Podcasting 2.0 RSS transcripts. Never bypasses CAPTCHAs or paywalls."
)


def _jsonrpc_result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(
    req_id: Any,
    code: int,
    message: str,
    data: Any = None,
) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


class MCPServer:
    """Model Context Protocol JSON-RPC 2.0 server communicating over newline-delimited stdio."""

    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.initialized = False
        self._client = client
        self._sleep_fn = sleep_fn

    def _negotiate_protocol(self, params: dict[str, Any]) -> str:
        requested = params.get("protocolVersion")
        if isinstance(requested, str) and requested in SUPPORTED_PROTOCOL_VERSIONS:
            return requested
        return DEFAULT_PROTOCOL_VERSION

    def _handle_initialize(self, req_id: Any, params: Any) -> dict[str, Any]:
        if params is not None and not isinstance(params, dict):
            return _jsonrpc_error(req_id, ERR_INVALID_PARAMS, "initialize params must be an object")
        protocol_version = self._negotiate_protocol(params or {})
        return _jsonrpc_result(
            req_id,
            {
                "protocolVersion": protocol_version,
                "capabilities": {
                    "tools": {
                        "listChanged": False,
                    }
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": __version__,
                },
                "instructions": SERVER_INSTRUCTIONS,
            },
        )

    def _handle_tools_call(self, req_id: Any, params: Any) -> dict[str, Any]:
        if not isinstance(params, dict):
            return _jsonrpc_error(req_id, ERR_INVALID_PARAMS, "tools/call params must be an object")
        tool_name = params.get("name")
        if not isinstance(tool_name, str) or not tool_name.strip():
            return _jsonrpc_error(req_id, ERR_INVALID_PARAMS, "tools/call requires non-empty string 'name'")
        arguments = params.get("arguments")
        if arguments is not None and not isinstance(arguments, dict):
            return _jsonrpc_error(req_id, ERR_INVALID_PARAMS, "tools/call 'arguments' must be an object")

        try:
            payload = dispatch_tool(
                tool_name.strip(),
                arguments or {},
                client=self._client,
                sleep_fn=self._sleep_fn,
            )
        except UnknownToolError as exc:
            return _jsonrpc_error(req_id, ERR_METHOD_NOT_FOUND, str(exc))
        except Exception as exc:
            err_payload = {
                "status": "error",
                "tool": tool_name.strip(),
                "error_type": type(exc).__name__,
                "message": str(exc),
            }
            return _jsonrpc_result(
                req_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(err_payload, ensure_ascii=False, indent=2),
                        }
                    ],
                    "isError": True,
                },
            )

        return _jsonrpc_result(
            req_id,
            {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(payload, ensure_ascii=False, indent=2),
                    }
                ],
                "isError": False,
            },
        )

    def handle_message(self, message: Any) -> dict[str, Any] | None:
        """Process one decoded JSON-RPC 2.0 message and return a response dict or None for notifications."""
        if not isinstance(message, dict):
            return _jsonrpc_error(None, ERR_INVALID_REQUEST, "JSON-RPC request must be an object")

        has_id = "id" in message
        req_id = message.get("id")

        if message.get("jsonrpc") != "2.0":
            return _jsonrpc_error(
                req_id if has_id else None,
                ERR_INVALID_REQUEST,
                "Invalid Request: 'jsonrpc' must be '2.0'",
            )

        method = message.get("method")
        if not isinstance(method, str) or not method:
            return _jsonrpc_error(
                req_id if has_id else None,
                ERR_INVALID_REQUEST,
                "Invalid Request: 'method' must be a non-empty string",
            )

        params = message.get("params")

        if method == "notifications/initialized":
            self.initialized = True
            return _jsonrpc_result(req_id, {}) if has_id else None

        if method.startswith("notifications/"):
            return _jsonrpc_result(req_id, {}) if has_id else None

        if method == "initialize":
            return self._handle_initialize(req_id, params)

        if method == "ping":
            return _jsonrpc_result(req_id, {}) if has_id else None

        if method == "tools/list":
            return _jsonrpc_result(req_id, {"tools": TOOL_DEFINITIONS})

        if method == "tools/call":
            return self._handle_tools_call(req_id, params)

        if not has_id:
            return None
        return _jsonrpc_error(req_id, ERR_METHOD_NOT_FOUND, f"Method not found: {method}")

    def handle_line(self, line: str) -> str | None:
        """Parse one newline-delimited JSON-RPC frame and return the serialized response frame or None."""
        stripped = line.strip()
        if not stripped:
            return None
        try:
            decoded = json.loads(stripped)
        except json.JSONDecodeError as exc:
            err = _jsonrpc_error(None, ERR_PARSE_ERROR, f"Parse error: {exc.msg}")
            return json.dumps(err, ensure_ascii=False)

        if isinstance(decoded, list):
            if not decoded:
                return json.dumps(
                    _jsonrpc_error(None, ERR_INVALID_REQUEST, "Empty JSON-RPC batch"),
                    ensure_ascii=False,
                )
            responses: list[dict[str, Any]] = []
            for item in decoded:
                res = self.handle_message(item)
                if res is not None:
                    responses.append(res)
            return json.dumps(responses, ensure_ascii=False) if responses else None

        response = self.handle_message(decoded)
        if response is None:
            return None
        return json.dumps(response, ensure_ascii=False)

    def run_stdio(self, stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
        """Run the newline-delimited JSON-RPC 2.0 loop over stdin/stdout until EOF."""
        in_stream = stdin if stdin is not None else sys.stdin
        out_stream = stdout if stdout is not None else sys.stdout

        for raw_line in in_stream:
            frame = self.handle_line(raw_line)
            if frame is not None:
                out_stream.write(frame + "\n")
                out_stream.flush()
        return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `mcp-public-intel`."""
    parser = argparse.ArgumentParser(
        prog="mcp-public-intel",
        description="Zero-API-key MCP JSON-RPC 2.0 stdio server for live public intelligence.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{SERVER_NAME} {__version__}",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="Print available MCP tools as JSON and exit.",
    )
    args = parser.parse_args(argv)

    if args.list_tools:
        summary = [
            {
                "name": t["name"],
                "description": t["description"],
                "required": t["inputSchema"].get("required", []),
            }
            for t in TOOL_DEFINITIONS
        ]
        sys.stdout.write(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
        return 0

    server = MCPServer()
    try:
        return server.run_stdio()
    except (KeyboardInterrupt, BrokenPipeError):
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
