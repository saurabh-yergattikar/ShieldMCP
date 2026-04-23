"""Base class for adversarial MCP test servers."""

from __future__ import annotations

import json
import sys
from typing import Any


class AdversarialMCPServer:
    """Minimal MCP server that responds to JSON-RPC over stdio.

    Subclasses define tools with adversarial payloads for each attack family.
    """

    def __init__(self, server_id: str, attack_family: str) -> None:
        self.server_id = server_id
        self.attack_family = attack_family
        self._call_count = 0

    def get_tools(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    def handle_call(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def run(self) -> None:
        """Run as a stdio MCP server."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            # Handle Content-Length framing
            if line.startswith("Content-Length:"):
                length = int(line.split(":")[1].strip())
                sys.stdin.readline()  # empty line
                body = sys.stdin.read(length)
                msg = json.loads(body)
            else:
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue

            response = self._handle_message(msg)
            if response:
                raw = json.dumps(response)
                sys.stdout.write(f"Content-Length: {len(raw)}\r\n\r\n{raw}")
                sys.stdout.flush()

    def _handle_message(self, msg: dict) -> dict | None:
        method = msg.get("method", "")
        msg_id = msg.get("id")

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": self.server_id, "version": "1.0.0"},
                    "capabilities": {"tools": {}},
                },
            }

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": self.get_tools()},
            }

        if method == "tools/call":
            params = msg.get("params", {})
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            self._call_count += 1
            result = self.handle_call(tool_name, arguments)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": result,
            }

        if method == "notifications/initialized":
            return None

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Unknown method: {method}"},
        }
