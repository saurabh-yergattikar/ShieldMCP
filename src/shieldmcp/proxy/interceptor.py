"""MCP Transparent Proxy — intercepts JSON-RPC messages between client and server.

Sits between the LLM agent (MCP client) and MCP servers, intercepting:
- tools/list responses → Stage 1 validation
- tools/call requests → Stage 2 validation
- tools/call responses → Stage 3 validation

Requires no modifications to either the client or server.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import uuid
from typing import Any

from ..core.config import ShieldMCPConfig
from ..core.models import Action
from ..core.pipeline import ShieldPipeline

logger = logging.getLogger("shieldmcp.proxy")


class StdioProxy:
    """Transparent MCP proxy over stdio transport.

    Reads JSON-RPC messages from stdin (client side), forwards to a subprocess
    (the real MCP server), intercepts responses, and writes back to stdout.
    """

    def __init__(
        self,
        server_command: list[str],
        config: ShieldMCPConfig,
        server_id: str = "default",
    ) -> None:
        self.server_command = server_command
        self.config = config
        self.server_id = server_id
        self.pipeline = ShieldPipeline(config)
        self._server_process: asyncio.subprocess.Process | None = None
        # Stable per-connection session so cross-call correlation and response
        # tool-name resolution work across the whole client session.
        self._session_id: str = str(uuid.uuid4())
        # Framing observed from each peer, so we forward using the framing that
        # peer speaks. The MCP stdio spec is newline-delimited JSON; some clients
        # use LSP-style Content-Length. We detect and mirror rather than assume.
        self._client_framing: str = "line"
        self._server_framing: str = "line"
        # Shared stdout writer so blocked-call errors and server replies both
        # reach the client without competing for sys.stdout.
        self._client_writer: asyncio.StreamWriter | None = None

    async def start(self) -> None:
        """Start the proxy: initialize pipeline and spawn the real MCP server."""
        await self.pipeline.initialize()

        self._server_process = await asyncio.create_subprocess_exec(
            *self.server_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        logger.info(
            "MCP server started: %s (pid=%s)",
            " ".join(self.server_command),
            self._server_process.pid,
        )

        writer_transport, writer_protocol = await asyncio.get_event_loop().connect_write_pipe(
            asyncio.streams.FlowControlMixin, sys.stdout.buffer
        )
        self._client_writer = asyncio.StreamWriter(
            writer_transport, writer_protocol, None, asyncio.get_event_loop()
        )

        await asyncio.gather(
            self._client_to_server(),
            self._server_to_client(),
            self._log_server_stderr(),
        )

    async def _client_to_server(self) -> None:
        """Read from client (stdin), intercept, forward to server.

        When Stage 2 blocks an outbound tools/call, write a JSON-RPC error back
        to the client (stdout) instead of forwarding the request to the server.
        """
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        assert self._server_process and self._server_process.stdin
        assert self._client_writer is not None

        try:
            async for message, framing in _read_jsonrpc_messages(reader):
                self._client_framing = framing
                intercepted = await self._intercept_client_message(message)
                if intercepted is None:
                    continue
                if "error" in intercepted:
                    # Blocked request: return the error to the client; do not
                    # forward anything to the server (matches SSE proxy behaviour).
                    frame = _encode_frame(intercepted, self._client_framing)
                    self._client_writer.write(frame)
                    await self._client_writer.drain()
                    continue
                # Forward using the framing the server speaks (defaults to the
                # spec's newline-delimited form until the server reveals otherwise).
                frame = _encode_frame(intercepted, self._server_framing)
                self._server_process.stdin.write(frame)
                await self._server_process.stdin.drain()
        except (asyncio.CancelledError, ConnectionError):
            pass
        finally:
            await self.pipeline.shutdown()

    async def _server_to_client(self) -> None:
        """Read from server (subprocess stdout), intercept, forward to client."""
        assert self._server_process and self._server_process.stdout
        assert self._client_writer is not None

        try:
            async for message, framing in _read_jsonrpc_messages(self._server_process.stdout):
                self._server_framing = framing
                intercepted = await self._intercept_server_message(message)
                if intercepted is not None:
                    # Forward using the framing the client speaks.
                    frame = _encode_frame(intercepted, self._client_framing)
                    self._client_writer.write(frame)
                    await self._client_writer.drain()
        except (asyncio.CancelledError, ConnectionError):
            pass

    async def _log_server_stderr(self) -> None:
        """Forward server stderr to our logging."""
        assert self._server_process and self._server_process.stderr
        try:
            async for line in self._server_process.stderr:
                logger.debug("[server stderr] %s", line.decode().strip())
        except (asyncio.CancelledError, ConnectionError):
            pass

    async def _intercept_client_message(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """Intercept outbound client→server messages."""
        method = msg.get("method", "")

        if method == "tools/call":
            params = msg.get("params", {})
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})

            action, alerts = await self.pipeline.process_tool_call(
                self.server_id, tool_name, arguments, self._session_id
            )

            if action == Action.BLOCK:
                logger.warning("BLOCKED tool call: %s (alerts: %d)", tool_name, len(alerts))
                return _make_error_response(
                    msg.get("id"),
                    -32600,
                    f"ShieldMCP blocked this call: {alerts[0].message if alerts else 'security policy'}",
                )

        return msg

    async def _intercept_server_message(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """Intercept inbound server→client messages."""
        # Check if this is a tools/list response
        if "result" in msg and isinstance(msg["result"], dict):
            result = msg["result"]

            # tools/list response has a "tools" key
            if "tools" in result and isinstance(result["tools"], list):
                action, filtered_tools, alerts = await self.pipeline.validate_tools(
                    self.server_id, result["tools"]
                )
                msg = {**msg, "result": {**result, "tools": filtered_tools}}

                if action == Action.BLOCK:
                    logger.warning(
                        "BLOCKED tools/list: all tools removed (alerts: %d)", len(alerts)
                    )

            # tools/call response has "content" key
            elif "content" in result:
                tool_name = self._last_called_tool or "unknown"
                action, modified, alerts = await self.pipeline.process_tool_response(
                    self.server_id, tool_name, result["content"], self._session_id
                )
                msg = {**msg, "result": {**result, "content": modified}}

                if action == Action.BLOCK:
                    return _make_error_response(
                        msg.get("id"),
                        -32600,
                        f"ShieldMCP blocked response: {alerts[0].message if alerts else 'security policy'}",
                    )

        return msg

    @property
    def _last_called_tool(self) -> str | None:
        if self._session_id and self._session_id in self.pipeline._sessions:
            calls = self.pipeline._sessions[self._session_id].tool_calls
            if calls:
                return calls[-1].tool_name
        return None


def _make_error_response(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": code, "message": message},
    }


def _encode_frame(msg: dict, framing: str) -> bytes:
    """Serialize a JSON-RPC message using the peer's framing.

    'line' is the MCP stdio spec's newline-delimited JSON; 'lsp' is the
    LSP-style Content-Length framing some clients use.
    """
    raw = json.dumps(msg)
    if framing == "lsp":
        return f"Content-Length: {len(raw)}\r\n\r\n{raw}".encode()
    return (raw + "\n").encode()


async def _read_jsonrpc_messages(reader: asyncio.StreamReader):
    """Parse JSON-RPC messages from a stream, auto-detecting the framing.

    Yields (message, framing) where framing is 'line' (newline-delimited JSON,
    the MCP stdio spec) or 'lsp' (Content-Length headers). Detection is per
    message: a line beginning with 'Content-Length:' switches to LSP framing;
    any other non-empty line is treated as one complete JSON message.
    """
    while True:
        line = await reader.readline()
        if not line:
            return
        line_str = line.decode("utf-8").strip()
        if not line_str:
            continue

        if line_str.lower().startswith("content-length:"):
            # LSP framing: this and following lines are headers until a blank line.
            headers = {"content-length": line_str.split(":", 1)[1].strip()}
            while True:
                hline = await reader.readline()
                if not hline:
                    return
                hstr = hline.decode("utf-8").strip()
                if not hstr:
                    break
                if ":" in hstr:
                    key, value = hstr.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
            content_length = int(headers.get("content-length", 0))
            if content_length == 0:
                continue
            body = await reader.readexactly(content_length)
            try:
                yield json.loads(body.decode("utf-8")), "lsp"
            except json.JSONDecodeError:
                logger.error("Failed to parse JSON-RPC message: %s", body[:200])
        else:
            # Newline-delimited JSON (MCP stdio spec).
            try:
                yield json.loads(line_str), "line"
            except json.JSONDecodeError:
                logger.error("Failed to parse JSON-RPC line: %s", line_str[:200])
