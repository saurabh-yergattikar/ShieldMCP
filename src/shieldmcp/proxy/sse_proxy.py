"""MCP SSE Transport Proxy — intercepts JSON-RPC messages over HTTP/SSE.

Sits between the LLM agent (MCP client) and a remote MCP server using the SSE
transport, intercepting the same three stages as the stdio proxy:
- tools/list responses → Stage 1 validation
- tools/call requests  → Stage 2 validation
- tools/call responses → Stage 3 validation

MCP SSE protocol:
  GET  /sse      → server-sent event stream (endpoint + message events)
  POST /messages → client sends JSON-RPC requests
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

import httpx
from aiohttp import web

from ..core.config import ShieldMCPConfig
from ..core.models import Action
from ..core.pipeline import ShieldPipeline

logger = logging.getLogger("shieldmcp.proxy.sse")


class _SSESession:
    """Per-client connection state."""

    __slots__ = ("session_id", "response", "backend_endpoint", "last_called_tool")

    def __init__(self, session_id: str, response: web.StreamResponse) -> None:
        self.session_id = session_id
        self.response = response
        self.backend_endpoint: str | None = None
        self.last_called_tool: str | None = None


class SSEProxy:
    """Transparent MCP proxy over SSE transport.

    Accepts SSE connections from MCP clients, forwards JSON-RPC traffic to a
    backend MCP server, and runs the ShieldMCP validation pipeline on every
    message in both directions.
    """

    def __init__(
        self,
        backend_url: str,
        config: ShieldMCPConfig,
        server_id: str = "default",
    ) -> None:
        self.backend_url = backend_url.rstrip("/")
        self.config = config
        self.server_id = server_id
        self.pipeline = ShieldPipeline(config)
        self.host = config.proxy.host
        self.port = config.proxy.port
        self._sessions: dict[str, _SSESession] = {}
        self._runner: web.AppRunner | None = None

    async def start(self) -> None:
        await self.pipeline.initialize()

        app = web.Application()
        app.router.add_get("/sse", self._handle_sse)
        app.router.add_post("/messages", self._handle_messages)

        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.host, self.port)
        await site.start()

        logger.info(
            "SSE proxy listening on http://%s:%d → %s",
            self.host,
            self.port,
            self.backend_url,
        )

        try:
            await asyncio.Event().wait()
        except (KeyboardInterrupt, asyncio.CancelledError):
            await self.stop()

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
        await self.pipeline.shutdown()
        logger.info("SSE proxy stopped")

    # ------------------------------------------------------------------
    # HTTP handlers
    # ------------------------------------------------------------------

    async def _handle_sse(self, request: web.Request) -> web.StreamResponse:
        """Client connects here to open an SSE event stream."""
        session_id = str(uuid.uuid4())

        response = web.StreamResponse(
            status=200,
            reason="OK",
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            },
        )
        await response.prepare(request)

        session = _SSESession(session_id, response)
        self._sessions[session_id] = session

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(None)) as client:
                async with client.stream("GET", f"{self.backend_url}/sse") as backend:
                    await self._relay_backend_sse(backend, session)
        except (ConnectionError, httpx.HTTPError) as exc:
            logger.error("Backend SSE connection lost: %s", exc)
        finally:
            self._sessions.pop(session_id, None)

        return response

    async def _handle_messages(self, request: web.Request) -> web.Response:
        """Client POSTs JSON-RPC requests here."""
        session_id = request.query.get("sessionId", "")
        session = self._sessions.get(session_id)

        if not session:
            return web.json_response(
                _make_error(None, -32600, "Invalid or missing session"),
                status=400,
            )

        if not session.backend_endpoint:
            return web.json_response(
                _make_error(None, -32600, "Backend not ready"),
                status=503,
            )

        body: dict[str, Any] = await request.json()

        intercepted = await self._intercept_client_message(body, session)

        # If interception produced an error (blocked), push it on the SSE
        # stream and return 202 to match normal MCP flow.
        if intercepted is not None and "error" in intercepted:
            await _write_sse(session.response, "message", json.dumps(intercepted))
            return web.Response(status=202)

        msg_to_forward = intercepted if intercepted is not None else body

        async with httpx.AsyncClient() as client:
            backend_resp = await client.post(
                session.backend_endpoint,
                json=msg_to_forward,
                headers={"Content-Type": "application/json"},
            )

        return web.Response(status=backend_resp.status_code)

    # ------------------------------------------------------------------
    # Backend SSE relay
    # ------------------------------------------------------------------

    async def _relay_backend_sse(
        self,
        backend: httpx.Response,
        session: _SSESession,
    ) -> None:
        """Parse SSE events from the backend stream and relay to the client."""
        event_type = ""
        data_lines: list[str] = []

        async for raw_line in backend.aiter_lines():
            if raw_line.startswith("event:"):
                event_type = raw_line[6:].strip()

            elif raw_line.startswith("data:"):
                data_lines.append(raw_line[5:].lstrip(" "))

            elif raw_line == "":
                event_data = "\n".join(data_lines)
                await self._dispatch_backend_event(event_type, event_data, session)
                event_type = ""
                data_lines = []

    async def _dispatch_backend_event(
        self,
        event_type: str,
        event_data: str,
        session: _SSESession,
    ) -> None:
        if event_type == "endpoint":
            endpoint = event_data
            if endpoint.startswith("/"):
                endpoint = self.backend_url + endpoint
            session.backend_endpoint = endpoint

            proxy_endpoint = f"/messages?sessionId={session.session_id}"
            await _write_sse(session.response, "endpoint", proxy_endpoint)

        elif event_type == "message":
            try:
                msg = json.loads(event_data)
            except json.JSONDecodeError:
                await _write_sse(session.response, event_type, event_data)
                return

            intercepted = await self._intercept_server_message(msg, session)
            if intercepted is not None:
                await _write_sse(session.response, "message", json.dumps(intercepted))

        elif event_type:
            await _write_sse(session.response, event_type, event_data)

    # ------------------------------------------------------------------
    # Interception logic (mirrors StdioProxy)
    # ------------------------------------------------------------------

    async def _intercept_client_message(
        self, msg: dict[str, Any], session: _SSESession
    ) -> dict[str, Any] | None:
        method = msg.get("method", "")

        if method == "tools/call":
            params = msg.get("params", {})
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            session.last_called_tool = tool_name

            action, alerts = await self.pipeline.process_tool_call(
                self.server_id, tool_name, arguments, session.session_id
            )

            if action == Action.BLOCK:
                logger.warning("BLOCKED tool call: %s (alerts: %d)", tool_name, len(alerts))
                return _make_error(
                    msg.get("id"),
                    -32600,
                    f"ShieldMCP blocked this call: "
                    f"{alerts[0].message if alerts else 'security policy'}",
                )

        return msg

    async def _intercept_server_message(
        self, msg: dict[str, Any], session: _SSESession
    ) -> dict[str, Any] | None:
        if "result" not in msg or not isinstance(msg["result"], dict):
            return msg

        result = msg["result"]

        if "tools" in result and isinstance(result["tools"], list):
            action, filtered_tools, alerts = await self.pipeline.validate_tools(
                self.server_id, result["tools"]
            )
            msg = {**msg, "result": {**result, "tools": filtered_tools}}

            if action == Action.BLOCK:
                logger.warning(
                    "BLOCKED tools/list: all tools removed (alerts: %d)", len(alerts)
                )

        elif "content" in result:
            tool_name = session.last_called_tool or "unknown"
            action, modified, alerts = await self.pipeline.process_tool_response(
                self.server_id, tool_name, result["content"], session.session_id
            )
            msg = {**msg, "result": {**result, "content": modified}}

            if action == Action.BLOCK:
                return _make_error(
                    msg.get("id"),
                    -32600,
                    f"ShieldMCP blocked response: "
                    f"{alerts[0].message if alerts else 'security policy'}",
                )

        return msg


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _make_error(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": code, "message": message},
    }


async def _write_sse(response: web.StreamResponse, event: str, data: str) -> None:
    lines = data.split("\n")
    payload = f"event: {event}\n"
    for line in lines:
        payload += f"data: {line}\n"
    payload += "\n"
    await response.write(payload.encode())
