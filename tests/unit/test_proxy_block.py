"""Regression tests: blocked tools/call must yield a JSON-RPC error, not a hang.

When Stage 2 blocks an outbound tools/call, StdioProxy must write the error
response back to the client (stdout) and must NOT forward the request to the
server. Previously the error was written into the server's stdin, so the
client saw a dropped message / TaskGroup exception.
"""

from __future__ import annotations

import asyncio
import json
import types

import pytest

from shieldmcp.core.config import ShieldMCPConfig
from shieldmcp.proxy.interceptor import StdioProxy, _encode_frame, _make_error_response


class _RecordingTransport:
    """Minimal asyncio transport stand-in that records everything written."""

    def __init__(self) -> None:
        self.buffered = bytearray()

    def write(self, data: bytes) -> None:
        self.buffered.extend(data)

    def get_write_buffer_size(self) -> int:
        return 0

    def is_closing(self) -> bool:
        return False

    def close(self) -> None:
        pass

    async def drain(self) -> None:
        pass


class _EchoTransport:
    def is_closing(self) -> bool:
        return False

    def close(self) -> None:
        pass


def _parse_line_frames(buffered: bytes) -> list[dict]:
    """Parse newline-delimited JSON-RPC frames (MCP stdio default)."""
    messages: list[dict] = []
    for line in buffered.split(b"\n"):
        line = line.strip()
        if not line:
            continue
        messages.append(json.loads(line.decode("utf-8")))
    return messages


@pytest.fixture
async def harness(tmp_path, monkeypatch):
    """StdioProxy whose stdin/stdout are driven by fake transports."""
    loop = asyncio.get_running_loop()
    read_ready = asyncio.Event()
    read_protocols: list = []
    stdout_transport = _RecordingTransport()

    async def fake_connect_read_pipe(protocol_factory, pipe):
        proto = protocol_factory()
        read_protocols.append(proto)
        read_ready.set()
        return _EchoTransport()

    async def fake_connect_write_pipe(protocol_factory, pipe):
        return stdout_transport, protocol_factory()

    monkeypatch.setattr(loop, "connect_read_pipe", fake_connect_read_pipe)
    monkeypatch.setattr(loop, "connect_write_pipe", fake_connect_write_pipe)

    config = ShieldMCPConfig()
    config.registry_db_path = str(tmp_path / "test_registry.db")

    proxy = StdioProxy(["fake-server"], config, server_id="test-server")
    server_stdin = _RecordingTransport()
    proxy._server_process = types.SimpleNamespace(stdin=server_stdin)
    # Mirror start(): shared client writer used for blocked-call errors.
    proxy._client_writer = asyncio.StreamWriter(
        stdout_transport, asyncio.streams.FlowControlMixin(), None, loop
    )

    return types.SimpleNamespace(
        proxy=proxy,
        server_stdin=server_stdin,
        stdout_transport=stdout_transport,
        read_protocols=read_protocols,
        read_ready=read_ready,
    )


async def _run_client_to_server(harness, message: dict) -> None:
    await harness.proxy.pipeline.initialize()
    task = asyncio.create_task(harness.proxy._client_to_server())
    await asyncio.wait_for(harness.read_ready.wait(), timeout=5)
    proto = harness.read_protocols[0]
    # Default MCP stdio framing is newline-delimited JSON.
    proto.data_received(_encode_frame(message, "line"))
    proto.eof_received()
    await asyncio.wait_for(task, timeout=10)


class TestBlockedToolsCall:
    @pytest.mark.asyncio
    async def test_blocked_call_returns_jsonrpc_error_to_client(
        self, harness: types.SimpleNamespace
    ) -> None:
        request = {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {
                "name": "query",
                "arguments": {"sql": "SELECT * FROM users; DROP TABLE users; --"},
            },
        }

        await _run_client_to_server(harness, request)

        responses = _parse_line_frames(bytes(harness.stdout_transport.buffered))
        assert len(responses) == 1
        response = responses[0]
        assert response.get("jsonrpc") == "2.0"
        assert response.get("id") == 42
        assert "error" in response
        assert response["error"]["code"] == -32600
        assert "ShieldMCP" in response["error"]["message"]
        assert "blocked" in response["error"]["message"].lower()

        # Blocked request must not be forwarded to the server.
        assert bytes(harness.server_stdin.buffered) == b""

    @pytest.mark.asyncio
    async def test_benign_call_still_forwarded_to_server(
        self, harness: types.SimpleNamespace
    ) -> None:
        request = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "search", "arguments": {"query": "python tutorials"}},
        }

        await _run_client_to_server(harness, request)

        assert bytes(harness.stdout_transport.buffered) == b""
        forwarded = _parse_line_frames(bytes(harness.server_stdin.buffered))
        assert len(forwarded) == 1
        assert forwarded[0]["id"] == 7
        assert forwarded[0]["method"] == "tools/call"
        assert "error" not in forwarded[0]


class TestMakeErrorResponse:
    def test_error_includes_shieldmcp_reason(self) -> None:
        err = _make_error_response(99, -32600, "ShieldMCP blocked this call: policy")
        assert err == {
            "jsonrpc": "2.0",
            "id": 99,
            "error": {"code": -32600, "message": "ShieldMCP blocked this call: policy"},
        }
