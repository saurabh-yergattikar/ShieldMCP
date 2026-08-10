"""Regression tests for StdioProxy handling of BLOCKED outbound tools/call.

When the pipeline blocks an outbound ``tools/call``, the proxy must write the
JSON-RPC error response back to the client (stdout) as a Content-Length-framed
message, and must NOT forward the blocked request to the server.

The proxy's IO is driven with fake asyncio transports so the tests are
deterministic and do not depend on real OS pipes (which ProactorEventLoop on
Windows cannot wrap in overlapped mode for arbitrary fds).
"""

from __future__ import annotations

import asyncio
import json
import types

import pytest

from shieldmcp.core.config import ShieldMCPConfig
from shieldmcp.proxy.interceptor import StdioProxy


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
    """Read-side transport stand-in; data is pushed via the protocol."""

    def is_closing(self) -> bool:
        return False

    def close(self) -> None:
        pass


def _frame(message: dict) -> bytes:
    raw = json.dumps(message)
    return f"Content-Length: {len(raw)}\r\n\r\n{raw}".encode()


def _parse_frames(buffered: bytes) -> list[dict]:
    messages = []
    buf = buffered
    while buf:
        header, sep, rest = buf.partition(b"\r\n\r\n")
        if not sep:
            break
        content_length = None
        for line in header.split(b"\r\n"):
            key, _, value = line.partition(b":")
            if key.strip().lower() == b"content-length":
                content_length = int(value.strip())
                break
        if content_length is None:
            break
        messages.append(json.loads(rest[:content_length].decode("utf-8")))
        buf = rest[content_length:]
    return messages


@pytest.fixture
async def harness(tmp_path, monkeypatch):
    """A StdioProxy whose stdin/stdout are driven by fake transports."""

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
    proto.data_received(_frame(message))
    proto.eof_received()
    await asyncio.wait_for(task, timeout=10)


class TestBlockedToolsCall:
    @pytest.mark.asyncio
    async def test_blocked_call_returns_error_to_client(
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

        responses = _parse_frames(bytes(harness.stdout_transport.buffered))
        assert len(responses) == 1
        response = responses[0]
        assert response.get("jsonrpc") == "2.0"
        assert response.get("id") == 42
        assert "error" in response
        assert response["error"]["code"] == -32600
        assert "blocked" in response["error"]["message"].lower()

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
        forwarded = _parse_frames(bytes(harness.server_stdin.buffered))
        assert len(forwarded) == 1
        assert forwarded[0]["id"] == 7
        assert forwarded[0]["method"] == "tools/call"
        assert "error" not in forwarded[0]
