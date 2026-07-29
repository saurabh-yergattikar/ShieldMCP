"""Tests for the MCP proxy interceptor."""

import json

import pytest

from shieldmcp.proxy.interceptor import _make_error_response


class TestMakeErrorResponse:
    def test_basic_error_response(self):
        response = _make_error_response("req-1", -32600, "Blocked")
        assert response == {
            "jsonrpc": "2.0",
            "id": "req-1",
            "error": {"code": -32600, "message": "Blocked"},
        }

    def test_error_response_with_none_id(self):
        response = _make_error_response(None, -32700, "Parse error")
        assert response["id"] is None
        assert response["error"]["code"] == -32700
        assert "jsonrpc" in response

    def test_error_response_serializes_to_json(self):
        response = _make_error_response(1, -32600, "ShieldMCP blocked this call: SQL injection")
        serialized = json.dumps(response)
        parsed = json.loads(serialized)
        assert parsed["error"]["code"] == -32600
        assert "ShieldMCP blocked" in parsed["error"]["message"]
