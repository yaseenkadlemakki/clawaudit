"""Tests for hooks API hardening — issue #46 and #58."""
import json
import pytest
from httpx import AsyncClient
from fastapi.testclient import TestClient
from backend.main import app


class TestBodySizeLimit:
    """Issue #46: Request body must be rejected if Content-Length > 64KB."""

    def test_normal_request_accepted(self):
        client = TestClient(app)
        payload = {"tool_name": "exec", "params_summary": "ls -la"}
        # Supply HMAC — skip for now, just test size limit path
        resp = client.post(
            "/api/v1/hooks/tool-event",
            json=payload,
            headers={"Content-Length": "100"},
        )
        # Should NOT be 413 (may be 401/422 for missing hmac — that's fine)
        assert resp.status_code != 413

    def test_oversized_request_rejected(self):
        client = TestClient(app)
        resp = client.post(
            "/api/v1/hooks/tool-event",
            content=b"x" * (65 * 1024),
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(65 * 1024),
            },
        )
        assert resp.status_code == 413

    def test_exact_limit_accepted(self):
        client = TestClient(app)
        # 64KB exactly should be accepted (may fail for other reasons like JSON parse)
        resp = client.post(
            "/api/v1/hooks/tool-event",
            content=b"x" * (64 * 1024),
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(64 * 1024),
            },
        )
        assert resp.status_code != 413


class TestWebSocketAuth:
    """Issue #58: WS token must be sent in first message, not URL query param."""

    def test_ws_rejects_no_auth_message(self):
        """Connection must be closed if no auth message sent within timeout."""
        # We test via direct route inspection — actual async WS test needs pytest-anyio
        from backend.api.routes import hooks
        import inspect
        src = inspect.getsource(hooks.event_stream)
        # Token must NOT be a query param anymore
        assert "token: str" not in src, "Token must not be a URL query param"
        assert "receive_text" in src or "receive_json" in src, "Should read first message"

    def test_ws_endpoint_no_token_param(self):
        """The WebSocket endpoint signature must not accept token as query param."""
        import inspect
        from backend.api.routes.hooks import event_stream
        sig = inspect.signature(event_stream)
        params = list(sig.parameters.keys())
        # 'websocket' is fine, 'token' should not be a param
        assert "token" not in params, f"token should not be a query param. Params: {params}"
