"""Tests for hooks API hardening — issue #46 and #58."""

import pytest
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

    def test_malformed_content_length_does_not_500(self):
        """Malformed Content-Length header must not cause a 500."""
        client = TestClient(app)
        resp = client.post(
            "/api/v1/hooks/tool-event",
            content=b'{"tool_name": "test"}',
            headers={
                "Content-Type": "application/json",
                "Content-Length": "abc",
            },
        )
        assert resp.status_code != 500

    def test_negative_content_length_does_not_500(self):
        """Negative Content-Length must not cause a 500."""
        client = TestClient(app)
        resp = client.post(
            "/api/v1/hooks/tool-event",
            content=b'{"tool_name": "test"}',
            headers={
                "Content-Type": "application/json",
                "Content-Length": "-1",
            },
        )
        assert resp.status_code != 500


class TestWebSocketAuth:
    """Issue #58: WS token must be sent in first message, not URL query param."""

    def test_ws_endpoint_no_token_param(self):
        """The WebSocket endpoint signature must not accept token as query param."""
        import inspect

        from backend.api.routes.hooks import event_stream

        sig = inspect.signature(event_stream)
        params = list(sig.parameters.keys())
        assert "token" not in params, f"token should not be a query param. Params: {params}"

    def test_ws_rejects_wrong_token(self):
        """WS connection closed on wrong token."""
        client = TestClient(app)
        with pytest.raises(Exception):
            with client.websocket_connect("/api/v1/hooks/stream") as ws:
                ws.send_json({"type": "auth", "token": "wrong-token"})
                ws.receive_json()  # should raise on closed connection

    def test_ws_accepts_valid_auth(self):
        """WS connection proceeds with valid token."""
        import os

        token = os.environ.get("CLAWAUDIT_API_TOKEN", "")
        if not token:
            pytest.skip("CLAWAUDIT_API_TOKEN not set")
        client = TestClient(app)
        with client.websocket_connect("/api/v1/hooks/stream") as ws:
            ws.send_json({"type": "auth", "token": token})
            resp = ws.receive_json()
            assert resp["type"] == "auth_ok"
