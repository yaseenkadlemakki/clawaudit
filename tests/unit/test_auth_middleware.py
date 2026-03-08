"""Unit tests for backend.middleware.auth."""

from __future__ import annotations

from unittest.mock import patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from backend.middleware.auth import AuthMiddleware

pytestmark = pytest.mark.unit

TOKEN = "test-fixed-token-1234567890abcdef"


def _make_app(token: str | None = None) -> FastAPI:
    """Create a minimal FastAPI app with AuthMiddleware."""
    app = FastAPI()
    app.add_middleware(AuthMiddleware, token=token or TOKEN)

    @app.get("/api/v1/health")
    async def health():
        return {"status": "ok"}

    @app.get("/health")
    async def health_root():
        return {"status": "ok"}

    @app.get("/docs")
    async def docs():
        return {"docs": True}

    @app.get("/api/v1/data")
    async def data():
        return {"data": "secret"}

    return app


@pytest_asyncio.fixture
async def authed_client():
    app = _make_app()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {TOKEN}"},
    ) as c:
        yield c


@pytest.mark.asyncio
async def test_request_with_valid_token_passes(authed_client):
    r = await authed_client.get("/api/v1/data")
    assert r.status_code == 200
    assert r.json()["data"] == "secret"


@pytest.mark.asyncio
async def test_request_with_invalid_token_returns_401(tmp_path):
    app = _make_app()
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
        headers={"Authorization": "Bearer wrong-token"},
    ) as c:
        r = await c.get("/api/v1/data")
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_request_with_missing_token_returns_401(tmp_path):
    app = _make_app()
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as c:
        r = await c.get("/api/v1/data")
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_health_endpoint_exempt():
    app = _make_app()
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as c:
        r = await c.get("/api/v1/health")
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_docs_endpoint_exempt():
    app = _make_app()
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as c:
        r = await c.get("/docs")
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_token_generated_if_not_set(tmp_path, monkeypatch):
    """When no env var and no file, token is auto-generated."""
    monkeypatch.delenv("CLAWAUDIT_API_TOKEN", raising=False)
    token_file = tmp_path / "api-token"
    with patch("backend.middleware.auth.TOKEN_FILE", token_file):
        mw = AuthMiddleware(FastAPI())
        assert mw.token  # Non-empty
        assert token_file.exists()
        assert token_file.read_text().strip() == mw.token


@pytest.mark.asyncio
async def test_token_loaded_from_env(monkeypatch):
    monkeypatch.setenv("CLAWAUDIT_API_TOKEN", "env-token-123")
    mw = AuthMiddleware(FastAPI())
    assert mw.token == "env-token-123"


@pytest.mark.asyncio
async def test_token_loaded_from_file(tmp_path, monkeypatch):
    monkeypatch.delenv("CLAWAUDIT_API_TOKEN", raising=False)
    token_file = tmp_path / "api-token"
    token_file.write_text("file-token-456")
    with patch("backend.middleware.auth.TOKEN_FILE", token_file):
        mw = AuthMiddleware(FastAPI())
        assert mw.token == "file-token-456"


@pytest.mark.asyncio
async def test_websocket_accepts_query_param_token():
    """WebSocket paths accept token as ?token= query parameter."""
    app = _make_app()

    @app.get("/ws/test")
    async def ws_endpoint():
        return {"ws": True}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        r = await c.get(f"/ws/test?token={TOKEN}")
        assert r.status_code == 200


class TestTokenFileSecurity:
    def test_generated_token_file_has_restrictive_permissions(self, tmp_path, monkeypatch):
        """Token file must be written with 0o600 — not world-readable."""
        import stat

        from backend.middleware.auth import AuthMiddleware

        token_file = tmp_path / "api-token"
        monkeypatch.delenv("CLAWAUDIT_API_TOKEN", raising=False)

        # Patch TOKEN_FILE to our tmp location
        import backend.middleware.auth as auth_mod

        original = auth_mod.TOKEN_FILE
        auth_mod.TOKEN_FILE = token_file
        try:
            middleware = AuthMiddleware.__new__(AuthMiddleware)
            middleware._token = middleware._resolve_token.__func__(middleware)
            assert token_file.exists()
            mode = oct(stat.S_IMODE(token_file.stat().st_mode))
            assert mode == oct(0o600), f"Token file permissions {mode} should be 0o600"
        finally:
            auth_mod.TOKEN_FILE = original

    def test_empty_token_file_triggers_generation(self, tmp_path, monkeypatch):
        """An empty token file should be treated as missing and regenerate."""
        from backend.middleware.auth import AuthMiddleware

        token_file = tmp_path / "api-token"
        token_file.write_text("")  # empty
        monkeypatch.delenv("CLAWAUDIT_API_TOKEN", raising=False)

        import backend.middleware.auth as auth_mod

        original = auth_mod.TOKEN_FILE
        auth_mod.TOKEN_FILE = token_file
        try:
            middleware = AuthMiddleware.__new__(AuthMiddleware)
            token = middleware._resolve_token.__func__(middleware)
            assert len(token) > 0
        finally:
            auth_mod.TOKEN_FILE = original


class TestWSAuthExemption:
    """WS endpoints that handle their own auth must not be intercepted by middleware."""

    def test_ws_self_auth_paths_constant_exists(self):
        """WS_SELF_AUTH_PATHS frozenset must exist and contain the hooks stream path."""
        from backend.middleware.auth import WS_SELF_AUTH_PATHS

        assert isinstance(WS_SELF_AUTH_PATHS, frozenset)
        assert "/api/v1/hooks/stream" in WS_SELF_AUTH_PATHS

    @pytest.mark.asyncio
    async def test_hooks_stream_not_blocked_by_middleware(self):
        """Requests to /api/v1/hooks/stream must pass through middleware without 401.

        The endpoint handles its own auth via first-message. Middleware must
        not reject the WS upgrade for missing ?token= query param.
        """
        app = _make_app()

        @app.get("/api/v1/hooks/stream")
        async def hooks_stream():
            return {"stream": True}

        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as c:
            # No token — middleware should let it through
            r = await c.get("/api/v1/hooks/stream")
            assert r.status_code == 200, (
                f"Expected 200 (middleware pass-through), got {r.status_code}"
            )

    @pytest.mark.asyncio
    async def test_hooks_stream_ws_upgrade_not_blocked(self):
        """WS upgrade to /api/v1/hooks/stream with Upgrade header must not get 401."""
        app = _make_app()

        @app.get("/api/v1/hooks/stream")
        async def hooks_stream():
            return {"stream": True}

        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as c:
            # Simulate a WebSocket upgrade header without ?token=
            r = await c.get(
                "/api/v1/hooks/stream",
                headers={"Upgrade": "websocket"},
            )
            # Should NOT be 401 — middleware must exempt this path
            assert r.status_code != 401, (
                "Middleware blocked WS upgrade with 401; should exempt WS_SELF_AUTH_PATHS"
            )

    @pytest.mark.asyncio
    async def test_regular_http_still_requires_auth(self):
        """Non-exempt HTTP routes must still require Authorization header."""
        app = _make_app()
        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as c:
            r = await c.get("/api/v1/data")
            assert r.status_code == 401
