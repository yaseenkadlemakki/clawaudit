"""Bearer token authentication middleware for ClawAudit API.

Token resolution order:
1. CLAWAUDIT_API_TOKEN environment variable
2. ~/.openclaw/sentinel/api-token file
3. Auto-generate on first startup, write to file

Exempt paths: /health, /docs, /redoc, /openapi.json, /api/v1/ws/*
WebSocket self-auth paths: /api/v1/hooks/stream (uses first-message auth — see hooks.py)
"""

from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

TOKEN_FILE = Path.home() / ".openclaw" / "sentinel" / "api-token"

EXEMPT_PATHS = {"/health", "/docs", "/redoc", "/openapi.json", "/api/v1/health"}

EXEMPT_PREFIXES = ("/api/v1/ws",)

# Paths that handle their own WebSocket authentication (e.g. first-message auth)
WS_SELF_AUTH_PATHS = frozenset({"/api/v1/hooks/stream"})


class AuthMiddleware(BaseHTTPMiddleware):
    """Require ``Authorization: Bearer <token>`` on all non-exempt endpoints."""

    def __init__(self, app, token: str | None = None):  # type: ignore[no-untyped-def]
        super().__init__(app)
        self._token = token or self._resolve_token()

    def _resolve_token(self) -> str:
        # 1. env var
        env_token = os.environ.get("CLAWAUDIT_API_TOKEN", "").strip()
        if env_token:
            return env_token
        # 2. file — only use if non-empty
        if TOKEN_FILE.exists():
            stored = TOKEN_FILE.read_text().strip()
            if stored:
                return stored
        # 3. generate — write with 0o600 permissions so only owner can read
        token = secrets.token_hex(32)
        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(TOKEN_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(token)
        except Exception:
            os.close(fd)
            raise
        logger.warning(
            "[ClawAudit] Generated new API token (first %s...); saved to %s",
            token[:8],
            TOKEN_FILE,
        )
        return token

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        path = request.url.path

        # Fully exempt paths (no auth required)
        if path in EXEMPT_PATHS or any(path.startswith(p) for p in EXEMPT_PREFIXES):
            return await call_next(request)

        # WebSocket endpoints that manage their own authentication
        if path in WS_SELF_AUTH_PATHS:
            return await call_next(request)

        # WebSocket: check ?token= query param (legacy WS endpoints at /api/v1/ws/*)
        upgrade = request.headers.get("upgrade", "").lower()
        if path.startswith("/ws") or "websocket" in upgrade:
            token = request.query_params.get("token", "")
        else:
            auth = request.headers.get("Authorization", "")
            token = auth.removeprefix("Bearer ").strip() if auth else ""

        if not secrets.compare_digest(token, self._token):
            return JSONResponse(status_code=401, content={"detail": "Invalid or missing API token"})

        return await call_next(request)

    @property
    def token(self) -> str:
        return self._token
