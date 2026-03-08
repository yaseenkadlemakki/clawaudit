"""Bearer token authentication middleware for ClawAudit API.

Token resolution order:
1. CLAWAUDIT_API_TOKEN environment variable
2. ~/.openclaw/sentinel/api-token file
3. Auto-generate on first startup, write to file

Exempt paths: /health, /docs, /redoc, /openapi.json, /api/v1/ws/*
WebSocket paths: accept token as ?token= query parameter
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

TOKEN_FILE = Path.home() / ".openclaw" / "sentinel" / "api-token"

EXEMPT_PATHS = {"/health", "/docs", "/redoc", "/openapi.json", "/api/v1/health"}

EXEMPT_PREFIXES = ("/api/v1/ws",)


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
        # 2. file
        if TOKEN_FILE.exists():
            return TOKEN_FILE.read_text().strip()
        # 3. generate
        token = secrets.token_hex(32)
        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        TOKEN_FILE.write_text(token)
        print(f"[ClawAudit] Generated API token: {token}")  # noqa: T201
        print(f"[ClawAudit] Token saved to: {TOKEN_FILE}")  # noqa: T201
        return token

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        path = request.url.path

        # Exempt paths
        if path in EXEMPT_PATHS or any(path.startswith(p) for p in EXEMPT_PREFIXES):
            return await call_next(request)

        # WebSocket: check ?token= query param
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
