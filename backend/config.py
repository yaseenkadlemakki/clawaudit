"""Backend configuration for ClawAudit API server."""
from __future__ import annotations

import os
from pathlib import Path


class BackendConfig:
    """Configuration for the FastAPI backend service.

    All env vars are read at instantiation so tests can set them before
    constructing a BackendConfig (or before importing backend.database).
    """

    def __init__(self) -> None:
        # Database
        self.DATABASE_URL: str = os.getenv(
            "DATABASE_URL",
            f"sqlite+aiosqlite:///{Path.home()}/.openclaw/sentinel/clawaudit.db",
        )

        # Server
        self.HOST: str = os.getenv("CLAWAUDIT_HOST", "127.0.0.1")
        self.PORT: int = int(os.getenv("CLAWAUDIT_PORT", "18790"))
        self.LOG_LEVEL: str = os.getenv("CLAWAUDIT_LOG_LEVEL", "info")

        # CORS — comma-separated list of allowed origins
        cors_env = os.getenv(
            "CLAWAUDIT_CORS_ORIGINS",
            "http://localhost:3000,http://localhost:5173",
        )
        self.CORS_ORIGINS: list[str] = [o.strip() for o in cors_env.split(",") if o.strip()]

        # API metadata
        self.API_VERSION: str = "2.0.0"
        self.API_TITLE: str = "ClawAudit API"
        self.API_DESCRIPTION: str = "OpenClaw Security Intelligence Platform"


settings = BackendConfig()
