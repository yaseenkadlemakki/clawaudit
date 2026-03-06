"""Backend configuration for ClawAudit API server."""
from __future__ import annotations

import os
from pathlib import Path


class BackendConfig:
    """Configuration for the FastAPI backend service."""

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        f"sqlite+aiosqlite:///{Path.home()}/.openclaw/sentinel/clawaudit.db",
    )

    # Server
    HOST: str = os.getenv("CLAWAUDIT_HOST", "127.0.0.1")
    PORT: int = int(os.getenv("CLAWAUDIT_PORT", "18790"))
    LOG_LEVEL: str = os.getenv("CLAWAUDIT_LOG_LEVEL", "info")

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    # API
    API_VERSION: str = "2.0.0"
    API_TITLE: str = "ClawAudit API"
    API_DESCRIPTION: str = "OpenClaw Security Intelligence Platform"


settings = BackendConfig()
