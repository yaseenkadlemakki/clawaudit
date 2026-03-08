"""OpenClaw plugin manifest handler for ClawAudit."""

from __future__ import annotations

import json
import logging
import os
import secrets
from pathlib import Path

logger = logging.getLogger(__name__)

_SECRET_FILE = Path.home() / ".openclaw" / "sentinel" / "hook-secret"


def _get_or_create_secret() -> str:
    """Read or generate the HMAC secret for hook validation."""
    if _SECRET_FILE.exists():
        stored = _SECRET_FILE.read_text().strip()
        if stored:
            return stored
    _SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_hex(32)
    fd = os.open(str(_SECRET_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(secret)
    except Exception:
        os.close(fd)
        raise
    return secret


class ClawAuditPlugin:
    """Registers ClawAudit as an OpenClaw plugin.

    Writes plugin manifest to ~/.openclaw/plugins/clawaudit.json
    that OpenClaw can discover and call our hook handlers.
    """

    MANIFEST_PATH = Path.home() / ".openclaw" / "plugins" / "clawaudit.json"

    def __init__(self, manifest_path: Path | None = None) -> None:
        if manifest_path is not None:
            self.manifest_path = manifest_path
        else:
            self.manifest_path = self.MANIFEST_PATH

    def register(self) -> Path:
        """Write the plugin manifest. Returns the manifest path."""
        secret = _get_or_create_secret()
        manifest = {
            "name": "clawaudit",
            "version": "0.1.0",
            "hooks": ["before_tool_call", "after_tool_call"],
            "endpoint": "http://localhost:18790/api/v1/hooks/tool-event",
            "secret": secret,
            "enabled": True,
        }
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.manifest_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(json.dumps(manifest, indent=2))
        except Exception:
            os.close(fd)
            raise
        logger.info("ClawAudit plugin registered at %s", self.manifest_path)
        return self.manifest_path

    def unregister(self) -> None:
        """Remove the plugin manifest."""
        if self.manifest_path.exists():
            self.manifest_path.unlink()
            logger.info("ClawAudit plugin unregistered (removed %s)", self.manifest_path)

    def is_registered(self) -> bool:
        """Check if the plugin manifest exists and is enabled."""
        if not self.manifest_path.exists():
            return False
        try:
            data = json.loads(self.manifest_path.read_text())
            return data.get("enabled", False)
        except (json.JSONDecodeError, OSError):
            return False

    def read_manifest(self) -> dict | None:
        """Read and return the manifest contents, or None if not found."""
        if not self.manifest_path.exists():
            return None
        try:
            return json.loads(self.manifest_path.read_text())
        except (json.JSONDecodeError, OSError):
            return None
