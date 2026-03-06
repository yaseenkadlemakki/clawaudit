"""Config collector — polls gateway config and detects drift."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Callable

import httpx

from sentinel.config import SentinelConfig
from sentinel.models.event import Event
from sentinel.analyzer.config_auditor import ConfigAuditor
from sentinel.analyzer.secret_scanner import SecretScanner

logger = logging.getLogger(__name__)


def _sanitize_config(config: dict) -> dict:
    """Remove sensitive values from config before logging."""
    import re
    text = json.dumps(config)
    # Redact token-like values
    text = re.sub(r'"token"\s*:\s*"[^"]{8,}"', '"token": "[REDACTED]"', text)
    text = re.sub(r'"password"\s*:\s*"[^"]{4,}"', '"password": "[REDACTED]"', text)
    text = re.sub(r'"secret"\s*:\s*"[^"]{4,}"', '"secret": "[REDACTED]"', text)
    return json.loads(text)


def _hash_config(config: dict) -> str:
    """Return SHA256 hash of canonical config JSON."""
    canonical = json.dumps(config, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


class ConfigCollector:
    """Periodically polls the OpenClaw gateway config and detects drift."""

    def __init__(
        self,
        config: SentinelConfig,
        event_callback: Callable[[Event], None],
    ) -> None:
        self._config = config
        self._emit = event_callback
        self._auditor = ConfigAuditor()
        self._last_hash: str | None = None
        self._last_config: dict | None = None

    async def _fetch_config(self) -> dict[str, Any] | None:
        """Fetch config from gateway."""
        headers = {"Authorization": f"Bearer {self._config.gateway_token}"}
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{self._config.gateway_url}/config",
                    headers=headers,
                )
                resp.raise_for_status()
                return resp.json()
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            logger.debug("Config fetch failed: %s", exc)
            # Fall back to reading local config file
            try:
                return json.loads(self._config.config_file.read_text())
            except (OSError, json.JSONDecodeError):
                return None

    async def collect_once(self) -> None:
        """Run one collection cycle."""
        config = await self._fetch_config()
        if config is None:
            return

        current_hash = _hash_config(config)

        if self._last_hash is not None and current_hash != self._last_hash:
            sanitized = _sanitize_config(config)
            self._emit(Event(
                source="config_collector",
                event_type="config_drift",
                severity="HIGH",
                entity="openclaw.json",
                evidence=f"config_hash_changed={current_hash[:16]}",
                action_taken="ALERT",
                policy_refs=["POL-010"],
            ))
            logger.warning("Config drift detected: hash %s → %s", self._last_hash[:8], current_hash[:8])

        self._last_hash = current_hash
        self._last_config = config

        # Run auditor checks
        run_id = str(uuid.uuid4())
        findings = self._auditor.audit(config, run_id)
        for finding in findings:
            if finding.result == "FAIL":
                self._emit(Event(
                    source="config_collector",
                    event_type="config_audit_fail",
                    severity=finding.severity,
                    entity=finding.location,
                    evidence=f"check_id={finding.check_id} {finding.evidence}",
                    action_taken="ALERT",
                    policy_refs=[finding.check_id],
                ))

    async def run(self) -> None:
        """Run continuous collection loop."""
        while True:
            try:
                await self.collect_once()
            except Exception as exc:
                logger.error("Config collector error: %s", exc)
            await asyncio.sleep(self._config.scan_interval)
