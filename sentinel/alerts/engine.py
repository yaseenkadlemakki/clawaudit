"""Alert routing and deduplication engine."""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING

from sentinel.alerts.formatters import format_finding_alert
from sentinel.alerts.channels.file import FileAlertChannel
from sentinel.alerts.channels.openclaw import OpenClawAlertChannel
from sentinel.config import SentinelConfig

if TYPE_CHECKING:
    from sentinel.models.finding import Finding
    from sentinel.models.policy import PolicyDecision

logger = logging.getLogger(__name__)


class AlertEngine:
    """Routes alerts to configured channels with deduplication."""

    def __init__(self, config: SentinelConfig) -> None:
        self._config = config
        self._dedup: dict[str, float] = {}  # finding_id → last sent timestamp
        self._channels: list = []
        self._setup_channels()

    def _setup_channels(self) -> None:
        """Initialize alert delivery channels from config."""
        channels_cfg = self._config.alert_channels
        dedup_window = self._config.dedup_window

        # File channel
        file_cfg = channels_cfg.get("file", {})
        if file_cfg.get("enabled", True):
            path = Path(file_cfg.get("path", "~/.openclaw/sentinel/alerts.jsonl")).expanduser()
            self._channels.append(FileAlertChannel(path))

        # OpenClaw gateway channel
        oc_cfg = channels_cfg.get("openclaw", {})
        if oc_cfg.get("enabled", False) and self._config.gateway_token:
            self._channels.append(OpenClawAlertChannel(
                gateway_url=self._config.gateway_url,
                gateway_token=self._config.gateway_token,
                delivery_channel=oc_cfg.get("delivery_channel", "discord"),
                delivery_target=oc_cfg.get("delivery_target", ""),
            ))

    def _dedup_key(self, finding: "Finding") -> str:
        """Return a stable deduplication key for a finding (check_id + location)."""
        return f"{finding.check_id}:{finding.location}"

    def _is_deduplicated(self, finding: "Finding") -> bool:
        """Return True if this finding was recently alerted (within dedup window)."""
        last_sent = self._dedup.get(self._dedup_key(finding))
        if last_sent and (time.time() - last_sent) < self._config.dedup_window:
            return True
        return False

    def send(self, finding: "Finding", decision: "PolicyDecision") -> None:
        """Route a finding alert to all configured channels."""
        if not self._config.alerts_enabled:
            return
        if decision.action not in ("ALERT", "BLOCK", "WARN"):
            return
        if self._is_deduplicated(finding):
            logger.debug("Deduplicating alert for finding %s", finding.id)
            return

        message = format_finding_alert(finding, decision)
        self._dedup[self._dedup_key(finding)] = time.time()

        for channel in self._channels:
            try:
                channel.send(message, finding, decision)
            except Exception as exc:
                logger.warning("Alert channel error: %s", exc)

    def clear_dedup(self) -> None:
        """Clear the dedup cache."""
        self._dedup.clear()
