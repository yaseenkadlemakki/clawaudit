"""Cron collector — detects unauthorized cron job registrations."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Callable

import httpx

from sentinel.config import SentinelConfig
from sentinel.models.event import Event

logger = logging.getLogger(__name__)


class CronCollector:
    """Monitors the OpenClaw cron registry for unauthorized entries."""

    def __init__(self, config: SentinelConfig, event_callback: Callable[[Event], None]) -> None:
        self._config = config
        self._emit = event_callback
        self._baseline_crons: set[str] | None = None

    async def _fetch_crons(self) -> list[dict] | None:
        """Fetch current cron list from gateway."""
        headers = {"Authorization": f"Bearer {self._config.gateway_token}"}
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{self._config.gateway_url}/crons",
                    headers=headers,
                )
                resp.raise_for_status()
                return resp.json().get("crons", [])
        except (httpx.HTTPError, json.JSONDecodeError, KeyError) as exc:
            logger.debug("Cron fetch failed: %s", exc)
            return None

    async def collect_once(self) -> None:
        """Run one collection cycle."""
        crons = await self._fetch_crons()
        if crons is None:
            return

        cron_ids = {c.get("id") or c.get("name", str(i)) for i, c in enumerate(crons)}

        if self._baseline_crons is None:
            self._baseline_crons = cron_ids
            logger.info("Cron baseline established: %d entries", len(cron_ids))
            return

        new_crons = cron_ids - self._baseline_crons
        for cron_id in new_crons:
            self._emit(Event(
                source="cron_collector",
                event_type="unauthorized_cron",
                severity="HIGH",
                entity=cron_id,
                evidence=f"new_cron_id={cron_id}",
                action_taken="ALERT",
                policy_refs=["POL-008"],
            ))

        self._baseline_crons = cron_ids

    async def run(self) -> None:
        """Run continuous collection loop."""
        while True:
            try:
                await self.collect_once()
            except Exception as exc:
                logger.error("Cron collector error: %s", exc)
            await asyncio.sleep(self._config.scan_interval)
