"""Generic webhook alert channel."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from sentinel.models.finding import Finding
    from sentinel.models.policy import PolicyDecision


class WebhookAlertChannel:
    """Sends alerts via a generic HTTP webhook."""

    def __init__(self, url: str, headers: dict[str, str] | None = None) -> None:
        self._url = url
        self._headers = headers or {}

    async def send_async(self, message: str, finding: "Finding", decision: "PolicyDecision") -> None:
        """Send alert to webhook endpoint."""
        payload = {
            "text": message,
            "finding_id": finding.id,
            "severity": finding.severity,
            "action": decision.action,
        }
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                await client.post(self._url, json=payload, headers=self._headers)
            except httpx.HTTPError:
                pass  # Non-fatal

    def send(self, message: str, finding: "Finding", decision: "PolicyDecision") -> None:
        """Synchronous wrapper."""
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(self.send_async(message, finding, decision))
        except RuntimeError:
            asyncio.run(self.send_async(message, finding, decision))
