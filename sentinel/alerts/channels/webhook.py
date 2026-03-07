"""Generic webhook alert channel."""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from sentinel.models.finding import Finding
    from sentinel.models.policy import PolicyDecision

# Module-level set to hold task references and prevent premature GC
_background_tasks: set = set()


class WebhookAlertChannel:
    """Sends alerts via a generic HTTP webhook."""

    def __init__(self, url: str, headers: dict[str, str] | None = None) -> None:
        self._url = url
        self._headers = headers or {}

    async def send_async(self, message: str, finding: Finding, decision: PolicyDecision) -> None:
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

    def send(self, message: str, finding: Finding, decision: PolicyDecision) -> None:
        """Synchronous wrapper — schedules delivery, holds task ref to prevent GC."""
        import asyncio

        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(self.send_async(message, finding, decision))
            _background_tasks.add(task)
            task.add_done_callback(_background_tasks.discard)
        except RuntimeError:
            asyncio.run(self.send_async(message, finding, decision))
