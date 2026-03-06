"""OpenClaw gateway alert channel."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from sentinel.models.finding import Finding
    from sentinel.models.policy import PolicyDecision

logger = logging.getLogger(__name__)


class OpenClawAlertChannel:
    """Delivers alerts via the OpenClaw gateway message API."""

    def __init__(
        self,
        gateway_url: str,
        gateway_token: str,
        delivery_channel: str,
        delivery_target: str,
    ) -> None:
        self._gateway_url = gateway_url.rstrip("/")
        self._token = gateway_token
        self._channel = delivery_channel
        self._target = delivery_target

    async def send_async(self, message: str, finding: "Finding", decision: "PolicyDecision") -> None:
        """Send alert via OpenClaw gateway."""
        headers = {"Authorization": f"Bearer {self._token}"}
        payload = {
            "channel": self._channel,
            "to": self._target,
            "message": message,
        }
        async with httpx.AsyncClient(timeout=15) as client:
            try:
                resp = await client.post(
                    f"{self._gateway_url}/api/message/send",
                    headers=headers,
                    json=payload,
                )
                resp.raise_for_status()
                logger.debug("Alert sent via OpenClaw gateway: %s", finding.id)
            except httpx.HTTPError as exc:
                logger.warning("Failed to send alert via gateway: %s", exc)

    def send(self, message: str, finding: "Finding", decision: "PolicyDecision") -> None:
        """Synchronous wrapper."""
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.send_async(message, finding, decision))
        except RuntimeError:
            asyncio.run(self.send_async(message, finding, decision))
