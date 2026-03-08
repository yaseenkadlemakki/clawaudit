"""In-process async event bus for runtime hook events."""

from __future__ import annotations

import asyncio
import logging
import threading
import uuid
from collections.abc import Callable
from datetime import datetime, timezone  # noqa: UP017
from typing import Any

from sentinel.hooks.event import ToolEvent, sanitize_params
from sentinel.hooks.rules import evaluate_rules

logger = logging.getLogger(__name__)

# Type alias for async callback
AsyncCallback = Callable[[ToolEvent], Any]


class HookBus:
    """Singleton in-process event bus. Thread-safe.

    Subscribers receive ToolEvent objects via async callbacks.
    The bus evaluates alert rules on each event before dispatching.
    """

    _instance: HookBus | None = None
    _lock = threading.Lock()

    def __new__(cls) -> HookBus:
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._subscribers = []
                cls._instance._recent_events: list[ToolEvent] = []
                cls._instance._max_recent = 200
                cls._instance._async_lock = asyncio.Lock()
            return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset singleton — for testing only."""
        with cls._lock:
            cls._instance = None

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    def subscribe(self, callback: AsyncCallback) -> None:
        """Register an async callback to receive ToolEvents."""
        self._subscribers.append(callback)

    def unsubscribe(self, callback: AsyncCallback) -> None:
        """Remove a previously registered callback."""
        try:
            self._subscribers.remove(callback)
        except ValueError:
            pass

    async def publish(self, event: ToolEvent) -> None:
        """Evaluate rules and dispatch event to all subscribers."""
        async with self._async_lock:
            # Run alert rules
            reasons = evaluate_rules(event, self._recent_events)
            if reasons:
                event.alert_triggered = True
                event.alert_reasons = reasons

            # Track recent events for frequency detection
            self._recent_events.append(event)
            if len(self._recent_events) > self._max_recent:
                self._recent_events = self._recent_events[-self._max_recent :]

        # Fan out to subscribers
        for cb in self._subscribers:
            try:
                result = cb(event)
                if asyncio.iscoroutine(result) or asyncio.isfuture(result):
                    await result
            except Exception:
                logger.exception("Hook subscriber error")

    async def before_tool_call(
        self,
        tool_name: str,
        params: dict[str, Any],
        context: dict[str, Any],
    ) -> ToolEvent:
        """OpenClaw plugin hook: called before a tool executes.

        Creates a ToolEvent with outcome='pending' and publishes it.
        Returns the event so after_tool_call can update it.
        """
        event = ToolEvent(
            id=str(uuid.uuid4()),
            session_id=context.get("session_id", ""),
            skill_name=context.get("skill_name"),
            tool_name=tool_name,
            params_summary=sanitize_params(str(params)),
            timestamp=datetime.now(timezone.utc),  # noqa: UP017
            outcome="pending",
        )
        await self.publish(event)
        return event

    async def after_tool_call(
        self,
        tool_name: str,
        params: dict[str, Any],
        result: Any,
        context: dict[str, Any],
        duration_ms: int,
        event: ToolEvent | None = None,
    ) -> ToolEvent:
        """OpenClaw plugin hook: called after a tool finishes.

        Updates the event with duration and outcome, then re-publishes.
        """
        if event is None:
            event = ToolEvent(
                id=str(uuid.uuid4()),
                session_id=context.get("session_id", ""),
                skill_name=context.get("skill_name"),
                tool_name=tool_name,
                params_summary=sanitize_params(str(params)),
                timestamp=datetime.now(timezone.utc),  # noqa: UP017
            )

        event.duration_ms = duration_ms
        event.outcome = "error" if isinstance(result, Exception) else "success"
        await self.publish(event)
        return event
