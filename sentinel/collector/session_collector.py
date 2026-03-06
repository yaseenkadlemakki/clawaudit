"""Session collector — monitors session JSONL for runaway agent patterns."""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

from sentinel.config import SentinelConfig
from sentinel.models.event import Event

logger = logging.getLogger(__name__)

TOOL_CALL_LIMIT_PER_MINUTE = 30


class SessionCollector:
    """Scans session JSONL files for tool call rate anomalies."""

    def __init__(self, config: SentinelConfig, event_callback: Callable[[Event], None]) -> None:
        self._config = config
        self._emit = event_callback
        self._alerted_sessions: set[str] = set()

    def _analyze_session_file(self, path: Path) -> None:
        """Check tool call rate in a session file."""
        try:
            lines = path.read_text(errors="replace").splitlines()
        except (OSError, PermissionError):
            return

        tool_calls: list[datetime] = []
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Look for tool_use messages
            if record.get("type") == "tool_use" or record.get("role") == "tool":
                ts_str = record.get("ts") or record.get("timestamp") or record.get("created_at")
                if ts_str:
                    try:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        tool_calls.append(ts)
                    except (ValueError, AttributeError):
                        pass

        if len(tool_calls) < 2:
            return

        # Check calls per minute in any 60-second window
        tool_calls.sort()
        for i, call_time in enumerate(tool_calls):
            window_end = call_time + timedelta(seconds=60)
            count = sum(1 for t in tool_calls[i:] if t <= window_end)
            if count > TOOL_CALL_LIMIT_PER_MINUTE:
                session_id = path.stem
                if session_id not in self._alerted_sessions:
                    self._alerted_sessions.add(session_id)
                    self._emit(Event(
                        source="session_collector",
                        event_type="runaway_agent",
                        severity="HIGH",
                        entity=session_id,
                        evidence=f"tool_calls_per_minute={count} threshold={TOOL_CALL_LIMIT_PER_MINUTE}",
                        action_taken="ALERT",
                        policy_refs=["POL-007"],
                    ))
                break

    async def run(self) -> None:
        """Periodically scan session files."""
        while True:
            sessions_dir = self._config.sessions_dir
            if sessions_dir.exists():
                for session_file in sessions_dir.glob("*.jsonl"):
                    try:
                        self._analyze_session_file(session_file)
                    except Exception as exc:
                        logger.debug("Session analysis error: %s", exc)
            await asyncio.sleep(self._config.scan_interval)
