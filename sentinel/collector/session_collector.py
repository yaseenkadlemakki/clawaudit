"""Session collector — monitors session JSONL for runaway agent patterns."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

from sentinel.config import SentinelConfig
from sentinel.guard.command_guard import classify_command, detect_shell_errors
from sentinel.models.event import Event

logger = logging.getLogger(__name__)

TOOL_CALL_LIMIT_PER_MINUTE = 30


class SessionCollector:
    """Scans session JSONL files for tool call rate anomalies and code-block mis-execution."""

    def __init__(self, config: SentinelConfig, event_callback: Callable[[Event], None]) -> None:
        self._config = config
        self._emit = event_callback
        self._alerted_sessions: set[str] = set()
        self._code_block_alerted: set[str] = set()

    # ------------------------------------------------------------------
    # Code-block-as-command detection (issue #39233)
    # ------------------------------------------------------------------

    def _check_tool_use_for_code_block(self, record: dict, session_id: str) -> None:
        """Detect when a tool_use record executes code-block content as a shell command.

        Heuristic: if the ``input`` (or ``command``) field of a Bash/shell tool
        call contains syntax tokens from a non-shell language (Python, TS, etc.),
        the agent likely confused "write this file" with "run this command".
        """
        # Only inspect shell-execution tool calls
        tool_name = record.get("name") or record.get("tool_name") or record.get("tool") or ""
        if tool_name.lower() not in ("bash", "shell", "terminal", "execute", "run", ""):
            return

        # Extract the command text
        input_val = record.get("input") or record.get("command") or ""
        if isinstance(input_val, dict):
            input_val = input_val.get("command") or input_val.get("input") or ""
        if not isinstance(input_val, str) or len(input_val) < 20:
            return

        verdict = classify_command(input_val)
        if not verdict.is_code_block:
            return

        dedup_key = f"{session_id}:{verdict.detected_language}:{hash(input_val[:200])}"
        if dedup_key in self._code_block_alerted:
            return
        self._code_block_alerted.add(dedup_key)

        self._emit(
            Event(
                source="session_collector",
                event_type="code_block_as_command",
                severity="HIGH",
                entity=session_id,
                evidence=(
                    f"language={verdict.detected_language} "
                    f"confidence={verdict.confidence} "
                    f"tokens={','.join(verdict.matched_tokens[:5])} "
                    f"suggested_action={verdict.suggested_action}"
                ),
                action_taken="ALERT",
                policy_refs=["POL-011"],
            )
        )

    def _check_output_for_shell_errors(self, record: dict, session_id: str) -> None:
        """Detect shell error output that indicates non-shell code was executed."""
        output = record.get("output") or record.get("content") or ""
        if isinstance(output, list):
            output = "\n".join(item.get("text", "") for item in output if isinstance(item, dict))
        if not isinstance(output, str) or len(output) < 10:
            return

        errors = detect_shell_errors(output)
        if len(errors) < 2:
            return

        dedup_key = f"{session_id}:shell_errors:{hash(output[:200])}"
        if dedup_key in self._code_block_alerted:
            return
        self._code_block_alerted.add(dedup_key)

        self._emit(
            Event(
                source="session_collector",
                event_type="code_block_as_command",
                severity="HIGH",
                entity=session_id,
                evidence=(f"shell_errors={len(errors)} sample={errors[0][:120]}"),
                action_taken="ALERT",
                policy_refs=["POL-011"],
            )
        )

    # ------------------------------------------------------------------
    # Runaway agent detection
    # ------------------------------------------------------------------

    def _analyze_session_file(self, path: Path) -> None:
        """Check tool call rate and code-block misuse in a session file."""
        try:
            lines = path.read_text(errors="replace").splitlines()
        except (OSError, PermissionError):
            return

        session_id = path.stem
        tool_calls: list[datetime] = []
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            is_tool_use = record.get("type") == "tool_use" or record.get("role") == "tool"

            if is_tool_use:
                ts_str = record.get("ts") or record.get("timestamp") or record.get("created_at")
                if ts_str:
                    try:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        tool_calls.append(ts)
                    except (ValueError, AttributeError):
                        pass

                # Code-block-as-command check on tool_use records
                self._check_tool_use_for_code_block(record, session_id)

            # Check tool result output for shell error signatures
            if record.get("type") == "tool_result" or record.get("role") == "tool":
                self._check_output_for_shell_errors(record, session_id)

        if len(tool_calls) < 2:
            return

        # Check calls per minute in any 60-second window
        tool_calls.sort()
        for i, call_time in enumerate(tool_calls):
            window_end = call_time + timedelta(seconds=60)
            count = sum(1 for t in tool_calls[i:] if t <= window_end)
            if count > TOOL_CALL_LIMIT_PER_MINUTE:
                if session_id not in self._alerted_sessions:
                    self._alerted_sessions.add(session_id)
                    self._emit(
                        Event(
                            source="session_collector",
                            event_type="runaway_agent",
                            severity="HIGH",
                            entity=session_id,
                            evidence=f"tool_calls_per_minute={count} threshold={TOOL_CALL_LIMIT_PER_MINUTE}",
                            action_taken="ALERT",
                            policy_refs=["POL-007"],
                        )
                    )
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
