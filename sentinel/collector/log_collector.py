"""Log collector — tails OpenClaw log files for suspicious activity."""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Callable
from pathlib import Path

from sentinel.analyzer.secret_scanner import SecretScanner
from sentinel.config import SentinelConfig
from sentinel.models.event import Event

logger = logging.getLogger(__name__)

SUSPICIOUS_PATTERNS: list[tuple[str, str, str]] = [
    (r"rm\s+-rf\s+/", "rm -rf / detected", "CRITICAL"),
    (r"--yolo", "--yolo flag used", "HIGH"),
    (r"curl\s+.*\|\s*bash", "curl | bash detected", "HIGH"),
    (r"curl\s+.*\|\s*sh", "curl | sh detected", "HIGH"),
    (r"\beval\b.*\$", "eval with shell expansion", "HIGH"),
    (r"chmod\s+777", "chmod 777 detected", "MEDIUM"),
    (r"base64\s+--decode.*\|", "base64 decode pipe", "MEDIUM"),
    (r"nc\s+-[lLe]", "netcat listener", "HIGH"),
]

_COMPILED_SUSPICIOUS = [
    (re.compile(p, re.IGNORECASE), desc, sev) for p, desc, sev in SUSPICIOUS_PATTERNS
]


async def _tail_file(path: Path, callback: Callable[[str, Path], None]) -> None:
    """Tail a file, calling callback for each new line."""
    try:
        with path.open() as fh:
            fh.seek(0, 2)  # seek to end
            while True:
                line = fh.readline()
                if line:
                    callback(line.rstrip(), path)
                else:
                    await asyncio.sleep(0.5)
    except (OSError, PermissionError) as exc:
        logger.debug("Log tail error on %s: %s", path, exc)


class LogCollector:
    """Tails OpenClaw log files and scans for suspicious patterns."""

    def __init__(self, config: SentinelConfig, event_callback: Callable[[Event], None]) -> None:
        self._config = config
        self._emit = event_callback
        self._secret_scanner = SecretScanner()

    def _sanitize_for_evidence(self, line: str) -> str:
        """Redact any secret-like values from a log line before using as evidence."""
        return self._secret_scanner.sanitize_line(line[:200])

    def _handle_line(self, line: str, source_path: Path) -> None:
        """Process a single log line."""
        # Check for suspicious commands
        safe_evidence = self._sanitize_for_evidence(line)
        for pattern, description, severity in _COMPILED_SUSPICIOUS:
            if pattern.search(line):
                self._emit(
                    Event(
                        source="log_collector",
                        event_type="suspicious_command",
                        severity=severity,
                        entity=str(source_path),
                        evidence=description + " — " + safe_evidence,
                        action_taken="ALERT",
                    )
                )

        # Check for secrets in logs
        matches = self._secret_scanner.scan_text(line, str(source_path))
        for m in matches:
            self._emit(
                Event(
                    source="log_collector",
                    event_type="secret_in_log",
                    severity="CRITICAL",
                    entity=str(source_path),
                    evidence=f"secret_type={m.secret_type} context={m.context[:80]}",
                    action_taken="ALERT",
                )
            )

    async def run(self) -> None:
        """Start tailing all log files in the log directory."""
        log_dir = self._config.log_dir
        log_dir.mkdir(parents=True, exist_ok=True)

        tasks: list[asyncio.Task] = []
        while True:
            # Prune completed tasks to prevent unbounded list growth
            tasks = [t for t in tasks if not t.done()]

            # Discover new log files
            current_files = set(log_dir.glob("*.log")) | set(log_dir.glob("*.jsonl"))
            for f in current_files:
                if not any(t.get_name() == str(f) for t in tasks):
                    task = asyncio.create_task(
                        _tail_file(f, self._handle_line),
                        name=str(f),
                    )
                    tasks.append(task)

            await asyncio.sleep(10)
