"""Skill collector — watches skill directories for changes."""
from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEvent, FileCreatedEvent, FileModifiedEvent, FileDeletedEvent
from watchdog.observers import Observer

from sentinel.config import SentinelConfig
from sentinel.models.event import Event
from sentinel.analyzer.skill_analyzer import SkillAnalyzer

logger = logging.getLogger(__name__)


class _SkillHandler:
    """Watchdog event handler for SKILL.md files."""

    def __init__(self, emit: Callable[[Event], None]) -> None:
        self._emit = emit
        self._analyzer = SkillAnalyzer()

    def dispatch(self, event: FileSystemEvent) -> None:
        """Handle watchdog events."""
        if not isinstance(event, (FileCreatedEvent, FileModifiedEvent, FileDeletedEvent)):
            return
        path = Path(event.src_path)
        if path.name != "SKILL.md":
            return

        if isinstance(event, FileCreatedEvent):
            event_type = "new_skill"
            severity = "MEDIUM"
        elif isinstance(event, FileModifiedEvent):
            event_type = "modified_skill"
            severity = "LOW"
        else:
            event_type = "deleted_skill"
            severity = "INFO"

        skill_name = path.parent.name
        evidence = f"path={path}"

        if event_type in ("new_skill", "modified_skill") and path.exists():
            try:
                profile = self._analyzer.analyze(path, str(uuid.uuid4()))
                evidence = f"path={path} trust_score={profile.trust_score} injection_risk={profile.injection_risk}"
                if profile.trust_score in ("QUARANTINE", "UNTRUSTED"):
                    severity = "HIGH"
            except Exception as exc:
                logger.warning("Skill analysis error: %s", exc)

        self._emit(Event(
            source="skill_collector",
            event_type=event_type,
            severity=severity,
            entity=skill_name,
            evidence=evidence,
            action_taken="ALERT" if severity in ("HIGH", "CRITICAL") else "WARN",
        ))


class SkillCollector:
    """Watches skill directories for SKILL.md changes using watchdog."""

    def __init__(self, config: SentinelConfig, event_callback: Callable[[Event], None]) -> None:
        self._config = config
        self._emit = event_callback
        self._observer: Observer | None = None

    def start(self) -> None:
        """Start watching skill directories."""
        handler = _SkillHandler(self._emit)
        self._observer = Observer()

        for path in [self._config.skills_dir, self._config.workspace_skills_dir]:
            if path.exists():
                self._observer.schedule(handler, str(path), recursive=True)  # type: ignore[arg-type]
                logger.info("Watching skill directory: %s", path)

        self._observer.start()

    def stop(self) -> None:
        """Stop watching."""
        if self._observer:
            self._observer.stop()
            self._observer.join()
