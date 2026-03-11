"""PolicySyncService — bridges DB PolicyRecord rows into the runtime PolicyEngine."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

from sentinel.models.policy import Rule
from sentinel.policy.loader import PolicyLoader

if TYPE_CHECKING:
    from backend.models.policy import PolicyRecord


class PolicySyncService:
    """
    Bridges DB PolicyRecord rows into the runtime PolicyEngine.
    Singleton, initialized at app startup.
    """

    def __init__(self, db_session_factory, fallback_dir: Path | None = None) -> None:
        self._factory = db_session_factory
        self._fallback_dir = fallback_dir
        self._rules: list[Rule] = []
        self._lock = asyncio.Lock()

    async def reload(self) -> int:
        """Reload rules from DB. Returns rule count."""
        from backend.storage.repository import PolicyRepository

        async with self._lock:
            async with self._factory() as db:
                records = await PolicyRepository(db).list_enabled()
                self._rules = [self._record_to_rule(r) for r in records]

            # Fall back to YAML if DB is empty
            if not self._rules and self._fallback_dir:
                loader = PolicyLoader(self._fallback_dir)
                self._rules = loader.rules

            return len(self._rules)

    def get_rules(self) -> list[Rule]:
        """Return a snapshot of the current rules list."""
        return list(self._rules)

    def _record_to_rule(self, record: PolicyRecord) -> Rule:
        """Convert a PolicyRecord ORM row to a sentinel Rule dataclass."""
        return Rule(
            id=record.id,
            domain=record.domain,
            check=record.check,
            condition=record.condition,
            value=record.value,
            severity=record.severity,
            action=record.action,
            message=record.description or "",
            enabled=record.enabled,
            builtin=record.builtin,
            priority=record.priority,
        )


# Global singleton — initialized in backend/main.py lifespan
policy_sync: PolicySyncService | None = None
