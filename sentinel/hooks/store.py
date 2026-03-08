"""SQLite-backed event store for ToolEvents.

Uses a separate DB file (tool-events.db) for isolation from the main app DB.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone  # noqa: UP017
from pathlib import Path

import aiosqlite

from sentinel.hooks.event import ToolEvent

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path.home() / ".openclaw" / "sentinel" / "tool-events.db"

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS tool_events (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    skill_name TEXT,
    tool_name TEXT NOT NULL,
    params_summary TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL,
    duration_ms INTEGER,
    outcome TEXT NOT NULL DEFAULT 'pending',
    alert_triggered INTEGER NOT NULL DEFAULT 0,
    alert_reasons TEXT NOT NULL DEFAULT '[]'
);
"""

_CREATE_INDEXES_SQL = [
    "CREATE INDEX IF NOT EXISTS ix_tool_events_session_id ON tool_events(session_id);",
    "CREATE INDEX IF NOT EXISTS ix_tool_events_skill_name ON tool_events(skill_name);",
    "CREATE INDEX IF NOT EXISTS ix_tool_events_alert ON tool_events(alert_triggered);",
]

_RETENTION_DAYS = 30


class EventStore:
    """Persist ToolEvents to SQLite. Separate from main clawaudit.db for isolation."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or _DEFAULT_DB_PATH
        self._initialized = False

    async def _ensure_db(self) -> None:
        """Create database and tables if they don't exist."""
        if self._initialized:
            return
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.db_path.exists():
            fd = os.open(str(self.db_path), os.O_WRONLY | os.O_CREAT, 0o600)
            os.close(fd)
        async with aiosqlite.connect(str(self.db_path)) as db:
            await db.execute("PRAGMA journal_mode=WAL")
            await db.execute(_CREATE_TABLE_SQL)
            for idx_sql in _CREATE_INDEXES_SQL:
                await db.execute(idx_sql)
            await db.commit()
        self._initialized = True

    async def _cleanup_old_events(self, db: aiosqlite.Connection) -> None:
        """Delete events older than the retention period."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=_RETENTION_DAYS)  # noqa: UP017
        ).isoformat()
        await db.execute("DELETE FROM tool_events WHERE timestamp < ?", (cutoff,))

    async def save(self, event: ToolEvent) -> None:
        """Persist a ToolEvent to the database."""
        await self._ensure_db()
        async with aiosqlite.connect(str(self.db_path)) as db:
            await db.execute(
                """INSERT OR REPLACE INTO tool_events
                   (id, session_id, skill_name, tool_name, params_summary,
                    timestamp, duration_ms, outcome, alert_triggered, alert_reasons)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.id,
                    event.session_id,
                    event.skill_name,
                    event.tool_name,
                    event.params_summary,
                    event.timestamp.isoformat(),
                    event.duration_ms,
                    event.outcome,
                    int(event.alert_triggered),
                    json.dumps(event.alert_reasons),
                ),
            )
            await self._cleanup_old_events(db)
            await db.commit()

    async def list(
        self,
        session_id: str | None = None,
        skill_name: str | None = None,
        limit: int = 100,
        alerts_only: bool = False,
    ) -> list[ToolEvent]:
        """Query stored events with optional filters."""
        await self._ensure_db()
        conditions: list[str] = []
        params: list[object] = []

        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)
        if skill_name:
            conditions.append("skill_name = ?")
            params.append(skill_name)
        if alerts_only:
            conditions.append("alert_triggered = 1")

        where = ""
        if conditions:
            where = "WHERE " + " AND ".join(conditions)

        sql = f"SELECT * FROM tool_events {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        async with aiosqlite.connect(str(self.db_path)) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(sql, params) as cursor:
                rows = await cursor.fetchall()

        return [self._row_to_event(row) for row in rows]

    async def get(self, event_id: str) -> ToolEvent | None:
        """Retrieve a single event by ID."""
        await self._ensure_db()
        async with aiosqlite.connect(str(self.db_path)) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM tool_events WHERE id = ?", (event_id,)) as cursor:
                row = await cursor.fetchone()
        if row is None:
            return None
        return self._row_to_event(row)

    async def stats(self) -> dict:
        """Aggregate stats: total, alerts, by_tool, by_skill."""
        await self._ensure_db()
        async with aiosqlite.connect(str(self.db_path)) as db:
            # Total events
            async with db.execute("SELECT COUNT(*) FROM tool_events") as cur:
                total = (await cur.fetchone())[0]

            # Total alerts
            async with db.execute(
                "SELECT COUNT(*) FROM tool_events WHERE alert_triggered = 1"
            ) as cur:
                total_alerts = (await cur.fetchone())[0]

            # By tool
            by_tool: dict[str, int] = {}
            async with db.execute(
                "SELECT tool_name, COUNT(*) as cnt FROM tool_events GROUP BY tool_name ORDER BY cnt DESC"
            ) as cur:
                async for row in cur:
                    by_tool[row[0]] = row[1]

            # By skill
            by_skill: dict[str, int] = {}
            async with db.execute(
                "SELECT skill_name, COUNT(*) as cnt FROM tool_events WHERE skill_name IS NOT NULL GROUP BY skill_name ORDER BY cnt DESC"
            ) as cur:
                async for row in cur:
                    by_skill[row[0]] = row[1]

        return {
            "total_events": total,
            "total_alerts": total_alerts,
            "events_by_tool": by_tool,
            "events_by_skill": by_skill,
        }

    @staticmethod
    def _row_to_event(row: aiosqlite.Row) -> ToolEvent:
        """Convert a database row to a ToolEvent."""
        return ToolEvent.from_dict(
            {
                "id": row["id"],
                "session_id": row["session_id"],
                "skill_name": row["skill_name"],
                "tool_name": row["tool_name"],
                "params_summary": row["params_summary"],
                "timestamp": row["timestamp"],
                "duration_ms": row["duration_ms"],
                "outcome": row["outcome"],
                "alert_triggered": bool(row["alert_triggered"]),
                "alert_reasons": row["alert_reasons"],
            }
        )
