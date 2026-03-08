"""Tests for sentinel.hooks.store — EventStore SQLite persistence."""

from __future__ import annotations

import os
import stat
from datetime import datetime, timedelta, timezone  # noqa: UP017
from pathlib import Path

import aiosqlite
import pytest

from sentinel.hooks.event import ToolEvent
from sentinel.hooks.store import EventStore


@pytest.fixture
def store(tmp_path: Path) -> EventStore:
    return EventStore(db_path=tmp_path / "test-events.db")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_save_and_get(store: EventStore):
    event = ToolEvent(session_id="s1", tool_name="exec", outcome="success")
    await store.save(event)

    retrieved = await store.get(event.id)
    assert retrieved is not None
    assert retrieved.id == event.id
    assert retrieved.tool_name == "exec"
    assert retrieved.outcome == "success"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_not_found(store: EventStore):
    result = await store.get("nonexistent")
    assert result is None


@pytest.mark.unit
@pytest.mark.asyncio
async def test_list_all(store: EventStore):
    for i in range(5):
        await store.save(ToolEvent(session_id="s1", tool_name=f"tool-{i}"))

    events = await store.list()
    assert len(events) == 5


@pytest.mark.unit
@pytest.mark.asyncio
async def test_list_by_session(store: EventStore):
    await store.save(ToolEvent(session_id="s1", tool_name="exec"))
    await store.save(ToolEvent(session_id="s2", tool_name="read"))

    events = await store.list(session_id="s1")
    assert len(events) == 1
    assert events[0].session_id == "s1"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_list_by_skill(store: EventStore):
    await store.save(ToolEvent(session_id="s1", skill_name="alpha", tool_name="exec"))
    await store.save(ToolEvent(session_id="s1", skill_name="beta", tool_name="read"))

    events = await store.list(skill_name="alpha")
    assert len(events) == 1
    assert events[0].skill_name == "alpha"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_list_alerts_only(store: EventStore):
    normal = ToolEvent(session_id="s1", tool_name="read")
    alerted = ToolEvent(
        session_id="s1",
        tool_name="exec",
        alert_triggered=True,
        alert_reasons=["pty detected"],
    )
    await store.save(normal)
    await store.save(alerted)

    events = await store.list(alerts_only=True)
    assert len(events) == 1
    assert events[0].alert_triggered is True


@pytest.mark.unit
@pytest.mark.asyncio
async def test_list_with_limit(store: EventStore):
    for i in range(10):
        await store.save(ToolEvent(session_id="s1", tool_name=f"tool-{i}"))

    events = await store.list(limit=3)
    assert len(events) == 3


@pytest.mark.unit
@pytest.mark.asyncio
async def test_stats(store: EventStore):
    await store.save(ToolEvent(session_id="s1", skill_name="sk1", tool_name="exec"))
    await store.save(
        ToolEvent(
            session_id="s1",
            skill_name="sk2",
            tool_name="read",
            alert_triggered=True,
            alert_reasons=["test"],
        )
    )
    await store.save(ToolEvent(session_id="s1", tool_name="exec"))

    stats = await store.stats()
    assert stats["total_events"] == 3
    assert stats["total_alerts"] == 1
    assert stats["events_by_tool"]["exec"] == 2
    assert stats["events_by_tool"]["read"] == 1
    assert stats["events_by_skill"]["sk1"] == 1
    assert stats["events_by_skill"]["sk2"] == 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_save_upsert(store: EventStore):
    event = ToolEvent(session_id="s1", tool_name="exec", outcome="pending")
    await store.save(event)

    event.outcome = "success"
    event.duration_ms = 100
    await store.save(event)

    retrieved = await store.get(event.id)
    assert retrieved is not None
    assert retrieved.outcome == "success"
    assert retrieved.duration_ms == 100

    all_events = await store.list()
    assert len(all_events) == 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_store_db_file_permissions_0o600(tmp_path: Path):
    """tool-events.db must be created with 0o600 permissions."""
    db_path = tmp_path / "tool-events.db"
    store = EventStore(db_path=db_path)
    await store.save(ToolEvent(session_id="s1", tool_name="exec"))

    mode = stat.S_IMODE(os.stat(db_path).st_mode)
    assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_store_wal_mode_enabled(tmp_path: Path):
    """DB must open in WAL journal mode."""
    db_path = tmp_path / "wal-test.db"
    store = EventStore(db_path=db_path)
    await store.save(ToolEvent(session_id="s1", tool_name="exec"))

    async with aiosqlite.connect(str(db_path)) as db:
        async with db.execute("PRAGMA journal_mode") as cur:
            row = await cur.fetchone()
            assert row[0] == "wal"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_store_retention_deletes_old_events(tmp_path: Path):
    """Events older than 30 days must be deleted on save()."""
    db_path = tmp_path / "retention-test.db"
    store = EventStore(db_path=db_path)

    old_ts = datetime.now(timezone.utc) - timedelta(days=31)  # noqa: UP017
    old_event = ToolEvent(session_id="s1", tool_name="exec", timestamp=old_ts)

    # Save old event directly (bypassing retention on first save)
    await store._ensure_db()
    async with aiosqlite.connect(str(db_path)) as db:
        await db.execute(
            """INSERT INTO tool_events
               (id, session_id, skill_name, tool_name, params_summary,
                timestamp, duration_ms, outcome, alert_triggered, alert_reasons)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                old_event.id,
                old_event.session_id,
                old_event.skill_name,
                old_event.tool_name,
                old_event.params_summary,
                old_event.timestamp.isoformat(),
                old_event.duration_ms,
                old_event.outcome,
                int(old_event.alert_triggered),
                "[]",
            ),
        )
        await db.commit()

    # Save a new event — triggers retention cleanup
    new_event = ToolEvent(session_id="s1", tool_name="read")
    await store.save(new_event)

    events = await store.list()
    assert len(events) == 1
    assert events[0].id == new_event.id
