"""Tests for sentinel.hooks.store — EventStore SQLite persistence."""

from __future__ import annotations

from pathlib import Path

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
