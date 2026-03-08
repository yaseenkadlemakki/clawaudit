"""Integration tests for the hooks pipeline — end-to-end event flow."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.hooks.bus import HookBus
from sentinel.hooks.event import ToolEvent
from sentinel.hooks.store import EventStore


@pytest.fixture
def store(tmp_path: Path) -> EventStore:
    return EventStore(db_path=tmp_path / "pipeline-events.db")


@pytest.fixture(autouse=True)
def _reset_bus():
    HookBus.reset()
    yield
    HookBus.reset()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_event_through_bus_to_store(store: EventStore):
    """Post an event through bus → store → query it back."""
    bus = HookBus()

    saved_events: list[ToolEvent] = []

    async def on_event(event: ToolEvent) -> None:
        await store.save(event)
        saved_events.append(event)

    bus.subscribe(on_event)

    event = ToolEvent(session_id="s1", tool_name="exec", params_summary="echo hi")
    await bus.publish(event)

    assert len(saved_events) == 1

    events = await store.list(session_id="s1")
    assert len(events) == 1
    assert events[0].tool_name == "exec"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_alert_event_stored_and_queryable(store: EventStore):
    """Alert-triggering event stored and filtered correctly."""
    bus = HookBus()

    async def on_event(event: ToolEvent) -> None:
        await store.save(event)

    bus.subscribe(on_event)

    # Non-alert event
    normal = ToolEvent(session_id="s1", tool_name="read", params_summary="path=~/Desktop/notes.txt")
    await bus.publish(normal)

    # Alert-triggering event (pty)
    alert_event = ToolEvent(
        session_id="s1",
        tool_name="exec",
        params_summary='{"pty": true, "cmd": "bash"}',
    )
    await bus.publish(alert_event)

    all_events = await store.list()
    assert len(all_events) == 2

    alerts = await store.list(alerts_only=True)
    assert len(alerts) == 1
    assert alerts[0].alert_triggered is True


@pytest.mark.integration
@pytest.mark.asyncio
async def test_stats_after_events(store: EventStore):
    """Stats reflect saved events accurately."""
    events = [
        ToolEvent(session_id="s1", skill_name="sk1", tool_name="exec"),
        ToolEvent(session_id="s1", skill_name="sk1", tool_name="read"),
        ToolEvent(
            session_id="s1",
            skill_name="sk2",
            tool_name="exec",
            alert_triggered=True,
            alert_reasons=["test alert"],
        ),
    ]
    for e in events:
        await store.save(e)

    stats = await store.stats()
    assert stats["total_events"] == 3
    assert stats["total_alerts"] == 1
    assert stats["events_by_tool"]["exec"] == 2


@pytest.mark.integration
@pytest.mark.asyncio
async def test_before_after_lifecycle(store: EventStore):
    """Full before_tool_call → after_tool_call lifecycle."""
    bus = HookBus()

    async def on_event(event: ToolEvent) -> None:
        await store.save(event)

    bus.subscribe(on_event)

    event = await bus.before_tool_call(
        tool_name="exec",
        params={"cmd": "ls"},
        context={"session_id": "lifecycle-test"},
    )
    assert event.outcome == "pending"

    await bus.after_tool_call(
        tool_name="exec",
        params={"cmd": "ls"},
        result="ok",
        context={"session_id": "lifecycle-test"},
        duration_ms=50,
        event=event,
    )
    assert event.outcome == "success"

    retrieved = await store.get(event.id)
    assert retrieved is not None
    assert retrieved.outcome == "success"
    assert retrieved.duration_ms == 50
