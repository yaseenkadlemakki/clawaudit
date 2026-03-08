"""Tests for sentinel.hooks.bus — HookBus async event bus."""

from __future__ import annotations

import pytest

from sentinel.hooks.bus import HookBus
from sentinel.hooks.event import ToolEvent


@pytest.fixture(autouse=True)
def _reset_bus():
    """Ensure each test gets a fresh bus singleton."""
    HookBus.reset()
    yield
    HookBus.reset()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_publish_subscribe():
    bus = HookBus()
    received: list[ToolEvent] = []

    async def callback(event: ToolEvent) -> None:
        received.append(event)

    bus.subscribe(callback)
    event = ToolEvent(session_id="s1", tool_name="exec", params_summary="echo hi")
    await bus.publish(event)

    assert len(received) == 1
    assert received[0].tool_name == "exec"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_multiple_subscribers():
    bus = HookBus()
    results_a: list[ToolEvent] = []
    results_b: list[ToolEvent] = []

    async def cb_a(event: ToolEvent) -> None:
        results_a.append(event)

    async def cb_b(event: ToolEvent) -> None:
        results_b.append(event)

    bus.subscribe(cb_a)
    bus.subscribe(cb_b)
    await bus.publish(ToolEvent(tool_name="read"))

    assert len(results_a) == 1
    assert len(results_b) == 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_unsubscribe():
    bus = HookBus()
    received: list[ToolEvent] = []

    async def callback(event: ToolEvent) -> None:
        received.append(event)

    bus.subscribe(callback)
    bus.unsubscribe(callback)
    await bus.publish(ToolEvent(tool_name="exec"))

    assert len(received) == 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_subscriber_count():
    bus = HookBus()
    assert bus.subscriber_count == 0

    async def cb(event: ToolEvent) -> None:
        pass

    bus.subscribe(cb)
    assert bus.subscriber_count == 1

    bus.unsubscribe(cb)
    assert bus.subscriber_count == 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_alert_rules_run_on_publish():
    bus = HookBus()
    event = ToolEvent(
        session_id="s1",
        tool_name="exec",
        params_summary='{"pty": true, "cmd": "bash"}',
    )
    await bus.publish(event)
    assert event.alert_triggered is True
    assert len(event.alert_reasons) > 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_before_tool_call():
    bus = HookBus()
    event = await bus.before_tool_call(
        tool_name="exec",
        params={"cmd": "ls"},
        context={"session_id": "s1", "skill_name": "test-skill"},
    )
    assert event.tool_name == "exec"
    assert event.session_id == "s1"
    assert event.skill_name == "test-skill"
    assert event.outcome == "pending"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_after_tool_call():
    bus = HookBus()
    event = await bus.before_tool_call(
        tool_name="exec",
        params={"cmd": "ls"},
        context={"session_id": "s1"},
    )
    updated = await bus.after_tool_call(
        tool_name="exec",
        params={"cmd": "ls"},
        result="files listed",
        context={"session_id": "s1"},
        duration_ms=42,
        event=event,
    )
    assert updated.duration_ms == 42
    assert updated.outcome == "success"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_after_tool_call_error():
    bus = HookBus()
    updated = await bus.after_tool_call(
        tool_name="exec",
        params={"cmd": "fail"},
        result=RuntimeError("boom"),
        context={"session_id": "s1"},
        duration_ms=10,
    )
    assert updated.outcome == "error"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_singleton_behavior():
    bus1 = HookBus()
    bus2 = HookBus()
    assert bus1 is bus2
