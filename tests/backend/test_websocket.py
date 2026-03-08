"""WebSocket streaming tests (queue-based, no httpx_ws required)."""

from __future__ import annotations

import asyncio

import pytest

from backend.engine.scan_manager import ScanManager


@pytest.mark.asyncio
async def test_ws_subscribe_and_receive_events():
    """Verify that the scan_manager broadcast mechanism works."""
    mgr = ScanManager()
    scan_id = "test-ws-scan"
    queue = mgr.subscribe(scan_id)

    mgr._broadcast(scan_id, {"type": "progress", "current": 1, "total": 10, "skill": "test"})
    mgr._broadcast(scan_id, {"type": "completed", "summary": {}})

    events = []
    for _ in range(2):
        event = await asyncio.wait_for(queue.get(), timeout=1.0)
        events.append(event)

    mgr.unsubscribe(scan_id, queue)

    assert events[0]["type"] == "progress"
    assert events[0]["current"] == 1
    assert events[1]["type"] == "completed"


@pytest.mark.asyncio
async def test_ws_unsubscribe_cleans_up():
    mgr = ScanManager()
    scan_id = "ws-cleanup-test"
    q = mgr.subscribe(scan_id)
    assert q in mgr._ws_subscribers.get(scan_id, [])
    mgr.unsubscribe(scan_id, q)
    assert q not in mgr._ws_subscribers.get(scan_id, [])


@pytest.mark.asyncio
async def test_multiple_subscribers():
    mgr = ScanManager()
    scan_id = "multi-sub-test"
    q1 = mgr.subscribe(scan_id)
    q2 = mgr.subscribe(scan_id)

    mgr._broadcast(scan_id, {"type": "finding", "data": {"id": "f1"}})

    e1 = await asyncio.wait_for(q1.get(), timeout=1.0)
    e2 = await asyncio.wait_for(q2.get(), timeout=1.0)

    assert e1["type"] == "finding"
    assert e2["type"] == "finding"

    mgr.unsubscribe(scan_id, q1)
    mgr.unsubscribe(scan_id, q2)


@pytest.mark.asyncio
async def test_error_event_broadcast():
    mgr = ScanManager()
    scan_id = "error-test"
    q = mgr.subscribe(scan_id)

    mgr._broadcast(scan_id, {"type": "error", "message": "Something went wrong"})
    event = await asyncio.wait_for(q.get(), timeout=1.0)
    assert event["type"] == "error"
    assert "message" in event
    mgr.unsubscribe(scan_id, q)
