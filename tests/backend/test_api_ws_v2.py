"""Tests for the WebSocket scan stream endpoint (ws.py lines 29-49)."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest

from backend.api.routes.ws import scan_stream
from backend.engine.scan_manager import ScanManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_ws() -> AsyncMock:
    """Return an AsyncMock that behaves like a WebSocket."""
    ws = AsyncMock()
    ws.accept = AsyncMock()
    ws.send_text = AsyncMock()
    ws.close = AsyncMock()
    return ws


# ---------------------------------------------------------------------------
# Tests covering the happy path and early-break on terminal events
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ws_stream_completed_event_breaks_loop():
    """Stream should disconnect after receiving a 'completed' event."""
    mgr = ScanManager()
    mock_ws = _make_mock_ws()

    with patch("backend.api.routes.ws.scan_manager", mgr):
        task = asyncio.create_task(scan_stream(mock_ws, "scan-ws-1"))
        # Give the task a tick to subscribe and start waiting
        await asyncio.sleep(0)
        mgr._broadcast("scan-ws-1", {"type": "completed", "summary": {"total": 0}})
        await asyncio.wait_for(task, timeout=3.0)

    mock_ws.accept.assert_called_once()
    # send_text was called at least once with the completed event
    call_args_list = [call.args[0] for call in mock_ws.send_text.call_args_list]
    events = [json.loads(a) for a in call_args_list]
    assert any(e.get("type") == "completed" for e in events)


@pytest.mark.asyncio
async def test_ws_stream_error_event_breaks_loop():
    """Stream should disconnect after receiving an 'error' event."""
    mgr = ScanManager()
    mock_ws = _make_mock_ws()

    with patch("backend.api.routes.ws.scan_manager", mgr):
        task = asyncio.create_task(scan_stream(mock_ws, "scan-ws-2"))
        await asyncio.sleep(0)
        mgr._broadcast("scan-ws-2", {"type": "error", "message": "oops"})
        await asyncio.wait_for(task, timeout=3.0)

    call_args_list = [call.args[0] for call in mock_ws.send_text.call_args_list]
    events = [json.loads(a) for a in call_args_list]
    assert any(e.get("type") == "error" for e in events)


@pytest.mark.asyncio
async def test_ws_stream_progress_then_completed():
    """Multiple events are streamed before the terminal event."""
    mgr = ScanManager()
    mock_ws = _make_mock_ws()

    with patch("backend.api.routes.ws.scan_manager", mgr):
        task = asyncio.create_task(scan_stream(mock_ws, "scan-ws-3"))
        await asyncio.sleep(0)
        mgr._broadcast("scan-ws-3", {"type": "progress", "current": 1, "total": 5, "skill": "s"})
        mgr._broadcast("scan-ws-3", {"type": "finding", "data": {"id": "f1"}})
        mgr._broadcast("scan-ws-3", {"type": "completed", "summary": {}})
        await asyncio.wait_for(task, timeout=3.0)

    raw_calls = [call.args[0] for call in mock_ws.send_text.call_args_list]
    events = [json.loads(c) for c in raw_calls]
    types = [e["type"] for e in events]
    assert "progress" in types
    assert "finding" in types
    assert "completed" in types


@pytest.mark.asyncio
async def test_ws_stream_websocket_disconnect_handled():
    """WebSocketDisconnect is caught gracefully and unsubscribes queue."""
    from fastapi import WebSocketDisconnect

    mgr = ScanManager()
    mock_ws = _make_mock_ws()
    # Raise WebSocketDisconnect on first send_text call
    mock_ws.send_text.side_effect = WebSocketDisconnect()

    with patch("backend.api.routes.ws.scan_manager", mgr):
        task = asyncio.create_task(scan_stream(mock_ws, "scan-ws-4"))
        await asyncio.sleep(0)
        mgr._broadcast("scan-ws-4", {"type": "progress", "current": 1, "total": 1, "skill": "x"})
        # Should complete without raising
        await asyncio.wait_for(task, timeout=3.0)

    # Queue must be unsubscribed in the finally block
    assert len(mgr._ws_subscribers.get("scan-ws-4", [])) == 0


@pytest.mark.asyncio
async def test_ws_stream_late_subscriber_gets_terminal_event():
    """A late subscriber should immediately receive the cached terminal event."""
    mgr = ScanManager()
    # Pre-cache a terminal event (simulating completed scan)
    terminal = {"type": "completed", "summary": {"total": 2}}
    mgr._terminal_events["scan-late"] = terminal

    # Subscribe after the scan completed
    q = mgr.subscribe("scan-late")
    event = await asyncio.wait_for(q.get(), timeout=1.0)
    assert event["type"] == "completed"
    mgr.unsubscribe("scan-late", q)


@pytest.mark.asyncio
async def test_ws_stream_keepalive_ping_on_timeout():
    """A 30-second timeout fires a keepalive ping to the client."""
    mgr = ScanManager()
    mock_ws = _make_mock_ws()

    # Simulate timeout by patching asyncio.wait_for to raise TimeoutError once,
    # then return a 'completed' event the second time.
    call_count = 0

    async def patched_wait_for(coro, timeout):  # noqa: ARG001
        nonlocal call_count
        call_count += 1
        coro.close()  # prevent RuntimeWarning: coroutine was never awaited
        if call_count == 1:
            raise TimeoutError
        # Return completed event so the loop exits
        return {"type": "completed", "summary": {}}

    with patch("backend.api.routes.ws.scan_manager", mgr):
        with patch("backend.api.routes.ws.asyncio.wait_for", patched_wait_for):
            # Note: don't wrap in asyncio.wait_for here since the patch is global
            await scan_stream(mock_ws, "scan-ping")

    # The ping should have been sent
    all_sent = [call.args[0] for call in mock_ws.send_text.call_args_list]
    payloads = [json.loads(s) for s in all_sent]
    assert any(p.get("type") == "ping" for p in payloads)


@pytest.mark.asyncio
async def test_ws_stream_keepalive_send_failure_breaks_loop():
    """If the keepalive ping send fails, the loop should exit cleanly."""
    mgr = ScanManager()
    mock_ws = _make_mock_ws()

    call_count = 0

    async def patched_wait_for(coro, timeout):  # noqa: ARG001
        nonlocal call_count
        call_count += 1
        coro.close()  # prevent RuntimeWarning: coroutine was never awaited
        raise TimeoutError

    # Raise on ping send so the inner except triggers break
    mock_ws.send_text.side_effect = Exception("connection lost")

    with patch("backend.api.routes.ws.scan_manager", mgr):
        with patch("backend.api.routes.ws.asyncio.wait_for", patched_wait_for):
            # Should complete without propagating the exception
            await scan_stream(mock_ws, "scan-ping-fail")
