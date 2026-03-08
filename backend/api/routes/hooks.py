"""Runtime hook API routes — /api/v1/hooks.

Provides endpoints for:
- Ingesting tool events (with HMAC validation)
- Querying stored events
- Managing the ClawAudit plugin registration
- WebSocket real-time event streaming
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging

from fastapi import APIRouter, Query, Request, WebSocket, WebSocketDisconnect

from sentinel.hooks.bus import HookBus
from sentinel.hooks.event import ToolEvent, sanitize_params
from sentinel.hooks.plugin import ClawAuditPlugin
from sentinel.hooks.rules import evaluate_rules
from sentinel.hooks.store import EventStore

logger = logging.getLogger(__name__)

router = APIRouter(tags=["hooks"])

# Module-level singletons
_store = EventStore()
_bus = HookBus()
_plugin = ClawAuditPlugin()

# WebSocket subscribers for the stream endpoint
_ws_clients: list[asyncio.Queue[dict]] = []


def _read_hmac_secret() -> str | None:
    """Read the HMAC secret from the plugin manifest."""
    manifest = _plugin.read_manifest()
    if manifest is None:
        return None
    return manifest.get("secret")


def _validate_hmac(body: bytes, signature: str) -> bool:
    """Validate X-ClawAudit-Signature: sha256=<hex>."""
    secret = _read_hmac_secret()
    if not secret:
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    provided = signature.removeprefix("sha256=")
    return hmac.compare_digest(expected, provided)


# ── POST /tool-event ─────────────────────────────────────────────────────────


@router.post("/tool-event")
async def ingest_tool_event(request: Request):
    """Receive a tool event from OpenClaw runtime. Validates HMAC signature."""
    signature = request.headers.get("X-ClawAudit-Signature", "")
    body = await request.body()

    if not signature or not _validate_hmac(body, signature):
        return {"detail": "Invalid or missing HMAC signature"}, 401

    data = json.loads(body)
    event = ToolEvent(
        session_id=data.get("session_id", ""),
        skill_name=data.get("skill_name"),
        tool_name=data.get("tool_name", ""),
        params_summary=sanitize_params(data.get("params_summary", "")),
    )

    # Evaluate alert rules
    recent = await _store.list(session_id=event.session_id, limit=50)
    reasons = evaluate_rules(event, recent)
    if reasons:
        event.alert_triggered = True
        event.alert_reasons = reasons

    # Persist
    await _store.save(event)

    # Publish to bus and WebSocket clients
    await _bus.publish(event)
    event_dict = event.to_dict()
    for q in list(_ws_clients):
        try:
            q.put_nowait(event_dict)
        except asyncio.QueueFull:
            pass

    return {
        "event_id": event.id,
        "alert_triggered": event.alert_triggered,
        "alert_reasons": event.alert_reasons,
    }


# ── GET /events ───────────────────────────────────────────────────────────────


@router.get("/events")
async def list_events(
    session_id: str | None = Query(None),
    skill_name: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    alerts_only: bool = Query(False),
):
    """Query stored tool events with optional filters."""
    events = await _store.list(
        session_id=session_id,
        skill_name=skill_name,
        limit=limit,
        alerts_only=alerts_only,
    )
    return [e.to_dict() for e in events]


# ── GET /events/{event_id} ───────────────────────────────────────────────────


@router.get("/events/{event_id}")
async def get_event(event_id: str):
    """Retrieve a single event by ID."""
    event = await _store.get(event_id)
    if event is None:
        return {"detail": "Event not found"}, 404
    return event.to_dict()


# ── GET /stats ────────────────────────────────────────────────────────────────


@router.get("/stats")
async def get_stats():
    """Aggregate event statistics."""
    return await _store.stats()


# ── GET /status ───────────────────────────────────────────────────────────────


@router.get("/status")
async def get_status():
    """Plugin registration status and hook system health."""
    return {
        "plugin_registered": _plugin.is_registered(),
        "plugin_manifest_path": str(_plugin.manifest_path),
        "bus_subscribers": _bus.subscriber_count,
        "store_path": str(_store.db_path),
    }


# ── POST /plugin/register ────────────────────────────────────────────────────


@router.post("/plugin/register")
async def register_plugin():
    """Register ClawAudit as an OpenClaw plugin."""
    path = _plugin.register()
    manifest = _plugin.read_manifest()
    return {
        "registered": True,
        "manifest_path": str(path),
        "manifest": manifest,
    }


# ── DELETE /plugin/unregister ─────────────────────────────────────────────────


@router.delete("/plugin/unregister")
async def unregister_plugin():
    """Remove the ClawAudit plugin registration."""
    _plugin.unregister()
    return {"registered": False}


# ── WebSocket /stream ─────────────────────────────────────────────────────────


@router.websocket("/stream")
async def event_stream(websocket: WebSocket):
    """Real-time WebSocket stream of ToolEvents."""
    await websocket.accept()
    queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=100)
    _ws_clients.append(queue)
    logger.info("Hook stream WebSocket client connected")

    try:
        while True:
            try:
                event_dict = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_text(json.dumps(event_dict))
            except TimeoutError:
                try:
                    await websocket.send_text(json.dumps({"type": "ping"}))
                except Exception:
                    break
    except WebSocketDisconnect:
        logger.info("Hook stream WebSocket client disconnected")
    finally:
        if queue in _ws_clients:
            _ws_clients.remove(queue)
