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
import os
import secrets

from fastapi import APIRouter, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, field_validator

from backend.middleware.auth import TOKEN_FILE
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


class ToolEventRequest(BaseModel):
    """Pydantic model for tool event ingestion with size limits."""

    tool_name: str
    params_summary: str = ""
    session_id: str = ""
    skill_name: str | None = None
    timestamp: str | None = None
    hmac_signature: str = ""

    @field_validator("params_summary")
    @classmethod
    def cap_params_summary(cls, v: str) -> str:
        return v[:2000]

    @field_validator("tool_name", "session_id")
    @classmethod
    def cap_short_fields(cls, v: str) -> str:
        return v[:256]


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


def _get_current_token() -> str:
    """Read the current API token from env or file."""
    env = os.environ.get("CLAWAUDIT_API_TOKEN", "").strip()
    if env:
        return env
    if TOKEN_FILE.exists():
        stored = TOKEN_FILE.read_text().strip()
        if stored:
            return stored
    return ""


# ── POST /tool-event ─────────────────────────────────────────────────────────


@router.post("/tool-event")
async def ingest_tool_event(request: Request):
    """Receive a tool event from OpenClaw runtime. Validates HMAC signature."""
    signature = request.headers.get("X-ClawAudit-Signature", "")
    body = await request.body()

    if not signature or not _validate_hmac(body, signature):
        raise HTTPException(status_code=401, detail="Invalid or missing HMAC signature")

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    event = ToolEvent(
        session_id=data.get("session_id", "")[:256],
        skill_name=data.get("skill_name"),
        tool_name=data.get("tool_name", "")[:256],
        params_summary=sanitize_params(data.get("params_summary", "")[:2000]),
    )

    # Evaluate alert rules here — bus.publish() skips re-evaluation when
    # alert data is already populated, preventing double rule execution.
    recent = await _store.list(session_id=event.session_id, limit=50)
    reasons = evaluate_rules(event, recent)
    if reasons:
        event.alert_triggered = True
        event.alert_reasons = reasons

    # Persist
    await _store.save(event)

    # Publish to bus (skips rule re-evaluation) and WebSocket clients
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
        raise HTTPException(status_code=404, detail="Event not found")
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
async def event_stream(websocket: WebSocket) -> None:
    """Real-time WebSocket stream of ToolEvents.

    Auth: client must send {"type": "auth", "token": "<token>"} as the
    first message within 5 seconds of connecting. Connection is closed
    with code 4001 on auth failure or timeout.
    """
    await websocket.accept()

    # Phase 1 — authenticate via first message (token never in URL)
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
        msg = json.loads(raw)
        client_token = msg.get("token", "") if msg.get("type") == "auth" else ""
    except (asyncio.TimeoutError, json.JSONDecodeError, Exception):
        await websocket.close(code=4001, reason="auth timeout or invalid message")
        return

    expected = _get_current_token()
    if not expected or not secrets.compare_digest(client_token, expected):
        await websocket.close(code=4001, reason="unauthorized")
        return

    await websocket.send_json({"type": "auth_ok"})

    queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=100)
    _ws_clients.append(queue)
    logger.info("Hook stream WebSocket client connected")

    try:
        while True:
            event_data = await queue.get()
            await websocket.send_json(event_data)
    except WebSocketDisconnect:
        pass
    finally:
        _ws_clients.remove(queue)
        logger.info("Hook stream WebSocket client disconnected")
