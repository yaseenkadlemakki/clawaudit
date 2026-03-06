"""WebSocket streaming endpoint."""
from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.engine.scan_manager import scan_manager

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])


@router.websocket("/ws/scans/{scan_id}/stream")
async def scan_stream(websocket: WebSocket, scan_id: str):
    """
    Stream live scan progress events as JSON.

    Event types:
    - {"type": "finding", "data": {...}}
    - {"type": "skill", "data": {...}}
    - {"type": "progress", "current": 5, "total": 50, "skill": "coding-agent"}
    - {"type": "completed", "summary": {...}}
    - {"type": "error", "message": "..."}
    """
    await websocket.accept()
    queue = scan_manager.subscribe(scan_id)
    logger.info("WebSocket client connected for scan %s", scan_id)

    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_text(json.dumps(event))
                if event.get("type") in ("completed", "error"):
                    break
            except asyncio.TimeoutError:
                # Send keepalive ping
                try:
                    await websocket.send_text(json.dumps({"type": "ping"}))
                except Exception:
                    break
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected for scan %s", scan_id)
    finally:
        scan_manager.unsubscribe(scan_id, queue)
