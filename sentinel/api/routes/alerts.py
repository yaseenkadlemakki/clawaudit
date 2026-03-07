"""Alerts API routes."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/")
async def list_alerts():
    return {"alerts": []}


@router.post("/{alert_id}/ack")
async def ack_alert(alert_id: str):
    return {"alert_id": alert_id, "acknowledged": True}
