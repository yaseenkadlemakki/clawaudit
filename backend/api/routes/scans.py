"""Scan lifecycle routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from backend.api.schemas import ScanCreate, ScanResponse
from backend.engine.scan_manager import scan_manager

router = APIRouter(tags=["scans"])


@router.post("", response_model=ScanResponse, status_code=201)
async def start_scan(body: ScanCreate = ScanCreate()):
    """Trigger a new security audit scan."""
    scan = await scan_manager.start_scan(triggered_by=body.triggered_by)
    return scan


@router.get("", response_model=list[ScanResponse])
async def list_scans(limit: int = 20):
    """List recent scan runs."""
    return await scan_manager.list_scans(limit=limit)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str):
    """Get a specific scan by ID."""
    scan = await scan_manager.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.delete("/{scan_id}/stop", response_model=ScanResponse)
async def stop_scan(scan_id: str):
    """Request stop of a running scan."""
    scan = await scan_manager.stop_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
