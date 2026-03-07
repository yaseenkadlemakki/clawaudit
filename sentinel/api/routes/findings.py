"""Findings API routes."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("/")
async def list_findings():
    """List all findings."""
    return {"findings": [], "total": 0}


@router.get("/{finding_id}")
async def get_finding(finding_id: str):
    """Get a specific finding by ID."""
    return {"id": finding_id, "message": "Phase 2 — not yet implemented"}
