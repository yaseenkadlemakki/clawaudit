"""Findings routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas import FindingResponse
from backend.database import get_db
from backend.storage.repository import FindingRepository

router = APIRouter(tags=["findings"])


@router.get("", response_model=list[FindingResponse])
async def list_findings(
    scan_id: str | None = None,
    severity: str | None = None,
    domain: str | None = None,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """List findings with optional filters."""
    repo = FindingRepository(db)
    records = await repo.list(
        scan_id=scan_id, severity=severity, domain=domain, limit=limit, offset=offset
    )
    return [r.to_dict() for r in records]


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str, db: AsyncSession = Depends(get_db)):
    """Get a specific finding by ID."""
    repo = FindingRepository(db)
    record = await repo.get(finding_id)
    if not record:
        raise HTTPException(status_code=404, detail="Finding not found")
    return record.to_dict()
