"""Skills routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas import SkillResponse
from backend.database import get_db
from backend.storage.repository import SkillRepository

router = APIRouter(tags=["skills"])


@router.get("", response_model=list[SkillResponse])
async def list_skills(
    scan_id: str | None = None,
    risk_level: str | None = None,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """List skills with optional filters."""
    repo = SkillRepository(db)
    records = await repo.list(scan_id=scan_id, risk_level=risk_level, limit=limit, offset=offset)
    return [r.to_dict() for r in records]


@router.get("/{name}", response_model=SkillResponse)
async def get_skill(name: str, db: AsyncSession = Depends(get_db)):
    """Get the latest skill profile by name."""
    repo = SkillRepository(db)
    record = await repo.get_by_name(name)
    if not record:
        raise HTTPException(status_code=404, detail="Skill not found")
    return record.to_dict()
