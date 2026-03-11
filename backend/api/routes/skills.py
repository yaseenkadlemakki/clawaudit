"""Skills routes."""

from __future__ import annotations

from datetime import datetime, timezone

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


@router.post("/{skill_id}/unquarantine")
async def unquarantine_skill(skill_id: str, db: AsyncSession = Depends(get_db)):
    """Remove quarantine from a skill. Requires human approval."""
    repo = SkillRepository(db)
    skill = await repo.get(skill_id)
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")
    if not skill.quarantined:
        raise HTTPException(status_code=400, detail="Skill is not quarantined")
    skill.quarantined = False
    skill.quarantined_at = None
    skill.quarantine_reason = None
    await db.flush()
    await db.commit()
    return skill.to_dict()
