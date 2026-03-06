"""Policy management routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas import PolicyCreate, PolicyResponse, PolicyUpdate
from backend.database import get_db
from backend.storage.repository import PolicyRepository

router = APIRouter(tags=["policies"])


@router.get("", response_model=list[PolicyResponse])
async def list_policies(limit: int = 100, offset: int = 0, db: AsyncSession = Depends(get_db)):
    """List all policies."""
    repo = PolicyRepository(db)
    records = await repo.list(limit=limit, offset=offset)
    return [r.to_dict() for r in records]


@router.post("", response_model=PolicyResponse, status_code=201)
async def create_policy(body: PolicyCreate, db: AsyncSession = Depends(get_db)):
    """Create a new policy rule."""
    repo = PolicyRepository(db)
    record = await repo.create(body.model_dump())
    return record.to_dict()


@router.put("/{policy_id}", response_model=PolicyResponse)
async def update_policy(policy_id: str, body: PolicyUpdate, db: AsyncSession = Depends(get_db)):
    """Update an existing policy rule."""
    repo = PolicyRepository(db)
    data = {k: v for k, v in body.model_dump().items() if v is not None}
    record = await repo.update(policy_id, data)
    if not record:
        raise HTTPException(status_code=404, detail="Policy not found")
    return record.to_dict()


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(policy_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a policy rule."""
    repo = PolicyRepository(db)
    deleted = await repo.delete(policy_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Policy not found")
