"""Policies API routes."""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/policies", tags=["policies"])


@router.get("/")
async def list_policies():
    return {"policies": []}


@router.post("/")
async def create_policy(policy: dict):
    return {"status": "Phase 2"}


@router.put("/{policy_id}")
async def update_policy(policy_id: str, policy: dict):
    return {"status": "Phase 2"}
