"""Skills API routes."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/skills", tags=["skills"])


@router.get("/")
async def list_skills():
    return {"skills": []}


@router.get("/{name}")
async def get_skill(name: str):
    return {"name": name, "message": "Phase 2"}
