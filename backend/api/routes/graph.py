"""Knowledge graph routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from backend.engine.knowledge_graph import knowledge_graph

router = APIRouter(tags=["graph"])


@router.get("")
async def get_graph():
    """Export the full security knowledge graph."""
    return knowledge_graph.export_graph()


@router.get("/skill/{name}")
async def get_skill_graph(name: str):
    """Get the subgraph for a specific skill."""
    result = knowledge_graph.get_skill_graph(name)
    if not result:
        raise HTTPException(status_code=404, detail="Skill not found in graph")
    return result
