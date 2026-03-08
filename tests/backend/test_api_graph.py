"""API tests for knowledge graph endpoints."""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from unittest.mock import MagicMock

from backend.main import app
from backend.engine.knowledge_graph import knowledge_graph


@pytest_asyncio.fixture
async def client():
    from tests.backend.conftest import TEST_API_TOKEN

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {TEST_API_TOKEN}"},
    ) as c:
        yield c


@pytest_asyncio.fixture(autouse=True)
def clear_graph():
    """Reset the knowledge graph singleton before and after each test."""
    knowledge_graph.clear()
    yield
    knowledge_graph.clear()


def _make_skill_profile(name: str, domains: list[str] | None = None):
    """Build a minimal SkillProfile mock for graph seeding."""
    from sentinel.models.skill import SkillProfile
    profile = MagicMock(spec=SkillProfile)
    profile.name = name
    profile.path = f"/skills/{name}/SKILL.md"
    profile.source = "local"
    profile.trust_score = "TRUSTED"
    profile.trust_score_value = 90
    profile.shell_access = False
    profile.injection_risk = "LOW"
    profile.credential_exposure = False
    profile.outbound_domains = domains or []
    profile.shell_evidence = []
    return profile


@pytest.mark.asyncio
async def test_get_graph_empty(client):
    r = await client.get("/api/v1/graph")
    assert r.status_code == 200
    data = r.json()
    assert "nodes" in data
    assert "edges" in data
    assert "stats" in data
    assert data["stats"]["total_nodes"] == 0


@pytest.mark.asyncio
async def test_get_graph_with_skills(client):
    knowledge_graph.add_skill(_make_skill_profile("alpha", ["api.example.com"]), 20, "Low")
    knowledge_graph.add_skill(_make_skill_profile("beta"), 60, "High")

    r = await client.get("/api/v1/graph")
    assert r.status_code == 200
    data = r.json()
    node_ids = [n["id"] for n in data["nodes"]]
    assert "skill:alpha" in node_ids
    assert "skill:beta" in node_ids
    assert "network:api.example.com" in node_ids
    assert data["stats"]["skills"] == 2


@pytest.mark.asyncio
async def test_get_skill_subgraph_not_found(client):
    r = await client.get("/api/v1/graph/skill/nonexistent-skill")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_get_skill_subgraph_found(client):
    knowledge_graph.add_skill(_make_skill_profile("my-skill", ["api.test.com"]), 30, "Low")

    r = await client.get("/api/v1/graph/skill/my-skill")
    assert r.status_code == 200
    data = r.json()
    assert "node" in data
    assert "edges" in data
    assert data["node"]["name"] == "my-skill"
    assert len(data["edges"]) == 1
    assert data["edges"][0]["relation"] == "connects_to"
