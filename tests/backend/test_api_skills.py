"""API tests for skills endpoints."""

from __future__ import annotations

import json
from datetime import datetime

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import backend.database as _db
from backend.main import app
from backend.models.scan import ScanRun, ScanStatus
from backend.models.skill import SkillRecord


@pytest_asyncio.fixture
async def client():
    from tests.backend.conftest import TEST_API_TOKEN

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {TEST_API_TOKEN}"},
    ) as c:
        yield c


@pytest_asyncio.fixture
async def seeded_skill():
    async with _db.AsyncSessionLocal() as db:
        scan = ScanRun(id="scan-002", status=ScanStatus.COMPLETED, triggered_by="test")
        db.add(scan)
        skill = SkillRecord(
            id="skill-001",
            scan_id="scan-002",
            name="coding-agent",
            source="local",
            path="/skills/coding-agent/SKILL.md",
            shell_access=True,
            outbound_domains=json.dumps(["api.openai.com"]),
            injection_risk="MEDIUM",
            trust_score="CAUTION",
            risk_score=45,
            risk_level="Medium",
            detected_at=datetime.utcnow(),
        )
        db.add(skill)
        await db.commit()
    return "coding-agent"


@pytest.mark.asyncio
async def test_list_skills_empty(client):
    r = await client.get("/api/v1/skills")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_list_skills(client, seeded_skill):
    r = await client.get("/api/v1/skills")
    assert r.status_code == 200
    assert len(r.json()) == 1
    assert r.json()[0]["name"] == "coding-agent"


@pytest.mark.asyncio
async def test_get_skill_by_name(client, seeded_skill):
    r = await client.get(f"/api/v1/skills/{seeded_skill}")
    assert r.status_code == 200
    assert r.json()["risk_score"] == 45


@pytest.mark.asyncio
async def test_get_skill_not_found(client):
    r = await client.get("/api/v1/skills/nonexistent")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_filter_by_risk_level(client, seeded_skill):
    r = await client.get("/api/v1/skills?risk_level=Medium")
    assert r.status_code == 200
    assert all(s["risk_level"] == "Medium" for s in r.json())
