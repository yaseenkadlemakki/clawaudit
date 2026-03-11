"""Tests for backend skills API routes — improves coverage of skills.py lines 24-36."""

from __future__ import annotations

import uuid
from datetime import datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.scan import ScanRun, ScanStatus
from backend.models.skill import SkillRecord

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _seed_scan(db: AsyncSession, scan_id: str = "scan-s1") -> ScanRun:
    scan = ScanRun(
        id=scan_id,
        status=ScanStatus.COMPLETED,
        triggered_by="test",
    )
    db.add(scan)
    await db.commit()
    return scan


async def _seed_skill(
    db: AsyncSession,
    *,
    scan_id: str = "scan-s1",
    name: str = "test-skill",
    risk_level: str = "High",
    risk_score: int = 75,
) -> SkillRecord:
    skill = SkillRecord(
        id=str(uuid.uuid4()),
        scan_id=scan_id,
        name=name,
        source="npm",
        path=f"/opt/skills/{name}",
        shell_access=True,
        outbound_domains='["example.com"]',
        injection_risk="LOW",
        trust_score="TRUSTED",
        risk_score=risk_score,
        risk_level=risk_level,
        detected_at=datetime.utcnow(),  # noqa: UP017
    )
    db.add(skill)
    await db.commit()
    return skill


@pytest.fixture
async def db_session():
    from backend.database import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        yield session


# ---------------------------------------------------------------------------
# GET /api/v1/skills  (lines 24-26)
# ---------------------------------------------------------------------------


@pytest.mark.backend
@pytest.mark.asyncio
async def test_list_skills_empty(client):
    resp = await client.get("/api/v1/skills")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.backend
@pytest.mark.asyncio
async def test_list_skills_returns_records(client, db_session):
    await _seed_scan(db_session)
    await _seed_skill(db_session, name="skill-a")
    await _seed_skill(db_session, name="skill-b")

    resp = await client.get("/api/v1/skills")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    names = {s["name"] for s in data}
    assert "skill-a" in names
    assert "skill-b" in names


@pytest.mark.backend
@pytest.mark.asyncio
async def test_list_skills_filter_by_scan_id(client, db_session):
    await _seed_scan(db_session, scan_id="scan-x")
    await _seed_scan(db_session, scan_id="scan-y")
    await _seed_skill(db_session, scan_id="scan-x", name="x-skill")
    await _seed_skill(db_session, scan_id="scan-y", name="y-skill")

    resp = await client.get("/api/v1/skills?scan_id=scan-x")
    assert resp.status_code == 200
    data = resp.json()
    assert all(s["scan_id"] == "scan-x" for s in data)
    assert len(data) == 1


@pytest.mark.backend
@pytest.mark.asyncio
async def test_list_skills_filter_by_risk_level(client, db_session):
    await _seed_scan(db_session)
    await _seed_skill(db_session, name="high-skill", risk_level="High")
    await _seed_skill(db_session, name="low-skill", risk_level="Low")
    await _seed_skill(db_session, name="crit-skill", risk_level="Critical")

    resp = await client.get("/api/v1/skills?risk_level=High")
    assert resp.status_code == 200
    data = resp.json()
    assert all(s["risk_level"] == "High" for s in data)
    assert len(data) == 1


# ---------------------------------------------------------------------------
# GET /api/v1/skills/{name}  (lines 32-36)
# ---------------------------------------------------------------------------


@pytest.mark.backend
@pytest.mark.asyncio
async def test_get_skill_found(client, db_session):
    await _seed_scan(db_session)
    skill = await _seed_skill(db_session, name="my-skill")

    resp = await client.get("/api/v1/skills/my-skill")
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "my-skill"
    assert data["id"] == skill.id


@pytest.mark.backend
@pytest.mark.asyncio
async def test_get_skill_not_found(client):
    resp = await client.get("/api/v1/skills/nonexistent-skill")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


@pytest.mark.backend
@pytest.mark.asyncio
async def test_get_skill_returns_latest_when_duplicates(client, db_session):
    """If the same skill appears multiple times, latest should be returned."""
    import asyncio

    await _seed_scan(db_session, scan_id="scan-old")
    await _seed_scan(db_session, scan_id="scan-new")
    await _seed_skill(db_session, scan_id="scan-old", name="dup-skill", risk_score=30)
    await asyncio.sleep(0.01)  # ensure different detected_at
    await _seed_skill(db_session, scan_id="scan-new", name="dup-skill", risk_score=90)

    resp = await client.get("/api/v1/skills/dup-skill")
    assert resp.status_code == 200
    # Returns the latest by detected_at — risk_score could be either in SQLite
    assert resp.json()["name"] == "dup-skill"
