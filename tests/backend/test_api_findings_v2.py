"""Tests for backend findings API routes — improves coverage of findings.py lines 25-39."""

from __future__ import annotations

import uuid
from datetime import datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.finding import FindingRecord
from backend.models.scan import ScanRun, ScanStatus

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _seed_scan(db: AsyncSession, scan_id: str = "scan-1") -> ScanRun:
    scan = ScanRun(
        id=scan_id,
        status=ScanStatus.COMPLETED,
        triggered_by="test",
        total_findings=0,
    )
    db.add(scan)
    await db.commit()
    return scan


async def _seed_finding(
    db: AsyncSession,
    *,
    scan_id: str = "scan-1",
    severity: str = "HIGH",
    domain: str = "capability",
    skill_name: str | None = "test-skill",
) -> FindingRecord:
    finding = FindingRecord(
        id=str(uuid.uuid4()),
        scan_id=scan_id,
        check_id="CHECK-01",
        domain=domain,
        title="Test Finding",
        description="A test finding",
        severity=severity,
        result="FAIL",
        evidence="none",
        location="/tmp/test",
        remediation="fix it",
        detected_at=datetime.utcnow(),  # noqa: UP017
        skill_name=skill_name,
    )
    db.add(finding)
    await db.commit()
    return finding


@pytest.fixture
async def db_session():
    """Provide a DB session that shares the isolated_db patch."""
    from backend.database import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        yield session


# ---------------------------------------------------------------------------
# GET /api/v1/findings  (lines 25-29)
# ---------------------------------------------------------------------------


@pytest.mark.backend
@pytest.mark.asyncio
async def test_list_findings_empty(client):
    resp = await client.get("/api/v1/findings")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.backend
@pytest.mark.asyncio
async def test_list_findings_returns_records(client, db_session):
    await _seed_scan(db_session)
    await _seed_finding(db_session, severity="HIGH")
    await _seed_finding(db_session, severity="CRITICAL", domain="network")

    resp = await client.get("/api/v1/findings")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2


@pytest.mark.backend
@pytest.mark.asyncio
async def test_list_findings_filter_by_severity(client, db_session):
    await _seed_scan(db_session)
    await _seed_finding(db_session, severity="HIGH")
    await _seed_finding(db_session, severity="CRITICAL")
    await _seed_finding(db_session, severity="LOW")

    resp = await client.get("/api/v1/findings?severity=HIGH")
    assert resp.status_code == 200
    data = resp.json()
    assert all(f["severity"] == "HIGH" for f in data)
    assert len(data) == 1


@pytest.mark.backend
@pytest.mark.asyncio
async def test_list_findings_filter_by_domain(client, db_session):
    await _seed_scan(db_session)
    await _seed_finding(db_session, domain="capability")
    await _seed_finding(db_session, domain="network")

    resp = await client.get("/api/v1/findings?domain=capability")
    assert resp.status_code == 200
    data = resp.json()
    assert all(f["domain"] == "capability" for f in data)
    assert len(data) == 1


@pytest.mark.backend
@pytest.mark.asyncio
async def test_list_findings_filter_by_scan_id(client, db_session):
    await _seed_scan(db_session, scan_id="scan-a")
    await _seed_scan(db_session, scan_id="scan-b")
    await _seed_finding(db_session, scan_id="scan-a")
    await _seed_finding(db_session, scan_id="scan-b")
    await _seed_finding(db_session, scan_id="scan-a")

    resp = await client.get("/api/v1/findings?scan_id=scan-a")
    assert resp.status_code == 200
    data = resp.json()
    assert all(f["scan_id"] == "scan-a" for f in data)
    assert len(data) == 2


# ---------------------------------------------------------------------------
# GET /api/v1/findings/{finding_id}  (lines 35-39)
# ---------------------------------------------------------------------------


@pytest.mark.backend
@pytest.mark.asyncio
async def test_get_finding_found(client, db_session):
    await _seed_scan(db_session)
    finding = await _seed_finding(db_session)

    resp = await client.get(f"/api/v1/findings/{finding.id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == finding.id
    assert data["title"] == "Test Finding"


@pytest.mark.backend
@pytest.mark.asyncio
async def test_get_finding_not_found(client):
    resp = await client.get("/api/v1/findings/nonexistent-finding-id")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()
