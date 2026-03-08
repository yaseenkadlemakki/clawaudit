"""API tests for findings endpoints."""
from __future__ import annotations

from datetime import datetime

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import backend.database as _db
from backend.main import app
from backend.models.finding import FindingRecord
from backend.models.scan import ScanRun, ScanStatus


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
async def seeded_finding():
    """Insert a scan + finding into the DB."""
    async with _db.AsyncSessionLocal() as db:
        scan = ScanRun(id="scan-001", status=ScanStatus.COMPLETED, triggered_by="test")
        db.add(scan)
        finding = FindingRecord(
            id="finding-001",
            scan_id="scan-001",
            check_id="CONF-01",
            domain="config",
            title="Test finding",
            description="desc",
            severity="HIGH",
            result="FAIL",
            evidence="evidence",
            location="/some/path",
            remediation="fix it",
            detected_at=datetime.utcnow(),
        )
        db.add(finding)
        await db.commit()
    return "finding-001"


@pytest.mark.asyncio
async def test_list_findings_empty(client):
    r = await client.get("/api/v1/findings")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_list_findings(client, seeded_finding):
    r = await client.get("/api/v1/findings")
    assert r.status_code == 200
    assert len(r.json()) == 1
    assert r.json()[0]["check_id"] == "CONF-01"


@pytest.mark.asyncio
async def test_filter_by_scan_id(client, seeded_finding):
    r = await client.get("/api/v1/findings?scan_id=scan-001")
    assert r.status_code == 200
    assert len(r.json()) == 1


@pytest.mark.asyncio
async def test_filter_by_severity(client, seeded_finding):
    r = await client.get("/api/v1/findings?severity=HIGH")
    assert r.status_code == 200
    assert all(f["severity"] == "HIGH" for f in r.json())


@pytest.mark.asyncio
async def test_get_finding_by_id(client, seeded_finding):
    r = await client.get(f"/api/v1/findings/{seeded_finding}")
    assert r.status_code == 200
    assert r.json()["id"] == seeded_finding


@pytest.mark.asyncio
async def test_get_finding_not_found(client):
    r = await client.get("/api/v1/findings/no-such-id")
    assert r.status_code == 404
