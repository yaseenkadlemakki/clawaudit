"""API tests for scan endpoints."""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from backend.database import Base, engine
from backend.main import app


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    """Create tables before each test, drop after."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_health(client):
    r = await client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_list_scans_empty(client):
    r = await client.get("/api/v1/scans")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_start_scan(client):
    r = await client.post("/api/v1/scans", json={"triggered_by": "test"})
    assert r.status_code == 201
    data = r.json()
    assert data["status"] in ("running", "completed")
    assert data["triggered_by"] == "test"
    assert "id" in data


@pytest.mark.asyncio
async def test_get_scan_not_found(client):
    r = await client.get("/api/v1/scans/nonexistent-id")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_get_scan_by_id(client):
    # Start a scan
    r = await client.post("/api/v1/scans", json={"triggered_by": "test"})
    scan_id = r.json()["id"]

    r2 = await client.get(f"/api/v1/scans/{scan_id}")
    assert r2.status_code == 200
    assert r2.json()["id"] == scan_id


@pytest.mark.asyncio
async def test_stop_scan_not_found(client):
    r = await client.delete("/api/v1/scans/no-such-scan/stop")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_dashboard(client):
    r = await client.get("/api/v1/dashboard")
    assert r.status_code == 200
    data = r.json()
    assert "overall_score" in data
    assert "total_skills" in data
    assert "critical_findings" in data
