"""Tests for backend scans API routes — improves coverage of scans.py."""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# POST /api/v1/scans  (lines 16-17)
# ---------------------------------------------------------------------------


@pytest.mark.backend
@pytest.mark.asyncio
async def test_start_scan_default(client):
    """POST with no body triggers a scan with default triggered_by='api'."""
    resp = await client.post("/api/v1/scans", json={})
    assert resp.status_code == 201
    data = resp.json()
    assert "id" in data
    assert data["status"] in ("running", "RUNNING")
    assert data["triggered_by"] == "api"


@pytest.mark.backend
@pytest.mark.asyncio
async def test_start_scan_custom_trigger(client):
    resp = await client.post("/api/v1/scans", json={"triggered_by": "cli"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["triggered_by"] == "cli"


# ---------------------------------------------------------------------------
# GET /api/v1/scans  (line 23)
# ---------------------------------------------------------------------------


@pytest.mark.backend
@pytest.mark.asyncio
async def test_list_scans_empty(client):
    resp = await client.get("/api/v1/scans")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.backend
@pytest.mark.asyncio
async def test_list_scans_with_results(client):
    await client.post("/api/v1/scans", json={})
    await client.post("/api/v1/scans", json={})
    resp = await client.get("/api/v1/scans")
    assert resp.status_code == 200
    assert len(resp.json()) >= 2


@pytest.mark.backend
@pytest.mark.asyncio
async def test_list_scans_limit_respected(client):
    for _ in range(5):
        await client.post("/api/v1/scans", json={})
    resp = await client.get("/api/v1/scans?limit=2")
    assert resp.status_code == 200
    assert len(resp.json()) <= 2


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id}  (lines 29-32)
# ---------------------------------------------------------------------------


@pytest.mark.backend
@pytest.mark.asyncio
async def test_get_scan_found(client):
    create_resp = await client.post("/api/v1/scans", json={})
    scan_id = create_resp.json()["id"]

    resp = await client.get(f"/api/v1/scans/{scan_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == scan_id


@pytest.mark.backend
@pytest.mark.asyncio
async def test_get_scan_not_found(client):
    resp = await client.get("/api/v1/scans/nonexistent-scan-id")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# DELETE /api/v1/scans/{scan_id}/stop  (lines 38-41)
# ---------------------------------------------------------------------------


@pytest.mark.backend
@pytest.mark.asyncio
async def test_stop_scan_found(client):
    create_resp = await client.post("/api/v1/scans", json={})
    scan_id = create_resp.json()["id"]

    resp = await client.delete(f"/api/v1/scans/{scan_id}/stop")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == scan_id
    # _execute_scan is stubbed to a noop (conftest), so the scan stays
    # RUNNING until stop_scan transitions it to STOPPING.
    assert data["status"] in ("stopping", "STOPPING")


@pytest.mark.backend
@pytest.mark.asyncio
async def test_stop_scan_not_found(client):
    resp = await client.delete("/api/v1/scans/no-such-scan/stop")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()
