"""API tests for policies endpoints (CRUD + DELETE)."""
from __future__ import annotations

from datetime import datetime

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import backend.database as _db
from backend.main import app
from backend.models.policy import PolicyRecord


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def seeded_policy():
    """Insert a policy into the DB and return its ID."""
    async with _db.AsyncSessionLocal() as db:
        policy = PolicyRecord(
            id="policy-001",
            name="test-policy",
            domain="config",
            check="CONF-01",
            severity="HIGH",
            action="ALERT",
            enabled=True,
            description="A test policy",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(policy)
        await db.commit()
    return "policy-001"


@pytest.mark.asyncio
async def test_list_policies_empty(client):
    r = await client.get("/api/v1/policies")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_create_policy(client):
    payload = {
        "name": "block-shell",
        "domain": "skills",
        "check": "SKILL-03",
        "severity": "CRITICAL",
        "action": "BLOCK",
        "enabled": True,
        "description": "Block shell access",
    }
    r = await client.post("/api/v1/policies", json=payload)
    assert r.status_code == 201
    data = r.json()
    assert data["name"] == "block-shell"
    assert data["action"] == "BLOCK"
    assert "id" in data
    assert data["enabled"] is True


@pytest.mark.asyncio
async def test_list_policies(client, seeded_policy):
    r = await client.get("/api/v1/policies")
    assert r.status_code == 200
    assert len(r.json()) == 1
    assert r.json()[0]["id"] == seeded_policy


@pytest.mark.asyncio
async def test_update_policy(client, seeded_policy):
    r = await client.put(
        f"/api/v1/policies/{seeded_policy}",
        json={"enabled": False},
    )
    assert r.status_code == 200
    assert r.json()["enabled"] is False


@pytest.mark.asyncio
async def test_update_policy_not_found(client):
    r = await client.put("/api/v1/policies/no-such-id", json={"enabled": False})
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_delete_policy(client, seeded_policy):
    r = await client.delete(f"/api/v1/policies/{seeded_policy}")
    assert r.status_code == 204

    # Verify the record is gone
    r2 = await client.get("/api/v1/policies")
    assert r2.status_code == 200
    assert r2.json() == []


@pytest.mark.asyncio
async def test_delete_policy_not_found(client):
    r = await client.delete("/api/v1/policies/no-such-id")
    assert r.status_code == 404
