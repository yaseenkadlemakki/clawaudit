"""Tests for backend policies API routes — improves coverage of policies.py lines 18-48."""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


async def _create_policy(client, *, name="test-policy", domain="capability", check="CHECK-01"):
    payload = {
        "name": name,
        "domain": domain,
        "check": check,
        "severity": "HIGH",
        "action": "alert",
        "enabled": True,
        "description": "A test policy",
    }
    resp = await client.post("/api/v1/policies", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# list_policies (lines 18-20)
# ---------------------------------------------------------------------------


@pytest.mark.backend
@pytest.mark.asyncio
async def test_list_policies_empty(client):
    resp = await client.get("/api/v1/policies")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.backend
@pytest.mark.asyncio
async def test_list_policies_with_records(client):
    await _create_policy(client, name="pol-a")
    await _create_policy(client, name="pol-b")
    resp = await client.get("/api/v1/policies")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    names = {p["name"] for p in data}
    assert "pol-a" in names
    assert "pol-b" in names


# ---------------------------------------------------------------------------
# create_policy (lines 26-28)
# ---------------------------------------------------------------------------


@pytest.mark.backend
@pytest.mark.asyncio
async def test_create_policy_returns_201(client):
    policy = await _create_policy(client)
    assert "id" in policy
    assert policy["name"] == "test-policy"
    assert policy["domain"] == "capability"
    assert policy["severity"] == "HIGH"
    assert policy["enabled"] is True


@pytest.mark.backend
@pytest.mark.asyncio
async def test_create_policy_all_fields(client):
    payload = {
        "name": "full-policy",
        "domain": "network",
        "check": "NET-01",
        "severity": "CRITICAL",
        "action": "block",
        "enabled": False,
        "description": "Full field test",
    }
    resp = await client.post("/api/v1/policies", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["description"] == "Full field test"
    assert data["enabled"] is False


# ---------------------------------------------------------------------------
# update_policy (lines 34-39)
# ---------------------------------------------------------------------------


@pytest.mark.backend
@pytest.mark.asyncio
async def test_update_policy_success(client):
    policy = await _create_policy(client, name="update-me")
    policy_id = policy["id"]

    resp = await client.put(f"/api/v1/policies/{policy_id}", json={"severity": "CRITICAL"})
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["severity"] == "CRITICAL"
    assert updated["name"] == "update-me"


@pytest.mark.backend
@pytest.mark.asyncio
async def test_update_policy_not_found(client):
    resp = await client.put(
        "/api/v1/policies/nonexistent-id", json={"severity": "LOW"}
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# delete_policy (lines 45-48)
# ---------------------------------------------------------------------------


@pytest.mark.backend
@pytest.mark.asyncio
async def test_delete_policy_success(client):
    policy = await _create_policy(client, name="delete-me")
    policy_id = policy["id"]

    resp = await client.delete(f"/api/v1/policies/{policy_id}")
    assert resp.status_code == 204

    # Confirm it's gone
    list_resp = await client.get("/api/v1/policies")
    ids = [p["id"] for p in list_resp.json()]
    assert policy_id not in ids


@pytest.mark.backend
@pytest.mark.asyncio
async def test_delete_policy_not_found(client):
    resp = await client.delete("/api/v1/policies/no-such-policy")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()
