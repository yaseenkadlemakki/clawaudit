"""Backend API tests for /api/v1/hooks endpoints."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel.hooks.bus import HookBus
from sentinel.hooks.store import EventStore

# Re-use the backend test fixtures from conftest.py
# (isolated_db, client, _set_test_api_token are autouse)


@pytest.fixture(autouse=True)
def _reset_bus():
    HookBus.reset()
    yield
    HookBus.reset()


@pytest.fixture(autouse=True)
def _mock_store(tmp_path: Path):
    """Use a temp DB for the hooks store during tests."""
    test_store = EventStore(db_path=tmp_path / "test-hooks.db")
    with patch("backend.api.routes.hooks._store", test_store):
        yield test_store


@pytest.fixture(autouse=True)
def _mock_plugin(tmp_path: Path):
    """Use a temp path for plugin manifest during tests."""
    from sentinel.hooks.plugin import ClawAuditPlugin

    plugin = ClawAuditPlugin(manifest_path=tmp_path / "plugins" / "clawaudit.json")
    with (
        patch("backend.api.routes.hooks._plugin", plugin),
        patch("sentinel.hooks.plugin._SECRET_FILE", tmp_path / "hook-secret"),
    ):
        yield plugin


@pytest.mark.backend
@pytest.mark.asyncio
async def test_get_status(client):
    resp = await client.get("/api/v1/hooks/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "plugin_registered" in data
    assert "store_path" in data


@pytest.mark.backend
@pytest.mark.asyncio
async def test_register_plugin(client):
    resp = await client.post("/api/v1/hooks/plugin/register")
    assert resp.status_code == 200
    data = resp.json()
    assert data["registered"] is True
    assert data["manifest"] is not None
    assert data["manifest"]["name"] == "clawaudit"


@pytest.mark.backend
@pytest.mark.asyncio
async def test_unregister_plugin(client):
    # Register first
    await client.post("/api/v1/hooks/plugin/register")
    resp = await client.delete("/api/v1/hooks/plugin/unregister")
    assert resp.status_code == 200
    assert resp.json()["registered"] is False


@pytest.mark.backend
@pytest.mark.asyncio
async def test_post_tool_event_with_valid_hmac(client, _mock_plugin, _mock_store):
    # Register plugin to create secret
    _mock_plugin.register()
    manifest = _mock_plugin.read_manifest()
    secret = manifest["secret"]

    body = json.dumps(
        {
            "tool_name": "exec",
            "session_id": "s1",
            "params_summary": "echo hello",
        }
    ).encode()
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    resp = await client.post(
        "/api/v1/hooks/tool-event",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-ClawAudit-Signature": sig,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "event_id" in data
    assert data["alert_triggered"] is False


@pytest.mark.backend
@pytest.mark.asyncio
async def test_post_tool_event_invalid_hmac(client, _mock_plugin):
    _mock_plugin.register()
    body = json.dumps({"tool_name": "exec", "session_id": "s1"}).encode()

    resp = await client.post(
        "/api/v1/hooks/tool-event",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-ClawAudit-Signature": "sha256=deadbeef",
        },
    )
    # Should fail HMAC validation
    assert resp.status_code == 200  # FastAPI returns the tuple as JSON body
    data = resp.json()
    # The route returns a tuple (dict, status_code) — FastAPI wraps it as array
    assert isinstance(data, list)
    assert data[1] == 401


@pytest.mark.backend
@pytest.mark.asyncio
async def test_post_tool_event_missing_hmac(client, _mock_plugin):
    _mock_plugin.register()
    body = json.dumps({"tool_name": "exec", "session_id": "s1"}).encode()

    resp = await client.post(
        "/api/v1/hooks/tool-event",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    data = resp.json()
    assert isinstance(data, list)
    assert data[1] == 401


@pytest.mark.backend
@pytest.mark.asyncio
async def test_get_events(client, _mock_plugin, _mock_store):
    # First post an event
    _mock_plugin.register()
    manifest = _mock_plugin.read_manifest()
    secret = manifest["secret"]

    body = json.dumps(
        {
            "tool_name": "read",
            "session_id": "s1",
            "params_summary": "file=test.py",
        }
    ).encode()
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    await client.post(
        "/api/v1/hooks/tool-event",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-ClawAudit-Signature": sig,
        },
    )

    # Now query
    resp = await client.get("/api/v1/hooks/events")
    assert resp.status_code == 200
    events = resp.json()
    assert len(events) >= 1
    assert events[0]["tool_name"] == "read"


@pytest.mark.backend
@pytest.mark.asyncio
async def test_get_stats(client, _mock_store):
    resp = await client.get("/api/v1/hooks/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_events" in data
    assert "total_alerts" in data
    assert "events_by_tool" in data


@pytest.mark.backend
@pytest.mark.asyncio
async def test_get_single_event(client, _mock_plugin, _mock_store):
    _mock_plugin.register()
    manifest = _mock_plugin.read_manifest()
    secret = manifest["secret"]

    body = json.dumps(
        {
            "tool_name": "exec",
            "session_id": "s1",
        }
    ).encode()
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    post_resp = await client.post(
        "/api/v1/hooks/tool-event",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-ClawAudit-Signature": sig,
        },
    )
    event_id = post_resp.json()["event_id"]

    resp = await client.get(f"/api/v1/hooks/events/{event_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == event_id


@pytest.mark.backend
@pytest.mark.asyncio
async def test_get_event_not_found(client):
    resp = await client.get("/api/v1/hooks/events/nonexistent-id")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert data[1] == 404
