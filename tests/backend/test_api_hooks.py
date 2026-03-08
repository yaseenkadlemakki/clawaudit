"""Backend API tests for /api/v1/hooks endpoints."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
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
async def test_hmac_rejection_returns_401(client, _mock_plugin):
    """POST without valid HMAC must return actual HTTP 401, not 200."""
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
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid or missing HMAC signature"


@pytest.mark.backend
@pytest.mark.asyncio
async def test_post_tool_event_missing_hmac_returns_401(client, _mock_plugin):
    """POST without HMAC header must return HTTP 401."""
    _mock_plugin.register()
    body = json.dumps({"tool_name": "exec", "session_id": "s1"}).encode()

    resp = await client.post(
        "/api/v1/hooks/tool-event",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 401


@pytest.mark.backend
@pytest.mark.asyncio
async def test_event_not_found_returns_404(client):
    """GET /events/nonexistent must return actual HTTP 404."""
    resp = await client.get("/api/v1/hooks/events/nonexistent-id")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Event not found"


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
async def test_tool_event_params_summary_capped(client, _mock_plugin, _mock_store):
    """Oversized params_summary must be truncated to 2000 chars."""
    _mock_plugin.register()
    manifest = _mock_plugin.read_manifest()
    secret = manifest["secret"]

    big_summary = "x" * 5000
    body = json.dumps(
        {
            "tool_name": "exec",
            "session_id": "s1",
            "params_summary": big_summary,
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
    event_id = resp.json()["event_id"]

    # Fetch the event and verify summary was capped
    get_resp = await client.get(f"/api/v1/hooks/events/{event_id}")
    event_data = get_resp.json()
    # sanitize_params truncates to MAX_PARAMS_LEN (200) after the 2000 cap
    assert len(event_data["params_summary"]) <= 2000


@pytest.mark.backend
@pytest.mark.asyncio
async def test_manifest_file_permissions_0o600(tmp_path: Path):
    """Plugin manifest must be written with 0o600 permissions."""
    from sentinel.hooks.plugin import ClawAuditPlugin

    plugin = ClawAuditPlugin(manifest_path=tmp_path / "plugins" / "clawaudit.json")
    secret_file = tmp_path / "hook-secret"
    with patch("sentinel.hooks.plugin._SECRET_FILE", secret_file):
        plugin.register()

    mode = stat.S_IMODE(os.stat(plugin.manifest_path).st_mode)
    assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"


@pytest.mark.backend
@pytest.mark.asyncio
async def test_hook_secret_file_permissions_0o600(tmp_path: Path):
    """Hook-secret file must be written with 0o600 permissions."""
    from sentinel.hooks.plugin import ClawAuditPlugin

    secret_file = tmp_path / "hook-secret"
    plugin = ClawAuditPlugin(manifest_path=tmp_path / "plugins" / "clawaudit.json")
    with patch("sentinel.hooks.plugin._SECRET_FILE", secret_file):
        plugin.register()

    mode = stat.S_IMODE(os.stat(secret_file).st_mode)
    assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"
