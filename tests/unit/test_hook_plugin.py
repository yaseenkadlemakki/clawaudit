"""Tests for sentinel.hooks.plugin — ClawAuditPlugin manifest handler."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel.hooks.plugin import ClawAuditPlugin


@pytest.fixture
def plugin(tmp_path: Path) -> ClawAuditPlugin:
    return ClawAuditPlugin(manifest_path=tmp_path / "plugins" / "clawaudit.json")


@pytest.fixture(autouse=True)
def _mock_secret(tmp_path: Path):
    """Mock the secret file to use tmp_path."""
    secret_file = tmp_path / "hook-secret"
    with patch("sentinel.hooks.plugin._SECRET_FILE", secret_file):
        yield


@pytest.mark.unit
class TestClawAuditPlugin:
    def test_register(self, plugin: ClawAuditPlugin):
        path = plugin.register()
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["name"] == "clawaudit"
        assert data["version"] == "0.1.0"
        assert "before_tool_call" in data["hooks"]
        assert "after_tool_call" in data["hooks"]
        assert data["enabled"] is True
        assert len(data["secret"]) == 64  # 32 bytes hex

    def test_is_registered(self, plugin: ClawAuditPlugin):
        assert plugin.is_registered() is False
        plugin.register()
        assert plugin.is_registered() is True

    def test_unregister(self, plugin: ClawAuditPlugin):
        plugin.register()
        assert plugin.is_registered() is True
        plugin.unregister()
        assert plugin.is_registered() is False
        assert not plugin.manifest_path.exists()

    def test_unregister_noop(self, plugin: ClawAuditPlugin):
        plugin.unregister()  # should not raise

    def test_read_manifest(self, plugin: ClawAuditPlugin):
        assert plugin.read_manifest() is None
        plugin.register()
        manifest = plugin.read_manifest()
        assert manifest is not None
        assert manifest["name"] == "clawaudit"

    def test_register_creates_directories(self, plugin: ClawAuditPlugin):
        assert not plugin.manifest_path.parent.exists()
        plugin.register()
        assert plugin.manifest_path.parent.exists()

    def test_is_registered_invalid_json(self, plugin: ClawAuditPlugin):
        plugin.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        plugin.manifest_path.write_text("not json")
        assert plugin.is_registered() is False

    def test_is_registered_disabled(self, plugin: ClawAuditPlugin):
        plugin.register()
        data = json.loads(plugin.manifest_path.read_text())
        data["enabled"] = False
        plugin.manifest_path.write_text(json.dumps(data))
        assert plugin.is_registered() is False
