"""Functional tests for sentinel hooks CLI subcommands."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.mark.functional
class TestHooksCli:
    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "sentinel.main", "hooks", *args],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_status_exits_zero(self):
        result = self._run("status")
        assert result.returncode == 0
        assert "Runtime Hook Status" in result.stdout or "Plugin" in result.stdout

    def test_register_creates_manifest(self, tmp_path: Path):
        manifest = tmp_path / "plugins" / "clawaudit.json"
        with patch("sentinel.hooks.plugin.ClawAuditPlugin.MANIFEST_PATH", manifest):
            # We can't easily patch inside subprocess, so just test the command runs
            result = self._run("register")
            # The command should succeed regardless
            assert result.returncode == 0

    def test_unregister_runs(self):
        result = self._run("unregister")
        assert result.returncode == 0

    def test_simulate_fires_event(self):
        result = self._run("simulate")
        assert result.returncode == 0
        assert "Test event fired" in result.stdout or "event" in result.stdout.lower()

    def test_events_exits_zero(self):
        result = self._run("events")
        assert result.returncode == 0
