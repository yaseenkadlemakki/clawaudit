"""Tests for SkillCollector permission error handling."""
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from sentinel.config import SentinelConfig
from sentinel.collector.skill_collector import SkillCollector


def _make_test_config() -> SentinelConfig:
    return SentinelConfig({
        "openclaw": {
            "gateway_url": "http://localhost:18789",
            "gateway_token": "",
            "skills_dir": "/tmp/test-skills-does-not-exist",
            "workspace_skills_dir": "/tmp/test-workspace-does-not-exist",
            "config_file": "/tmp/test-openclaw.json",
        },
        "sentinel": {
            "scan_interval_seconds": 60,
            "log_dir": "/tmp",
            "findings_file": "/tmp/findings.jsonl",
            "baseline_file": "/tmp/baseline.json",
            "policies_dir": "/tmp",
        },
        "alerts": {"enabled": False, "dedup_window_seconds": 300, "channels": {}},
        "api": {"enabled": False, "port": 18790, "bind": "loopback"},
    })


def test_skill_collector_handles_permission_error_on_schedule(tmp_path):
    """SkillCollector.start() does not crash when watchdog raises PermissionError."""
    cfg = _make_test_config()
    cfg._data["openclaw"]["skills_dir"] = str(tmp_path)
    cfg._data["openclaw"]["workspace_skills_dir"] = str(tmp_path)

    events = []
    collector = SkillCollector(cfg, events.append)

    mock_observer = MagicMock()
    mock_observer.schedule.side_effect = PermissionError("no access")

    with patch("sentinel.collector.skill_collector.Observer", return_value=mock_observer):
        # Should not raise even though schedule raises PermissionError
        collector.start()

    # No events emitted; collector gracefully skipped the dir
    assert events == []
