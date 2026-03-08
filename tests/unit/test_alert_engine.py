"""Unit tests for AlertEngine — routing and deduplication."""

import json
import time
from unittest.mock import MagicMock

import pytest

from sentinel.alerts.engine import AlertEngine
from sentinel.config import SentinelConfig
from sentinel.models.finding import Finding
from sentinel.models.policy import PolicyDecision


def _make_config(alerts_enabled=True, dedup_window=300, tmp_path=None) -> SentinelConfig:
    alerts_path = (
        str(tmp_path / "alerts.jsonl") if tmp_path else "~/.openclaw/sentinel/alerts.jsonl"
    )
    return SentinelConfig(
        {
            "openclaw": {
                "gateway_url": "http://localhost:18789",
                "gateway_token": "",
                "skills_dir": "/tmp/skills",
                "workspace_skills_dir": "/tmp/workspace",
                "config_file": "/tmp/config.json",
            },
            "sentinel": {
                "scan_interval_seconds": 60,
                "log_dir": "/tmp/logs",
                "findings_file": "/tmp/findings.jsonl",
                "baseline_file": "/tmp/baseline.json",
                "policies_dir": "/tmp/policies",
            },
            "alerts": {
                "enabled": alerts_enabled,
                "dedup_window_seconds": dedup_window,
                "channels": {
                    "file": {"enabled": True, "path": alerts_path},
                    "openclaw": {"enabled": False},
                },
            },
            "api": {"enabled": False, "port": 18790, "bind": "loopback"},
        }
    )


def _finding(**kwargs) -> Finding:
    defaults = dict(
        check_id="CONF-01",
        domain="config",
        title="Test",
        description="",
        severity="HIGH",
        result="FAIL",
        evidence="ev",
        location="openclaw.json",
        remediation="",
        run_id="r1",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _decision(action="ALERT") -> PolicyDecision:
    return PolicyDecision(action=action, reason="test", policy_ids=["POL-001"])


# ── routing ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestAlertEngineRouting:
    def test_send_with_alerts_disabled_does_not_write(self, tmp_path):
        cfg = _make_config(alerts_enabled=False, tmp_path=tmp_path)
        engine = AlertEngine(cfg)
        engine.send(_finding(), _decision("ALERT"))
        alerts_file = tmp_path / "alerts.jsonl"
        assert not alerts_file.exists()

    def test_send_with_allow_action_does_not_write(self, tmp_path):
        cfg = _make_config(tmp_path=tmp_path)
        engine = AlertEngine(cfg)
        engine.send(_finding(), _decision("ALLOW"))
        alerts_file = tmp_path / "alerts.jsonl"
        assert not alerts_file.exists()

    def test_send_with_alert_action_writes_record(self, tmp_path):
        cfg = _make_config(tmp_path=tmp_path)
        engine = AlertEngine(cfg)
        engine.send(_finding(), _decision("ALERT"))
        alerts_file = tmp_path / "alerts.jsonl"
        assert alerts_file.exists()
        record = json.loads(alerts_file.read_text().strip())
        assert record["check_id"] == "CONF-01"

    def test_send_with_block_action_writes_record(self, tmp_path):
        cfg = _make_config(tmp_path=tmp_path)
        engine = AlertEngine(cfg)
        engine.send(_finding(), _decision("BLOCK"))
        assert (tmp_path / "alerts.jsonl").exists()

    def test_send_with_warn_action_writes_record(self, tmp_path):
        cfg = _make_config(tmp_path=tmp_path)
        engine = AlertEngine(cfg)
        engine.send(_finding(), _decision("WARN"))
        assert (tmp_path / "alerts.jsonl").exists()

    def test_channel_error_does_not_raise(self, tmp_path):
        cfg = _make_config(tmp_path=tmp_path)
        engine = AlertEngine(cfg)
        # Poison the channel
        bad_channel = MagicMock()
        bad_channel.send.side_effect = RuntimeError("channel down")
        engine._channels = [bad_channel]
        # Should not raise
        engine.send(_finding(), _decision("ALERT"))


# ── deduplication ─────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestAlertEngineDedup:
    def test_second_send_within_window_suppressed(self, tmp_path):
        cfg = _make_config(dedup_window=300, tmp_path=tmp_path)
        engine = AlertEngine(cfg)
        f = _finding(check_id="CONF-01", location="openclaw.json")
        engine.send(f, _decision())
        engine.send(f, _decision())
        lines = (tmp_path / "alerts.jsonl").read_text().splitlines()
        assert len(lines) == 1

    def test_different_check_location_not_deduped(self, tmp_path):
        cfg = _make_config(dedup_window=300, tmp_path=tmp_path)
        engine = AlertEngine(cfg)
        engine.send(_finding(check_id="CONF-01", location="loc-a"), _decision())
        engine.send(_finding(check_id="CONF-01", location="loc-b"), _decision())
        lines = (tmp_path / "alerts.jsonl").read_text().splitlines()
        assert len(lines) == 2

    def test_clear_dedup_allows_resend(self, tmp_path):
        cfg = _make_config(dedup_window=300, tmp_path=tmp_path)
        engine = AlertEngine(cfg)
        f = _finding()
        engine.send(f, _decision())
        engine.clear_dedup()
        engine.send(f, _decision())
        lines = (tmp_path / "alerts.jsonl").read_text().splitlines()
        assert len(lines) == 2

    def test_dedup_key_uses_check_id_and_location(self, tmp_path):
        cfg = _make_config(dedup_window=300, tmp_path=tmp_path)
        engine = AlertEngine(cfg)
        f = _finding(check_id="X", location="Y")
        assert engine._dedup_key(f) == "X:Y"

    def test_expired_dedup_allows_resend(self, tmp_path):
        cfg = _make_config(dedup_window=1, tmp_path=tmp_path)  # 1 second window
        engine = AlertEngine(cfg)
        f = _finding()
        engine.send(f, _decision())
        # Manually backdate the dedup entry
        key = engine._dedup_key(f)
        engine._dedup[key] = time.time() - 2  # 2 seconds ago
        engine.send(f, _decision())
        lines = (tmp_path / "alerts.jsonl").read_text().splitlines()
        assert len(lines) == 2
