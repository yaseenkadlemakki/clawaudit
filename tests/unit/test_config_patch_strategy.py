"""Unit tests for config_patch remediation strategy."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.remediation.actions import ActionType
from sentinel.remediation.strategies import config_patch


@pytest.mark.unit
class TestConfigPatchPropose:
    """Test proposal generation for CONF-xx checks."""

    def _write_config(self, tmp_path: Path, config: dict) -> Path:
        config_file = tmp_path / "openclaw.json"
        config_file.write_text(json.dumps(config, indent=2))
        return config_file

    def test_propose_conf03_gateway_bind(self, tmp_path):
        config_file = self._write_config(tmp_path, {"gateway": {"bind": "0.0.0.0"}})
        proposal = config_patch.propose(
            "openclaw-config", config_file, "find-1", check_id="CONF-03",
        )
        assert proposal is not None
        assert proposal.check_id == "CONF-03"
        assert proposal.action_type == ActionType.CONFIG_PATCH
        assert "loopback" in proposal.diff_preview
        assert "0.0.0.0" in proposal.diff_preview

    def test_propose_conf01_discord_group_policy(self, tmp_path):
        config_file = self._write_config(
            tmp_path, {"channels": {"discord": {"groupPolicy": "blocklist"}}},
        )
        proposal = config_patch.propose(
            "openclaw-config", config_file, "find-1", check_id="CONF-01",
        )
        assert proposal is not None
        assert proposal.check_id == "CONF-01"
        assert "allowlist" in proposal.diff_preview
        assert "blocklist" in proposal.diff_preview

    def test_propose_conf02_telegram_group_policy(self, tmp_path):
        config_file = self._write_config(
            tmp_path, {"channels": {"telegram": {"groupPolicy": "open"}}},
        )
        proposal = config_patch.propose(
            "openclaw-config", config_file, "find-1", check_id="CONF-02",
        )
        assert proposal is not None
        assert "allowlist" in proposal.diff_preview

    def test_propose_conf04_gateway_auth(self, tmp_path):
        config_file = self._write_config(
            tmp_path, {"gateway": {"auth": {"mode": "none"}}},
        )
        proposal = config_patch.propose(
            "openclaw-config", config_file, "find-1", check_id="CONF-04",
        )
        assert proposal is not None
        assert "token" in proposal.diff_preview

    def test_propose_conf06_yolo(self, tmp_path):
        config_file = self._write_config(tmp_path, {"yolo": True})
        proposal = config_patch.propose(
            "openclaw-config", config_file, "find-1", check_id="CONF-06",
        )
        assert proposal is not None
        assert "false" in proposal.diff_preview

    def test_propose_conf07_rate_limit(self, tmp_path):
        config_file = self._write_config(tmp_path, {"rateLimit": {"enabled": False}})
        proposal = config_patch.propose(
            "openclaw-config", config_file, "find-1", check_id="CONF-07",
        )
        assert proposal is not None
        assert "true" in proposal.diff_preview

    def test_propose_conf08_update_check(self, tmp_path):
        config_file = self._write_config(tmp_path, {"updates": {"checkEnabled": False}})
        proposal = config_patch.propose(
            "openclaw-config", config_file, "find-1", check_id="CONF-08",
        )
        assert proposal is not None
        assert "true" in proposal.diff_preview

    def test_propose_already_fixed_returns_none(self, tmp_path):
        config_file = self._write_config(tmp_path, {"gateway": {"bind": "loopback"}})
        proposal = config_patch.propose(
            "openclaw-config", config_file, "find-1", check_id="CONF-03",
        )
        assert proposal is None

    def test_propose_missing_config_file_returns_none(self, tmp_path):
        missing = tmp_path / "nonexistent.json"
        proposal = config_patch.propose(
            "openclaw-config", missing, "find-1", check_id="CONF-03",
        )
        assert proposal is None

    def test_propose_malformed_json_returns_none(self, tmp_path):
        config_file = tmp_path / "openclaw.json"
        config_file.write_text("{invalid json")
        proposal = config_patch.propose(
            "openclaw-config", config_file, "find-1", check_id="CONF-03",
        )
        assert proposal is None

    def test_propose_missing_key_creates_path(self, tmp_path):
        config_file = self._write_config(tmp_path, {})
        proposal = config_patch.propose(
            "openclaw-config", config_file, "find-1", check_id="CONF-03",
        )
        assert proposal is not None
        assert "loopback" in proposal.diff_preview

    def test_propose_unknown_check_id_returns_none(self, tmp_path):
        config_file = self._write_config(tmp_path, {})
        proposal = config_patch.propose(
            "openclaw-config", config_file, "find-1", check_id="UNKNOWN-99",
        )
        assert proposal is None

    def test_propose_no_check_id_returns_none(self, tmp_path):
        config_file = self._write_config(tmp_path, {})
        proposal = config_patch.propose(
            "openclaw-config", config_file, "find-1", check_id=None,
        )
        assert proposal is None

    def test_diff_preview_is_valid_unified_diff(self, tmp_path):
        config_file = self._write_config(tmp_path, {"gateway": {"bind": "0.0.0.0"}})
        proposal = config_patch.propose(
            "openclaw-config", config_file, "find-1", check_id="CONF-03",
        )
        assert proposal is not None
        assert proposal.diff_preview.startswith("---")
        assert "+++" in proposal.diff_preview
        assert "@@" in proposal.diff_preview

    def test_proposal_has_impact_and_description(self, tmp_path):
        config_file = self._write_config(tmp_path, {"gateway": {"bind": "0.0.0.0"}})
        proposal = config_patch.propose(
            "openclaw-config", config_file, "find-1", check_id="CONF-03",
        )
        assert proposal is not None
        assert len(proposal.impact) > 0
        assert len(proposal.description) > 0
        assert "loopback" in proposal.description


@pytest.mark.unit
class TestConfigPatchApply:
    """Test applying config patches."""

    def _write_config(self, tmp_path: Path, config: dict) -> Path:
        config_file = tmp_path / "openclaw.json"
        config_file.write_text(json.dumps(config, indent=2))
        return config_file

    def test_apply_patch_conf03(self, tmp_path):
        config_file = self._write_config(tmp_path, {"gateway": {"bind": "0.0.0.0"}})
        config_patch.apply_patch(config_file, check_id="CONF-03")
        result = json.loads(config_file.read_text())
        assert result["gateway"]["bind"] == "loopback"

    def test_apply_patch_conf06_yolo(self, tmp_path):
        config_file = self._write_config(tmp_path, {"yolo": True})
        config_patch.apply_patch(config_file, check_id="CONF-06")
        result = json.loads(config_file.read_text())
        assert result["yolo"] is False

    def test_apply_patch_creates_missing_keys(self, tmp_path):
        config_file = self._write_config(tmp_path, {})
        config_patch.apply_patch(config_file, check_id="CONF-03")
        result = json.loads(config_file.read_text())
        assert result["gateway"]["bind"] == "loopback"

    def test_apply_patch_preserves_other_keys(self, tmp_path):
        config_file = self._write_config(
            tmp_path, {"gateway": {"bind": "0.0.0.0", "port": 18789}, "other": "data"},
        )
        config_patch.apply_patch(config_file, check_id="CONF-03")
        result = json.loads(config_file.read_text())
        assert result["gateway"]["bind"] == "loopback"
        assert result["gateway"]["port"] == 18789
        assert result["other"] == "data"

    def test_apply_patch_directory_path(self, tmp_path):
        self._write_config(tmp_path, {"gateway": {"bind": "0.0.0.0"}})
        config_patch.apply_patch(tmp_path, check_id="CONF-03")
        result = json.loads((tmp_path / "openclaw.json").read_text())
        assert result["gateway"]["bind"] == "loopback"

    def test_apply_patch_atomic_no_tmp_left(self, tmp_path):
        config_file = self._write_config(tmp_path, {"yolo": True})
        config_patch.apply_patch(config_file, check_id="CONF-06")
        assert not (tmp_path / "openclaw.tmp").exists()

    def test_apply_multiple_patches_same_file(self, tmp_path):
        config_file = self._write_config(
            tmp_path, {"gateway": {"bind": "0.0.0.0"}, "yolo": True},
        )
        config_patch.apply_patch(config_file, check_id="CONF-03")
        config_patch.apply_patch(config_file, check_id="CONF-06")
        result = json.loads(config_file.read_text())
        assert result["gateway"]["bind"] == "loopback"
        assert result["yolo"] is False

    def test_apply_patch_unknown_check_raises(self, tmp_path):
        config_file = self._write_config(tmp_path, {})
        with pytest.raises(ValueError, match="No config fix"):
            config_patch.apply_patch(config_file, check_id="UNKNOWN")
