"""Unit tests for SentinelConfig and load_config."""
import os
import pytest
import tempfile
from pathlib import Path

import yaml

from sentinel.config import SentinelConfig, load_config, _deep_merge, _interpolate_env


def _minimal_data() -> dict:
    return {
        "openclaw": {
            "gateway_url": "http://localhost:18789",
            "gateway_token": "tok",
            "skills_dir": "/skills",
            "workspace_skills_dir": "/workspace",
            "config_file": "/config.json",
        },
        "sentinel": {
            "scan_interval_seconds": 60,
            "log_dir": "/logs",
            "findings_file": "/findings.jsonl",
            "baseline_file": "/baseline.json",
            "policies_dir": "/policies",
        },
        "alerts": {
            "enabled": True,
            "dedup_window_seconds": 300,
            "channels": {},
        },
        "api": {"enabled": False, "port": 18790, "bind": "loopback"},
    }


# ── SentinelConfig properties ─────────────────────────────────────────────────

@pytest.mark.unit
class TestSentinelConfigProperties:
    def _cfg(self, **overrides) -> SentinelConfig:
        data = _minimal_data()
        data["openclaw"].update(overrides)
        return SentinelConfig(data)

    def test_gateway_url(self):
        assert self._cfg().gateway_url == "http://localhost:18789"

    def test_gateway_token_from_data(self):
        assert self._cfg(gateway_token="mytoken").gateway_token == "mytoken"

    def test_gateway_token_falls_back_to_env(self, monkeypatch):
        monkeypatch.setenv("OPENCLAW_GATEWAY_TOKEN", "envtoken")
        cfg = SentinelConfig({**_minimal_data(),
                               "openclaw": {**_minimal_data()["openclaw"], "gateway_token": ""}})
        assert cfg.gateway_token == "envtoken"

    def test_scan_interval(self):
        cfg = SentinelConfig(_minimal_data())
        assert cfg.scan_interval == 60

    def test_scan_interval_setter(self):
        cfg = SentinelConfig(_minimal_data())
        cfg.scan_interval = 120
        assert cfg.scan_interval == 120

    def test_scan_interval_setter_coerces_to_int(self):
        cfg = SentinelConfig(_minimal_data())
        cfg.scan_interval = "90"  # type: ignore[assignment]
        assert cfg.scan_interval == 90

    def test_alerts_enabled_true(self):
        cfg = SentinelConfig(_minimal_data())
        assert cfg.alerts_enabled is True

    def test_alerts_enabled_false(self):
        data = _minimal_data()
        data["alerts"]["enabled"] = False
        assert SentinelConfig(data).alerts_enabled is False

    def test_dedup_window(self):
        assert SentinelConfig(_minimal_data()).dedup_window == 300

    def test_api_enabled_false(self):
        assert SentinelConfig(_minimal_data()).api_enabled is False

    def test_api_port(self):
        assert SentinelConfig(_minimal_data()).api_port == 18790

    def test_policies_dir_falls_back_to_bundled(self, tmp_path):
        data = _minimal_data()
        data["sentinel"]["policies_dir"] = str(tmp_path / "nonexistent")
        cfg = SentinelConfig(data)
        # bundled policies are at sentinel/policies/
        bundled = Path(__file__).parent.parent.parent / "sentinel" / "policies"
        if bundled.exists():
            assert cfg.policies_dir == bundled
        else:
            # If bundled doesn't exist either, it returns the configured path
            assert isinstance(cfg.policies_dir, Path)

    def test_raw_returns_dict(self):
        cfg = SentinelConfig(_minimal_data())
        assert isinstance(cfg.raw(), dict)


# ── _deep_merge ───────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestDeepMerge:
    def test_simple_override(self):
        result = _deep_merge({"a": 1, "b": 2}, {"b": 99})
        assert result["a"] == 1
        assert result["b"] == 99

    def test_nested_dict_merged(self):
        base = {"outer": {"a": 1, "b": 2}}
        override = {"outer": {"b": 99, "c": 3}}
        result = _deep_merge(base, override)
        assert result["outer"] == {"a": 1, "b": 99, "c": 3}

    def test_non_dict_value_overrides(self):
        result = _deep_merge({"k": {"nested": 1}}, {"k": "string"})
        assert result["k"] == "string"

    def test_base_not_mutated(self):
        base = {"a": {"x": 1}}
        _deep_merge(base, {"a": {"x": 2}})
        assert base["a"]["x"] == 1

    def test_new_key_added(self):
        result = _deep_merge({"a": 1}, {"b": 2})
        assert result["a"] == 1
        assert result["b"] == 2


# ── _interpolate_env ──────────────────────────────────────────────────────────

@pytest.mark.unit
class TestInterpolateEnv:
    def test_replaces_env_var(self, monkeypatch):
        monkeypatch.setenv("MY_TOKEN", "secret123")
        result = _interpolate_env("prefix_${MY_TOKEN}_suffix")
        assert result == "prefix_secret123_suffix"

    def test_missing_var_becomes_empty(self):
        result = _interpolate_env("${DEFINITELY_NOT_SET_XYZ}")
        assert result == ""

    def test_nested_dict_interpolated(self, monkeypatch):
        monkeypatch.setenv("GW_TOKEN", "tkn")
        data = {"token": "${GW_TOKEN}", "other": "plain"}
        result = _interpolate_env(data)
        assert result["token"] == "tkn"
        assert result["other"] == "plain"

    def test_list_interpolated(self, monkeypatch):
        monkeypatch.setenv("ITEM", "value")
        result = _interpolate_env(["${ITEM}", "literal"])
        assert result == ["value", "literal"]

    def test_non_string_passthrough(self):
        assert _interpolate_env(42) == 42
        assert _interpolate_env(True) is True
        assert _interpolate_env(None) is None


# ── load_config ───────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestLoadConfig:
    def test_returns_sentinel_config_with_defaults(self, tmp_path):
        cfg = load_config(tmp_path / "nonexistent.yaml")
        assert isinstance(cfg, SentinelConfig)
        assert cfg.scan_interval == 60  # default

    def test_user_yaml_overrides_defaults(self, tmp_path):
        config_file = tmp_path / "sentinel.yaml"
        config_file.write_text(yaml.dump({
            "sentinel": {"scan_interval_seconds": 120}
        }))
        cfg = load_config(config_file)
        assert cfg.scan_interval == 120

    def test_partial_override_preserves_other_defaults(self, tmp_path):
        config_file = tmp_path / "sentinel.yaml"
        config_file.write_text(yaml.dump({
            "sentinel": {"scan_interval_seconds": 30}
        }))
        cfg = load_config(config_file)
        assert cfg.api_port == 18790  # default preserved

    def test_env_interpolation_applied(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MY_GW_TOKEN", "fromenv")
        config_file = tmp_path / "sentinel.yaml"
        config_file.write_text(yaml.dump({
            "openclaw": {"gateway_token": "${MY_GW_TOKEN}"}
        }))
        cfg = load_config(config_file)
        assert cfg.gateway_token == "fromenv"
