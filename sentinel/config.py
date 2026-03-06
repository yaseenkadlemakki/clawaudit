"""Sentinel configuration loader.

Loads from ~/.openclaw/sentinel/sentinel.yaml or environment variables.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

load_dotenv()

_DEFAULT_CONFIG: dict[str, Any] = {
    "openclaw": {
        "gateway_url": "http://localhost:18789",
        "gateway_token": "",
        "skills_dir": "/opt/homebrew/lib/node_modules/openclaw/skills",
        "workspace_skills_dir": "~/.openclaw/workspace",
        "config_file": "~/.openclaw/openclaw.json",
    },
    "sentinel": {
        "scan_interval_seconds": 60,
        "log_dir": "~/.openclaw/sentinel/logs",
        "findings_file": "~/.openclaw/sentinel/findings.jsonl",
        "baseline_file": "~/.openclaw/sentinel/baseline.json",
        "policies_dir": "~/.openclaw/sentinel/policies",
    },
    "alerts": {
        "enabled": True,
        "dedup_window_seconds": 300,
        "channels": {
            "openclaw": {
                "enabled": True,
                "delivery_channel": "discord",
                "delivery_target": "channel:1479231189826015283",
            },
            "file": {
                "enabled": True,
                "path": "~/.openclaw/sentinel/alerts.jsonl",
            },
        },
    },
    "api": {
        "enabled": False,
        "port": 18790,
        "bind": "loopback",
    },
}

_ENV_PATTERN = re.compile(r"\$\{([^}]+)\}")


def _interpolate_env(value: Any) -> Any:
    """Recursively interpolate ${ENV_VAR} references."""
    if isinstance(value, str):
        def replace(m: re.Match) -> str:  # type: ignore[type-arg]
            return os.environ.get(m.group(1), "")
        return _ENV_PATTERN.sub(replace, value)
    if isinstance(value, dict):
        return {k: _interpolate_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate_env(v) for v in value]
    return value


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep merge override into base, returning a new dict."""
    result = dict(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


class SentinelConfig:
    """Configuration container for the Sentinel platform."""

    _instance: SentinelConfig | None = None

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    # ── convenience accessors ──────────────────────────────────────────────

    @property
    def gateway_url(self) -> str:
        return self._data["openclaw"]["gateway_url"]

    @property
    def gateway_token(self) -> str:
        return self._data["openclaw"]["gateway_token"] or os.environ.get("OPENCLAW_GATEWAY_TOKEN", "")

    @property
    def skills_dir(self) -> Path:
        return Path(self._data["openclaw"]["skills_dir"])

    @property
    def workspace_skills_dir(self) -> Path:
        return Path(self._data["openclaw"]["workspace_skills_dir"]).expanduser()

    @property
    def config_file(self) -> Path:
        return Path(self._data["openclaw"]["config_file"]).expanduser()

    @property
    def scan_interval(self) -> int:
        return int(self._data["sentinel"]["scan_interval_seconds"])

    @property
    def log_dir(self) -> Path:
        return Path(self._data["sentinel"]["log_dir"]).expanduser()

    @property
    def findings_file(self) -> Path:
        return Path(self._data["sentinel"]["findings_file"]).expanduser()

    @property
    def baseline_file(self) -> Path:
        return Path(self._data["sentinel"]["baseline_file"]).expanduser()

    @property
    def policies_dir(self) -> Path:
        p = Path(self._data["sentinel"]["policies_dir"]).expanduser()
        if not p.exists():
            # fall back to bundled policies
            bundled = Path(__file__).parent.parent / "policies"
            if bundled.exists():
                return bundled
        return p

    @property
    def alerts_enabled(self) -> bool:
        return bool(self._data["alerts"]["enabled"])

    @property
    def dedup_window(self) -> int:
        return int(self._data["alerts"]["dedup_window_seconds"])

    @property
    def alert_channels(self) -> dict[str, Any]:
        return self._data["alerts"]["channels"]

    @property
    def api_enabled(self) -> bool:
        return bool(self._data["api"]["enabled"])

    @property
    def api_port(self) -> int:
        return int(self._data["api"]["port"])

    def raw(self) -> dict[str, Any]:
        return self._data


def load_config(config_path: Path | None = None) -> SentinelConfig:
    """Load and return the Sentinel configuration."""
    default_path = Path("~/.openclaw/sentinel/sentinel.yaml").expanduser()
    path = config_path or default_path

    merged = dict(_DEFAULT_CONFIG)
    if path.exists():
        with path.open() as fh:
            user_data = yaml.safe_load(fh) or {}
        merged = _deep_merge(merged, user_data)

    merged = _interpolate_env(merged)
    return SentinelConfig(merged)


# Module-level singleton
_config: SentinelConfig | None = None


def get_config() -> SentinelConfig:
    """Return the global config singleton."""
    global _config
    if _config is None:
        _config = load_config()
    return _config
