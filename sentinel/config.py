"""Sentinel configuration loader.

Loads from ~/.openclaw/sentinel/sentinel.yaml or environment variables.
Also provides ``SecurityConfig`` (safe-domains + scan settings) loaded from
~/.openclaw/sentinel/config.yaml for script scanning and advanced detection.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# ── Security / scan configuration ──────────────────────────────────────────────

SECURITY_CONFIG_PATH = Path.home() / ".openclaw" / "sentinel" / "config.yaml"

_DEFAULT_SAFE_DOMAINS: frozenset[str] = frozenset(
    {
        "github.com",
        "api.github.com",
        "raw.githubusercontent.com",
        "pypi.org",
        "files.pythonhosted.org",
        "npmjs.com",
        "registry.npmjs.org",
        "anthropic.com",
        "api.anthropic.com",
        "openai.com",
        "api.openai.com",
        "google.com",
        "googleapis.com",
        "ai.google.dev",
        "huggingface.co",
        "cloudflare.com",
        "clawhub.com",
    }
)


@dataclass
class ScanConfig:
    """Knobs for the script / skill scanner."""

    severity_threshold: str = "low"
    scan_scripts: bool = True
    max_script_size_mb: float = 1.0


@dataclass
class SecurityConfig:
    """User-configurable safe domains and scan settings.

    Loaded from ``~/.openclaw/sentinel/config.yaml``.  Falls back to
    built-in defaults when the file is absent or corrupt.
    """

    safe_domains: frozenset[str] = field(default_factory=lambda: _DEFAULT_SAFE_DOMAINS)
    scan: ScanConfig = field(default_factory=ScanConfig)

    @classmethod
    def load(cls, path: Path | None = None) -> SecurityConfig:
        """Load from *path* (default ``SECURITY_CONFIG_PATH``), falling back to defaults."""
        path = path or SECURITY_CONFIG_PATH
        if not path.exists():
            return cls()
        try:
            raw = yaml.safe_load(path.read_text()) or {}
            domains = frozenset(raw.get("safe_domains", list(_DEFAULT_SAFE_DOMAINS)))
            scan_raw = raw.get("scan", {})
            scan = ScanConfig(
                severity_threshold=scan_raw.get("severity_threshold", "low"),
                scan_scripts=scan_raw.get("scan_scripts", True),
                max_script_size_mb=scan_raw.get("max_script_size_mb", 1.0),
            )
            return cls(safe_domains=domains, scan=scan)
        except Exception as exc:
            logger.warning("Failed to load security config from %s: %s — using defaults", path, exc)
            return cls()

    @classmethod
    def write_defaults(cls, path: Path | None = None) -> None:
        """Write a default config.yaml to *path*."""
        path = path or SECURITY_CONFIG_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# Sentinel configuration",
            "# Edit this file to customise ClawAudit behaviour.",
            "",
            "# Domains considered safe for outbound connections in skills.",
            "# Add your own providers here.",
            "safe_domains:",
        ]
        for d in sorted(_DEFAULT_SAFE_DOMAINS):
            lines.append(f"  - {d}")
        lines += [
            "",
            "scan:",
            "  # Minimum severity to report: low | medium | high | critical",
            "  severity_threshold: low",
            "  # Scan script files (non-SKILL.md) in skill directories",
            "  scan_scripts: true",
            "  # Maximum script file size to scan (MB)",
            "  max_script_size_mb: 1.0",
            "",
        ]
        path.write_text("\n".join(lines))


# ── Main sentinel configuration (sentinel.yaml) ───────────────────────────────

_DEFAULT_CONFIG: dict[str, Any] = {
    "openclaw": {
        "gateway_url": "http://localhost:18789",
        "gateway_token": "",
        "skills_dir": "/opt/homebrew/lib/node_modules/openclaw/skills",
        "workspace_skills_dir": "~/.openclaw/workspace/skills",
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

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    # ── convenience accessors ──────────────────────────────────────────────

    @property
    def gateway_url(self) -> str:
        return self._data["openclaw"]["gateway_url"]

    @property
    def gateway_token(self) -> str:
        return self._data["openclaw"]["gateway_token"] or os.environ.get(
            "OPENCLAW_GATEWAY_TOKEN", ""
        )

    @property
    def skills_dir(self) -> Path:
        return Path(self._data["openclaw"]["skills_dir"]).expanduser()

    @property
    def workspace_skills_dir(self) -> Path:
        return Path(self._data["openclaw"]["workspace_skills_dir"]).expanduser()

    @property
    def config_file(self) -> Path:
        return Path(self._data["openclaw"]["config_file"]).expanduser()

    @property
    def scan_interval(self) -> int:
        return int(self._data["sentinel"]["scan_interval_seconds"])

    @scan_interval.setter
    def scan_interval(self, value: int) -> None:
        self._data["sentinel"]["scan_interval_seconds"] = int(value)

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
            bundled = Path(__file__).parent / "policies"
            if bundled.exists():
                return bundled
        return p

    @property
    def sessions_dir(self) -> Path:
        return Path(self._data["openclaw"].get("sessions_dir", "~/.openclaw/sessions")).expanduser()

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
    load_dotenv()
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
