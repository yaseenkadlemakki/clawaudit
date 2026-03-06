"""Integration tests for the collector pipeline."""
import pytest
import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

from sentinel.config import SentinelConfig
from sentinel.collector.config_collector import ConfigCollector
from sentinel.models.event import Event


def _make_test_config() -> SentinelConfig:
    data = {
        "openclaw": {
            "gateway_url": "http://localhost:18789",
            "gateway_token": "test-token",
            "skills_dir": "/tmp/test-skills",
            "workspace_skills_dir": "/tmp/test-workspace",
            "config_file": "/tmp/test-openclaw.json",
        },
        "sentinel": {
            "scan_interval_seconds": 1,
            "log_dir": "/tmp/test-logs",
            "findings_file": "/tmp/test-findings.jsonl",
            "baseline_file": "/tmp/test-baseline.json",
            "policies_dir": "/tmp/test-policies",
        },
        "alerts": {
            "enabled": False,
            "dedup_window_seconds": 300,
            "channels": {},
        },
        "api": {"enabled": False, "port": 18790, "bind": "loopback"},
    }
    return SentinelConfig(data)


@pytest.mark.asyncio
async def test_config_collector_emits_drift_event():
    """ConfigCollector emits config_drift event when config hash changes."""
    cfg = _make_test_config()
    events = []

    collector = ConfigCollector(cfg, events.append)
    collector._last_hash = "oldhash"

    # Mock HTTP to fail, fall back to local file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"channels": {"discord": {"groupPolicy": "allowlist"}}}, f)
        cfg._data["openclaw"]["config_file"] = f.name

    await collector.collect_once()

    drift_events = [e for e in events if e.event_type == "config_drift"]
    assert len(drift_events) >= 1


@pytest.mark.asyncio
async def test_config_collector_no_drift_on_stable_config():
    """ConfigCollector does not emit drift when config is stable."""
    import hashlib
    cfg = _make_test_config()
    events = []

    config_data = {"channels": {"discord": {"groupPolicy": "allowlist"}}}
    config_hash = hashlib.sha256(
        json.dumps(config_data, sort_keys=True).encode()
    ).hexdigest()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config_data, f)
        cfg._data["openclaw"]["config_file"] = f.name

    collector = ConfigCollector(cfg, events.append)
    collector._last_hash = config_hash

    await collector.collect_once()

    drift_events = [e for e in events if e.event_type == "config_drift"]
    assert len(drift_events) == 0
