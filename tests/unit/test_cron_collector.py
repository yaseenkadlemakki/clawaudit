"""Unit tests for CronCollector unauthorized cron detection."""
import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

import httpx

from sentinel.config import SentinelConfig
from sentinel.collector.cron_collector import CronCollector
from sentinel.models.event import Event


def _cfg() -> SentinelConfig:
    return SentinelConfig({
        "openclaw": {
            "gateway_url": "http://localhost:18789", "gateway_token": "tok",
            "skills_dir": "/s", "workspace_skills_dir": "/w", "config_file": "/c.json",
        },
        "sentinel": {
            "scan_interval_seconds": 60, "log_dir": "/l",
            "findings_file": "/f.jsonl", "baseline_file": "/b.json", "policies_dir": "/p",
        },
        "alerts": {"enabled": True, "dedup_window_seconds": 300, "channels": {}},
        "api": {"enabled": False, "port": 18790, "bind": "loopback"},
    })


def _mock_fetch(crons: list):
    """Patch _fetch_crons to return a fixed list."""
    async def _fetch(self):
        return crons
    return patch.object(CronCollector, "_fetch_crons", _fetch)


@pytest.mark.unit
class TestCronCollector:
    async def test_first_collect_sets_baseline_no_events(self):
        events = []
        col = CronCollector(_cfg(), events.append)
        with _mock_fetch([{"id": "cron-1"}, {"id": "cron-2"}]):
            await col.collect_once()
        assert events == []
        assert col._baseline_crons == {"cron-1", "cron-2"}

    async def test_no_new_crons_no_events(self):
        events = []
        col = CronCollector(_cfg(), events.append)
        crons = [{"id": "cron-1"}]
        with _mock_fetch(crons):
            await col.collect_once()  # establish baseline
        with _mock_fetch(crons):
            await col.collect_once()  # same crons
        assert events == []

    async def test_new_cron_emits_unauthorized_event(self):
        events = []
        col = CronCollector(_cfg(), events.append)
        with _mock_fetch([{"id": "cron-1"}]):
            await col.collect_once()  # baseline
        with _mock_fetch([{"id": "cron-1"}, {"id": "cron-new"}]):
            await col.collect_once()
        assert any(e.event_type == "unauthorized_cron" for e in events)
        assert any("cron-new" in e.entity for e in events)

    async def test_new_cron_event_references_pol_008(self):
        events = []
        col = CronCollector(_cfg(), events.append)
        with _mock_fetch([]):
            await col.collect_once()
        with _mock_fetch([{"id": "sneaky-cron"}]):
            await col.collect_once()
        runaway = [e for e in events if e.event_type == "unauthorized_cron"]
        assert any("POL-008" in e.policy_refs for e in runaway)

    async def test_fetch_failure_no_events(self):
        events = []
        col = CronCollector(_cfg(), events.append)
        with _mock_fetch([{"id": "cron-1"}]):
            await col.collect_once()  # baseline

        async def _fail(self):
            return None

        with patch.object(CronCollector, "_fetch_crons", _fail):
            await col.collect_once()
        assert events == []

    async def test_cron_name_fallback_when_no_id(self):
        events = []
        col = CronCollector(_cfg(), events.append)
        with _mock_fetch([]):
            await col.collect_once()
        with _mock_fetch([{"name": "nightly-backup"}]):
            await col.collect_once()
        assert any(e.event_type == "unauthorized_cron" for e in events)

    async def test_fetch_crons_handles_http_error(self):
        col = CronCollector(_cfg(), lambda e: None)
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=httpx.ConnectError("down"))
            mock_cls.return_value = mock_client
            result = await col._fetch_crons()
        assert result is None

    async def test_removed_cron_does_not_emit_event(self):
        """Crons that disappear are not flagged — only new ones."""
        events = []
        col = CronCollector(_cfg(), events.append)
        with _mock_fetch([{"id": "cron-1"}, {"id": "cron-2"}]):
            await col.collect_once()
        with _mock_fetch([{"id": "cron-1"}]):
            await col.collect_once()
        assert events == []
