"""Unit tests for SessionCollector runaway agent detection."""

import json
from datetime import datetime, timedelta

import pytest

from sentinel.collector.session_collector import SessionCollector
from sentinel.config import SentinelConfig


def _cfg() -> SentinelConfig:
    return SentinelConfig(
        {
            "openclaw": {
                "gateway_url": "http://localhost",
                "gateway_token": "",
                "skills_dir": "/s",
                "workspace_skills_dir": "/w",
                "config_file": "/c.json",
            },
            "sentinel": {
                "scan_interval_seconds": 60,
                "log_dir": "/l",
                "findings_file": "/f.jsonl",
                "baseline_file": "/b.json",
                "policies_dir": "/p",
            },
            "alerts": {"enabled": True, "dedup_window_seconds": 300, "channels": {}},
            "api": {"enabled": False, "port": 18790, "bind": "loopback"},
        }
    )


def _make_session_jsonl(n_calls: int, window_seconds: int = 30) -> str:
    """Generate session JSONL with n_calls tool_use records within window_seconds."""
    base = datetime(2025, 1, 1, 12, 0, 0)
    lines = []
    for i in range(n_calls):
        ts = (base + timedelta(seconds=i * (window_seconds / max(n_calls, 1)))).isoformat()
        lines.append(json.dumps({"type": "tool_use", "ts": ts}))
    return "\n".join(lines)


@pytest.mark.unit
class TestSessionCollectorAnalyze:
    def _collector_and_events(self):
        events = []
        col = SessionCollector(_cfg(), events.append)
        return col, events

    def test_runaway_detected_when_rate_exceeds_30(self, tmp_path):
        col, events = self._collector_and_events()
        session = tmp_path / "session-001.jsonl"
        session.write_text(_make_session_jsonl(n_calls=35, window_seconds=50))
        col._analyze_session_file(session)
        assert any(e.event_type == "runaway_agent" for e in events)

    def test_normal_rate_no_event(self, tmp_path):
        col, events = self._collector_and_events()
        session = tmp_path / "session-002.jsonl"
        session.write_text(_make_session_jsonl(n_calls=10, window_seconds=60))
        col._analyze_session_file(session)
        assert events == []

    def test_fewer_than_2_calls_no_event(self, tmp_path):
        col, events = self._collector_and_events()
        session = tmp_path / "s.jsonl"
        session.write_text(json.dumps({"type": "tool_use", "ts": "2025-01-01T12:00:00"}))
        col._analyze_session_file(session)
        assert events == []

    def test_event_contains_session_id(self, tmp_path):
        col, events = self._collector_and_events()
        session = tmp_path / "my-session-42.jsonl"
        session.write_text(_make_session_jsonl(n_calls=35, window_seconds=50))
        col._analyze_session_file(session)
        runaway = [e for e in events if e.event_type == "runaway_agent"]
        assert any(e.entity == "my-session-42" for e in runaway)

    def test_event_references_pol_007(self, tmp_path):
        col, events = self._collector_and_events()
        session = tmp_path / "s.jsonl"
        session.write_text(_make_session_jsonl(n_calls=35, window_seconds=50))
        col._analyze_session_file(session)
        runaway = [e for e in events if e.event_type == "runaway_agent"]
        assert any("POL-007" in e.policy_refs for e in runaway)

    def test_same_session_only_alerted_once(self, tmp_path):
        col, events = self._collector_and_events()
        session = tmp_path / "s.jsonl"
        session.write_text(_make_session_jsonl(n_calls=35, window_seconds=50))
        col._analyze_session_file(session)
        col._analyze_session_file(session)
        assert sum(1 for e in events if e.event_type == "runaway_agent") == 1

    def test_permission_error_handled_gracefully(self, tmp_path):
        col, events = self._collector_and_events()
        session = tmp_path / "s.jsonl"
        session.write_text("")
        session.chmod(0o000)
        try:
            col._analyze_session_file(session)  # should not raise
        finally:
            session.chmod(0o644)

    def test_malformed_json_lines_skipped(self, tmp_path):
        col, events = self._collector_and_events()
        session = tmp_path / "s.jsonl"
        session.write_text("NOT_JSON\nALSO_BAD\n")
        col._analyze_session_file(session)
        assert events == []

    def test_empty_file_no_event(self, tmp_path):
        col, events = self._collector_and_events()
        session = tmp_path / "s.jsonl"
        session.write_text("")
        col._analyze_session_file(session)
        assert events == []

    def test_evidence_contains_call_count(self, tmp_path):
        col, events = self._collector_and_events()
        session = tmp_path / "s.jsonl"
        session.write_text(_make_session_jsonl(n_calls=35, window_seconds=50))
        col._analyze_session_file(session)
        runaway = [e for e in events if e.event_type == "runaway_agent"]
        assert any("tool_calls_per_minute" in e.evidence for e in runaway)
