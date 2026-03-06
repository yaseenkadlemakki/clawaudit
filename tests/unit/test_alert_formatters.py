"""Unit tests for alert message formatters."""
import pytest
from datetime import datetime

from sentinel.alerts.formatters import format_finding_alert, format_event_alert
from sentinel.models.finding import Finding
from sentinel.models.event import Event
from sentinel.models.policy import PolicyDecision


def _finding(**kwargs) -> Finding:
    defaults = dict(
        check_id="CONF-01", domain="config", title="Discord policy misconfigured",
        description="desc", severity="HIGH", result="FAIL",
        evidence="groupPolicy=open", location="openclaw.json",
        remediation="Set groupPolicy to allowlist", run_id="r1",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _decision(**kwargs) -> PolicyDecision:
    defaults = dict(action="ALERT", reason="rule matched", policy_ids=["POL-001"])
    defaults.update(kwargs)
    return PolicyDecision(**defaults)


def _event(**kwargs) -> Event:
    defaults = dict(
        source="session_collector", event_type="runaway_agent",
        severity="HIGH", entity="session-abc",
        evidence="tool_calls_per_minute=45", action_taken="ALERT",
    )
    defaults.update(kwargs)
    return Event(**defaults)


# ── format_finding_alert ──────────────────────────────────────────────────────

@pytest.mark.unit
class TestFormatFindingAlert:
    def test_contains_severity(self):
        msg = format_finding_alert(_finding(severity="CRITICAL"), _decision())
        assert "CRITICAL" in msg

    def test_contains_check_id(self):
        msg = format_finding_alert(_finding(), _decision())
        assert "CONF-01" in msg

    def test_contains_evidence(self):
        msg = format_finding_alert(_finding(), _decision())
        assert "groupPolicy=open" in msg

    def test_contains_location(self):
        msg = format_finding_alert(_finding(), _decision())
        assert "openclaw.json" in msg

    def test_contains_policy_ids(self):
        msg = format_finding_alert(_finding(), _decision(policy_ids=["POL-001", "POL-005"]))
        assert "POL-001" in msg

    def test_includes_remediation_when_set(self):
        msg = format_finding_alert(_finding(remediation="Fix it now"), _decision())
        assert "Fix it now" in msg

    def test_excludes_remediation_line_when_empty(self):
        msg = format_finding_alert(_finding(remediation=""), _decision())
        assert "Remediation:" not in msg

    def test_critical_uses_red_emoji(self):
        msg = format_finding_alert(_finding(severity="CRITICAL"), _decision())
        assert "🔴" in msg

    def test_high_uses_orange_emoji(self):
        msg = format_finding_alert(_finding(severity="HIGH"), _decision())
        assert "🟠" in msg

    def test_returns_string(self):
        assert isinstance(format_finding_alert(_finding(), _decision()), str)

    def test_multiline_output(self):
        msg = format_finding_alert(_finding(), _decision())
        assert "\n" in msg

    def test_default_policy_label_when_empty_ids(self):
        msg = format_finding_alert(_finding(), _decision(policy_ids=[]))
        assert "default" in msg


# ── format_event_alert ────────────────────────────────────────────────────────

@pytest.mark.unit
class TestFormatEventAlert:
    def test_contains_event_type(self):
        msg = format_event_alert(_event(), _decision())
        assert "runaway_agent" in msg

    def test_contains_source(self):
        msg = format_event_alert(_event(), _decision())
        assert "session_collector" in msg

    def test_contains_entity(self):
        msg = format_event_alert(_event(), _decision())
        assert "session-abc" in msg

    def test_contains_evidence(self):
        msg = format_event_alert(_event(), _decision())
        assert "tool_calls_per_minute=45" in msg

    def test_contains_action(self):
        msg = format_event_alert(_event(), _decision(action="BLOCK"))
        assert "BLOCK" in msg

    def test_returns_string(self):
        assert isinstance(format_event_alert(_event(), _decision()), str)

    def test_medium_uses_yellow_emoji(self):
        msg = format_event_alert(_event(severity="MEDIUM"), _decision())
        assert "🟡" in msg
