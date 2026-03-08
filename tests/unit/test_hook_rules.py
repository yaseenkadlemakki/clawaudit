"""Tests for sentinel.hooks.rules — alert rule engine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone  # noqa: UP017

import pytest

from sentinel.hooks.event import ToolEvent
from sentinel.hooks.rules import (
    evaluate_rules,
    rule_browser_navigate,
    rule_exec_pty,
    rule_high_frequency,
    rule_sensitive_path_read,
    rule_write_outside_workspace,
)


def _event(**kwargs) -> ToolEvent:
    defaults = {
        "session_id": "test-session",
        "tool_name": "exec",
        "params_summary": "",
        "timestamp": datetime.now(timezone.utc),  # noqa: UP017
        "outcome": "success",
    }
    defaults.update(kwargs)
    return ToolEvent(**defaults)


@pytest.mark.unit
class TestRuleExecPty:
    def test_triggers(self):
        e = _event(tool_name="exec", params_summary='{"pty": true, "cmd": "bash"}')
        reasons = rule_exec_pty(e)
        assert len(reasons) == 1
        assert "pty:true" in reasons[0]

    def test_no_trigger(self):
        e = _event(tool_name="exec", params_summary='{"cmd": "ls -la"}')
        assert rule_exec_pty(e) == []

    def test_non_exec_tool(self):
        e = _event(tool_name="read", params_summary='{"pty": true}')
        assert rule_exec_pty(e) == []


@pytest.mark.unit
class TestRuleSensitivePath:
    def test_ssh(self):
        e = _event(tool_name="read", params_summary="path=~/.ssh/id_rsa")
        reasons = rule_sensitive_path_read(e)
        assert any("~/.ssh" in r for r in reasons)

    def test_openclaw(self):
        e = _event(tool_name="read", params_summary="path=~/.openclaw/openclaw.json")
        reasons = rule_sensitive_path_read(e)
        assert any("openclaw.json" in r for r in reasons)

    def test_safe(self):
        e = _event(tool_name="read", params_summary="path=~/Desktop/notes.txt")
        assert rule_sensitive_path_read(e) == []

    def test_non_read_tool(self):
        e = _event(tool_name="exec", params_summary="path=~/.ssh/id_rsa")
        assert rule_sensitive_path_read(e) == []


@pytest.mark.unit
class TestRuleWriteOutsideWorkspace:
    def test_triggers(self):
        e = _event(tool_name="write", params_summary="path=/etc/hosts")
        reasons = rule_write_outside_workspace(e)
        assert len(reasons) == 1

    def test_desktop_allowed(self):
        e = _event(tool_name="write", params_summary="path=~/Desktop/project/file.py")
        assert rule_write_outside_workspace(e) == []

    def test_tmp_allowed(self):
        e = _event(tool_name="write", params_summary="path=/tmp/scratch.txt")
        assert rule_write_outside_workspace(e) == []


@pytest.mark.unit
class TestRuleBrowserNavigate:
    def test_triggers(self):
        e = _event(tool_name="browser", params_summary="navigate to http://evil.com/payload")
        reasons = rule_browser_navigate(e)
        assert len(reasons) == 1

    def test_safe_domain(self):
        e = _event(tool_name="browser", params_summary="navigate to https://github.com/foo")
        assert rule_browser_navigate(e) == []

    def test_no_navigate(self):
        e = _event(tool_name="browser", params_summary="click button#submit")
        assert rule_browser_navigate(e) == []


@pytest.mark.unit
class TestRuleHighFrequency:
    def test_triggers(self):
        now = datetime.now(timezone.utc)  # noqa: UP017
        recent = [_event(timestamp=now - timedelta(seconds=i)) for i in range(21)]
        e = _event(timestamp=now)
        reasons = rule_high_frequency(e, recent)
        assert len(reasons) == 1
        assert "high frequency" in reasons[0]

    def test_under_limit(self):
        now = datetime.now(timezone.utc)  # noqa: UP017
        recent = [_event(timestamp=now - timedelta(seconds=i)) for i in range(19)]
        e = _event(timestamp=now)
        assert rule_high_frequency(e, recent) == []

    def test_no_recent(self):
        e = _event()
        assert rule_high_frequency(e, None) == []


@pytest.mark.unit
class TestEvaluateRules:
    def test_combines_reasons(self):
        e = _event(tool_name="exec", params_summary='{"pty": true}')
        reasons = evaluate_rules(e)
        assert len(reasons) >= 1

    def test_no_alerts_for_benign(self):
        e = _event(tool_name="exec", params_summary="echo hello")
        reasons = evaluate_rules(e)
        assert reasons == []
