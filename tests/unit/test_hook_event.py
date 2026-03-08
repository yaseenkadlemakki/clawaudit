"""Tests for sentinel.hooks.event — ToolEvent dataclass."""

from __future__ import annotations

import json

import pytest

from sentinel.hooks.event import ToolEvent, sanitize_params


@pytest.mark.unit
class TestToolEvent:
    def test_defaults(self):
        e = ToolEvent()
        assert e.id
        assert e.session_id == ""
        assert e.skill_name is None
        assert e.tool_name == ""
        assert e.outcome == "pending"
        assert e.alert_triggered is False
        assert e.alert_reasons == []

    def test_to_dict(self):
        e = ToolEvent(session_id="s1", tool_name="exec", outcome="success")
        d = e.to_dict()
        assert d["session_id"] == "s1"
        assert d["tool_name"] == "exec"
        assert d["outcome"] == "success"
        assert isinstance(d["timestamp"], str)
        assert isinstance(d["alert_reasons"], list)

    def test_from_dict_roundtrip(self):
        e = ToolEvent(
            session_id="s1",
            skill_name="my-skill",
            tool_name="read",
            params_summary="file=foo.txt",
            outcome="success",
            alert_triggered=True,
            alert_reasons=["sensitive path"],
        )
        d = e.to_dict()
        e2 = ToolEvent.from_dict(d)
        assert e2.id == e.id
        assert e2.session_id == e.session_id
        assert e2.skill_name == e.skill_name
        assert e2.tool_name == e.tool_name
        assert e2.outcome == e.outcome
        assert e2.alert_triggered is True
        assert e2.alert_reasons == ["sensitive path"]

    def test_from_dict_json_reasons(self):
        d = {
            "id": "abc",
            "session_id": "s1",
            "tool_name": "exec",
            "alert_reasons": '["r1", "r2"]',
        }
        e = ToolEvent.from_dict(d)
        assert e.alert_reasons == ["r1", "r2"]

    def test_from_dict_missing_fields(self):
        e = ToolEvent.from_dict({})
        assert e.id
        assert e.tool_name == ""
        assert e.outcome == "pending"

    def test_to_dict_json_serializable(self):
        e = ToolEvent(session_id="s1", tool_name="browser")
        serialized = json.dumps(e.to_dict())
        assert "s1" in serialized


@pytest.mark.unit
class TestSanitizeParams:
    def test_truncates_long_string(self):
        raw = "x" * 500
        result = sanitize_params(raw)
        assert len(result) <= 200

    def test_redacts_anthropic_key(self):
        raw = "key=sk-ant-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        result = sanitize_params(raw)
        assert "sk-ant-" not in result
        assert "<REDACTED>" in result

    def test_redacts_github_pat(self):
        raw = "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        result = sanitize_params(raw)
        assert "ghp_" not in result

    def test_passes_safe_text(self):
        raw = "echo hello world"
        result = sanitize_params(raw)
        assert result == raw
