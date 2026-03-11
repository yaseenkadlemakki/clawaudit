"""Unit tests for PolicyEngine.evaluate_tool_call() and supporting functions."""

from __future__ import annotations

from sentinel.models.policy import Rule
from sentinel.policy.engine import (
    PolicyEngine,
    ToolCallContext,
    _extract_tool_call_value,
    _matches_condition_extended,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_rule(
    id: str = "rule-1",
    domain: str = "tool_call",
    check: str = "tool",
    condition: str = "equals",
    value: str = "exec",
    action: str = "BLOCK",
    severity: str = "HIGH",
    enabled: bool = True,
    priority: int = 0,
) -> Rule:
    return Rule(
        id=id,
        domain=domain,
        check=check,
        condition=condition,
        value=value,
        severity=severity,
        action=action,
        message="Test rule",
        enabled=enabled,
        priority=priority,
    )


def make_ctx(
    tool: str = "exec",
    params: dict | None = None,
    skill_name: str | None = None,
    skill_signed: bool = False,
    skill_publisher: str | None = None,
    skill_path: str | None = None,
) -> ToolCallContext:
    return ToolCallContext(
        tool=tool,
        params=params or {},
        skill_name=skill_name,
        skill_signed=skill_signed,
        skill_publisher=skill_publisher,
        skill_path=skill_path,
    )


# ---------------------------------------------------------------------------
# _extract_tool_call_value
# ---------------------------------------------------------------------------


class TestExtractToolCallValue:
    def test_tool_name(self):
        ctx = make_ctx(tool="exec")
        assert _extract_tool_call_value(ctx, "tool") == "exec"

    def test_params_pty_true(self):
        ctx = make_ctx(params={"pty": True})
        assert _extract_tool_call_value(ctx, "params.pty") == "true"

    def test_params_pty_false(self):
        ctx = make_ctx(params={"pty": False})
        assert _extract_tool_call_value(ctx, "params.pty") == "false"

    def test_params_missing_key(self):
        ctx = make_ctx(params={})
        assert _extract_tool_call_value(ctx, "params.pty") == ""

    def test_params_command(self):
        ctx = make_ctx(params={"command": "bash -c ls"})
        assert _extract_tool_call_value(ctx, "params.command") == "bash -c ls"

    def test_params_path(self):
        ctx = make_ctx(params={"path": "/etc/passwd"})
        assert _extract_tool_call_value(ctx, "params.path") == "/etc/passwd"

    def test_skill_name(self):
        ctx = make_ctx(skill_name="my-skill")
        assert _extract_tool_call_value(ctx, "skill.name") == "my-skill"

    def test_skill_name_none(self):
        ctx = make_ctx(skill_name=None)
        assert _extract_tool_call_value(ctx, "skill.name") == ""

    def test_skill_signed_true(self):
        ctx = make_ctx(skill_signed=True)
        assert _extract_tool_call_value(ctx, "skill.signed") == "true"

    def test_skill_signed_false(self):
        ctx = make_ctx(skill_signed=False)
        assert _extract_tool_call_value(ctx, "skill.signed") == "false"

    def test_skill_publisher(self):
        ctx = make_ctx(skill_publisher="trusted-corp")
        assert _extract_tool_call_value(ctx, "skill.publisher") == "trusted-corp"

    def test_skill_publisher_none(self):
        ctx = make_ctx(skill_publisher=None)
        assert _extract_tool_call_value(ctx, "skill.publisher") == "null"

    def test_skill_path(self):
        ctx = make_ctx(skill_path="/home/user/.openclaw/skills/mys")
        assert _extract_tool_call_value(ctx, "skill.path") == "/home/user/.openclaw/skills/mys"

    def test_unknown_check(self):
        ctx = make_ctx()
        assert _extract_tool_call_value(ctx, "unknown.field") == ""


# ---------------------------------------------------------------------------
# _matches_condition_extended — new operators
# ---------------------------------------------------------------------------


class TestMatchesConditionExtended:
    def test_matches_regex(self):
        rule = make_rule(condition="matches", value=r"\.env$|\.key$")
        assert _matches_condition_extended(rule, "secrets/.env")
        assert _matches_condition_extended(rule, "id.key")
        assert not _matches_condition_extended(rule, "app.py")

    def test_matches_case_insensitive(self):
        rule = make_rule(condition="matches", value=r"\.ENV$")
        assert _matches_condition_extended(rule, "config/.env")

    def test_matches_invalid_regex_returns_false(self):
        rule = make_rule(condition="matches", value=r"[invalid")
        assert not _matches_condition_extended(rule, "anything")

    def test_glob(self):
        rule = make_rule(condition="glob", value="*.env")
        assert _matches_condition_extended(rule, ".env")
        assert _matches_condition_extended(rule, "prod.env")
        assert not _matches_condition_extended(rule, "app.py")

    def test_starts_with(self):
        rule = make_rule(condition="starts_with", value="bash")
        assert _matches_condition_extended(rule, "bash -c ls")
        assert not _matches_condition_extended(rule, "echo hello")

    def test_ends_with(self):
        rule = make_rule(condition="ends_with", value=".pem")
        assert _matches_condition_extended(rule, "server.pem")
        assert not _matches_condition_extended(rule, "server.key")

    def test_delegates_to_existing_equals(self):
        rule = make_rule(condition="equals", value="exec")
        assert _matches_condition_extended(rule, "exec")
        assert not _matches_condition_extended(rule, "read")

    def test_delegates_to_existing_contains(self):
        rule = make_rule(condition="contains", value="bash")
        assert _matches_condition_extended(rule, "bash -c ls")

    def test_delegates_to_existing_not_equals(self):
        rule = make_rule(condition="not_equals", value="exec")
        assert _matches_condition_extended(rule, "read")
        assert not _matches_condition_extended(rule, "exec")

    def test_delegates_to_existing_gt(self):
        rule = make_rule(condition="gt", value="10")
        assert _matches_condition_extended(rule, "11")
        assert not _matches_condition_extended(rule, "9")

    def test_delegates_to_existing_gte(self):
        rule = make_rule(condition="gte", value="10")
        assert _matches_condition_extended(rule, "10")
        assert _matches_condition_extended(rule, "11")
        assert not _matches_condition_extended(rule, "9")

    def test_delegates_to_existing_in(self):
        rule = make_rule(condition="in", value="exec, read, write")
        assert _matches_condition_extended(rule, "exec")
        assert _matches_condition_extended(rule, "read")
        assert not _matches_condition_extended(rule, "delete")

    def test_delegates_to_existing_exists(self):
        rule = make_rule(condition="exists", value="")
        assert _matches_condition_extended(rule, "something")
        assert not _matches_condition_extended(rule, "")

    def test_delegates_to_existing_not_in(self):
        rule = make_rule(condition="not_in", value="exec, read")
        assert _matches_condition_extended(rule, "write")
        assert not _matches_condition_extended(rule, "exec")


# ---------------------------------------------------------------------------
# PolicyEngine.evaluate_tool_call
# ---------------------------------------------------------------------------


class TestEvaluateToolCall:
    def test_no_matching_rules_returns_allow(self):
        engine = PolicyEngine.from_rules([])
        ctx = make_ctx(tool="exec")
        decision = engine.evaluate_tool_call(ctx)
        assert decision.action == "ALLOW"
        assert decision.matched_rules == []

    def test_matching_rule_returns_action(self):
        rule = make_rule(check="tool", condition="equals", value="exec", action="BLOCK")
        engine = PolicyEngine.from_rules([rule])
        ctx = make_ctx(tool="exec")
        decision = engine.evaluate_tool_call(ctx)
        assert decision.action == "BLOCK"
        assert rule in decision.matched_rules

    def test_non_matching_rule_returns_allow(self):
        rule = make_rule(check="tool", condition="equals", value="exec", action="BLOCK")
        engine = PolicyEngine.from_rules([rule])
        ctx = make_ctx(tool="read")
        decision = engine.evaluate_tool_call(ctx)
        assert decision.action == "ALLOW"

    def test_only_tool_call_domain_rules_evaluated(self):
        rule_tc = make_rule(domain="tool_call", check="tool", condition="equals", value="exec")
        rule_cfg = make_rule(
            id="cfg-rule", domain="config", check="tool", condition="equals", value="exec"
        )
        engine = PolicyEngine.from_rules([rule_tc, rule_cfg])
        ctx = make_ctx(tool="exec")
        decision = engine.evaluate_tool_call(ctx)
        assert rule_tc in decision.matched_rules
        assert rule_cfg not in decision.matched_rules

    def test_wildcard_domain_rule_matched(self):
        rule = make_rule(domain="*", check="tool", condition="equals", value="exec")
        engine = PolicyEngine.from_rules([rule])
        ctx = make_ctx(tool="exec")
        decision = engine.evaluate_tool_call(ctx)
        assert decision.action == "BLOCK"

    def test_disabled_rules_skipped(self):
        rule = make_rule(check="tool", condition="equals", value="exec", enabled=False)
        engine = PolicyEngine.from_rules([rule])
        ctx = make_ctx(tool="exec")
        decision = engine.evaluate_tool_call(ctx)
        assert decision.action == "ALLOW"

    def test_priority_ordering_highest_first(self):
        """Higher priority rules are evaluated first; action resolution picks highest."""
        rule_low = make_rule(
            id="low", check="tool", condition="equals", value="exec", action="WARN", priority=10
        )
        rule_high = make_rule(
            id="high", check="tool", condition="equals", value="exec", action="BLOCK", priority=100
        )
        engine = PolicyEngine.from_rules([rule_low, rule_high])
        ctx = make_ctx(tool="exec")
        decision = engine.evaluate_tool_call(ctx)
        # Both match, but BLOCK wins (highest action priority)
        assert decision.action == "BLOCK"

    def test_params_pty_block(self):
        rule = make_rule(check="params.pty", condition="equals", value="true", action="BLOCK")
        engine = PolicyEngine.from_rules([rule])
        ctx = make_ctx(params={"pty": True})
        decision = engine.evaluate_tool_call(ctx)
        assert decision.action == "BLOCK"

    def test_params_pty_false_no_match(self):
        rule = make_rule(check="params.pty", condition="equals", value="true", action="BLOCK")
        engine = PolicyEngine.from_rules([rule])
        ctx = make_ctx(params={"pty": False})
        decision = engine.evaluate_tool_call(ctx)
        assert decision.action == "ALLOW"

    def test_credential_file_alert(self):
        rule = make_rule(
            check="params.path",
            condition="matches",
            value=r"\.env$|credentials|\.pem$|\.key$",
            action="ALERT",
        )
        engine = PolicyEngine.from_rules([rule])
        ctx = make_ctx(tool="read", params={"path": "/home/user/.env"})
        decision = engine.evaluate_tool_call(ctx)
        assert decision.action == "ALERT"

    def test_quarantine_action(self):
        rule = make_rule(
            check="skill.signed",
            condition="equals",
            value="false",
            action="QUARANTINE",
        )
        engine = PolicyEngine.from_rules([rule])
        ctx = make_ctx(skill_signed=False)
        decision = engine.evaluate_tool_call(ctx)
        assert decision.action == "QUARANTINE"

    def test_multiple_rules_highest_action_wins(self):
        rules = [
            make_rule(id="r1", check="tool", condition="equals", value="exec", action="WARN"),
            make_rule(id="r2", check="tool", condition="equals", value="exec", action="ALERT"),
            make_rule(id="r3", check="tool", condition="equals", value="exec", action="BLOCK"),
        ]
        engine = PolicyEngine.from_rules(rules)
        ctx = make_ctx(tool="exec")
        decision = engine.evaluate_tool_call(ctx)
        assert decision.action == "BLOCK"
        assert len(decision.matched_rules) == 3

    def test_policy_ids_populated(self):
        rules = [
            make_rule(id="r1", check="tool", condition="equals", value="exec"),
            make_rule(id="r2", check="tool", condition="equals", value="exec"),
        ]
        engine = PolicyEngine.from_rules(rules)
        ctx = make_ctx(tool="exec")
        decision = engine.evaluate_tool_call(ctx)
        assert "r1" in decision.policy_ids
        assert "r2" in decision.policy_ids

    def test_reason_contains_rule_info(self):
        rule = make_rule(id="my-rule", check="tool", condition="equals", value="exec")
        engine = PolicyEngine.from_rules([rule])
        ctx = make_ctx(tool="exec")
        decision = engine.evaluate_tool_call(ctx)
        assert "my-rule" in decision.reason

    def test_params_elevated_alert(self):
        rule = make_rule(check="params.elevated", condition="equals", value="true", action="ALERT")
        engine = PolicyEngine.from_rules([rule])
        ctx = make_ctx(tool="exec", params={"elevated": True})
        decision = engine.evaluate_tool_call(ctx)
        assert decision.action == "ALERT"

    def test_params_elevated_false_no_match(self):
        rule = make_rule(check="params.elevated", condition="equals", value="true", action="ALERT")
        engine = PolicyEngine.from_rules([rule])
        ctx = make_ctx(tool="exec", params={"elevated": False})
        decision = engine.evaluate_tool_call(ctx)
        assert decision.action == "ALLOW"

    def test_params_url_matches(self):
        rule = make_rule(
            check="params.url",
            condition="matches",
            value=r"^https?://(?!localhost)",
            action="ALERT",
        )
        engine = PolicyEngine.from_rules([rule])
        ctx = make_ctx(tool="browser", params={"url": "https://evil.com"})
        decision = engine.evaluate_tool_call(ctx)
        assert decision.action == "ALERT"

    def test_params_url_localhost_no_match(self):
        rule = make_rule(
            check="params.url",
            condition="matches",
            value=r"^https?://(?!localhost)",
            action="ALERT",
        )
        engine = PolicyEngine.from_rules([rule])
        ctx = make_ctx(tool="browser", params={"url": "http://localhost:3000"})
        decision = engine.evaluate_tool_call(ctx)
        assert decision.action == "ALLOW"

    def test_params_command_contains(self):
        rule = make_rule(
            check="params.command", condition="contains", value="rm -rf", action="BLOCK"
        )
        engine = PolicyEngine.from_rules([rule])
        ctx = make_ctx(tool="exec", params={"command": "rm -rf /"})
        decision = engine.evaluate_tool_call(ctx)
        assert decision.action == "BLOCK"

    def test_skill_name_equals(self):
        rule = make_rule(
            check="skill.name", condition="equals", value="dangerous-skill", action="BLOCK"
        )
        engine = PolicyEngine.from_rules([rule])
        ctx = make_ctx(tool="exec", skill_name="dangerous-skill")
        decision = engine.evaluate_tool_call(ctx)
        assert decision.action == "BLOCK"

    def test_skill_publisher_block(self):
        rule = make_rule(check="skill.publisher", condition="equals", value="null", action="WARN")
        engine = PolicyEngine.from_rules([rule])
        ctx = make_ctx(tool="exec", skill_publisher=None)
        decision = engine.evaluate_tool_call(ctx)
        assert decision.action == "WARN"

    def test_skill_path_block(self):
        rule = make_rule(
            check="skill.path",
            condition="starts_with",
            value="/tmp/",
            action="BLOCK",
        )
        engine = PolicyEngine.from_rules([rule])
        ctx = make_ctx(tool="exec", skill_path="/tmp/untrusted-skill.md")
        decision = engine.evaluate_tool_call(ctx)
        assert decision.action == "BLOCK"
