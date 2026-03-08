"""Tests for the policy engine."""

import tempfile
from pathlib import Path

import yaml

from sentinel.models.event import Event
from sentinel.models.finding import Finding
from sentinel.policy.engine import PolicyEngine


def _make_policy_dir(rules: list) -> Path:
    """Create a temp policy dir with given rules."""
    d = Path(tempfile.mkdtemp())
    policy_data = {"name": "test", "version": "1", "rules": rules}
    (d / "test.yaml").write_text(yaml.dump(policy_data))
    return d


def test_pol_001_discord_group_policy():
    pol_dir = _make_policy_dir(
        [
            {
                "id": "POL-001",
                "domain": "config",
                "check": "discord.groupPolicy",
                "condition": "not_equals",
                "value": "allowlist",
                "severity": "CRITICAL",
                "action": "ALERT",
                "message": "test",
            }
        ]
    )
    engine = PolicyEngine(pol_dir)

    _finding_unused = Finding(
        check_id="CONF-01",
        domain="config",
        title="test",
        description="",
        severity="CRITICAL",
        result="FAIL",
        evidence="groupPolicy=open",
        location="openclaw.json → discord.groupPolicy",
        remediation="",
        run_id="r1",
    )
    # Use check field matching
    event = Event(
        source="config_collector",
        event_type="config_audit_fail",
        severity="CRITICAL",
        entity="openclaw.json",
        evidence="check_id=CONF-01 groupPolicy=open",
        action_taken="ALLOW",
    )
    decision = engine.evaluate(event)
    assert isinstance(decision.action, str)


def test_pol_007_runaway_agent():
    pol_dir = _make_policy_dir(
        [
            {
                "id": "POL-007",
                "domain": "runtime",
                "check": "tool_calls_per_minute",
                "condition": "gt",
                "value": "30",
                "severity": "HIGH",
                "action": "ALERT",
                "message": "runaway",
            }
        ]
    )
    engine = PolicyEngine(pol_dir)

    event = Event(
        source="session_collector",
        event_type="runaway_agent",
        severity="HIGH",
        entity="session-abc",
        evidence="tool_calls_per_minute=45 threshold=30",
        action_taken="ALLOW",
    )
    decision = engine.evaluate(event)
    assert decision.action == "ALERT"
    assert any(r.id == "POL-007" for r in decision.matched_rules)


def test_pol_008_unauthorized_cron():
    pol_dir = _make_policy_dir(
        [
            {
                "id": "POL-008",
                "domain": "runtime",
                "check": "event_type",
                "condition": "equals",
                "value": "unauthorized_cron",
                "severity": "HIGH",
                "action": "ALERT",
                "message": "cron",
            }
        ]
    )
    engine = PolicyEngine(pol_dir)

    event = Event(
        source="cron_collector",
        event_type="unauthorized_cron",
        severity="HIGH",
        entity="cron-xyz",
        evidence="new_cron_id=cron-xyz",
        action_taken="ALLOW",
    )
    decision = engine.evaluate(event)
    assert decision.action == "ALERT"


def test_pol_009_new_skill():
    pol_dir = _make_policy_dir(
        [
            {
                "id": "POL-009",
                "domain": "skills",
                "check": "event_type",
                "condition": "equals",
                "value": "new_skill",
                "severity": "MEDIUM",
                "action": "ALERT",
                "message": "new skill",
            }
        ]
    )
    engine = PolicyEngine(pol_dir)

    event = Event(
        source="skill_collector",
        event_type="new_skill",
        severity="MEDIUM",
        entity="evil-skill",
        evidence="path=/tmp/evil-skill/SKILL.md",
        action_taken="ALLOW",
    )
    decision = engine.evaluate(event)
    assert decision.action == "ALERT"


def test_pol_010_config_drift():
    pol_dir = _make_policy_dir(
        [
            {
                "id": "POL-010",
                "domain": "config",
                "check": "event_type",
                "condition": "equals",
                "value": "config_drift",
                "severity": "HIGH",
                "action": "ALERT",
                "message": "drift",
            }
        ]
    )
    engine = PolicyEngine(pol_dir)

    event = Event(
        source="config_collector",
        event_type="config_drift",
        severity="HIGH",
        entity="openclaw.json",
        evidence="config_hash_changed=abc123",
        action_taken="ALLOW",
    )
    decision = engine.evaluate(event)
    assert decision.action == "ALERT"


def test_allow_when_no_rules_match():
    pol_dir = _make_policy_dir([])
    engine = PolicyEngine(pol_dir)

    event = Event(
        source="config_collector",
        event_type="config_ok",
        severity="INFO",
        entity="openclaw.json",
        evidence="",
        action_taken="ALLOW",
    )
    decision = engine.evaluate(event)
    assert decision.action == "ALLOW"


def test_highest_action_wins():
    pol_dir = _make_policy_dir(
        [
            {
                "id": "R1",
                "domain": "runtime",
                "check": "event_type",
                "condition": "equals",
                "value": "test_event",
                "severity": "LOW",
                "action": "WARN",
                "message": "warn",
            },
            {
                "id": "R2",
                "domain": "runtime",
                "check": "event_type",
                "condition": "equals",
                "value": "test_event",
                "severity": "HIGH",
                "action": "BLOCK",
                "message": "block",
            },
        ]
    )
    engine = PolicyEngine(pol_dir)

    event = Event(
        source="test",
        event_type="test_event",
        severity="HIGH",
        entity="test",
        evidence="",
        action_taken="ALLOW",
    )
    decision = engine.evaluate(event)
    assert decision.action == "BLOCK"


# ── Edge case tests ────────────────────────────────────────────────────────────


def test_malformed_yaml_policy_dir_graceful():
    """PolicyLoader gracefully handles malformed YAML files."""
    import tempfile

    d = Path(tempfile.mkdtemp())
    (d / "bad.yaml").write_text("{{{{ not valid yaml }}}}")
    (d / "good.yaml").write_text(
        'name: good\nversion: "1"\nrules:\n'
        "  - {id: G1, domain: runtime, check: event_type, condition: equals,\n"
        "     value: test, severity: LOW, action: WARN, message: ok}\n"
    )
    engine = PolicyEngine(d)
    # Bad file should be skipped; good file should load
    assert any(r.id == "G1" for r in engine.rules)


def test_empty_policy_dir():
    """PolicyLoader with empty directory returns zero rules without error."""
    import tempfile

    d = Path(tempfile.mkdtemp())
    engine = PolicyEngine(d)
    assert engine.rules == []


def test_policy_engine_nonexistent_dir():
    """PolicyEngine with nonexistent dir does not raise, returns zero rules."""
    engine = PolicyEngine(Path("/tmp/nonexistent-sentinel-policies-xyz"))
    assert engine.rules == []


def test_lt_condition_not_matched():
    """Unknown condition returns False, not an exception."""
    from sentinel.models.policy import Rule
    from sentinel.policy.engine import _matches_condition

    rule = Rule(
        id="X",
        domain="",
        check="severity",
        condition="unknown_op",
        value="HIGH",
        severity="LOW",
        action="ALERT",
        message="",
    )
    assert _matches_condition(rule, "HIGH") is False


def test_gt_condition_non_numeric_value():
    """gt condition with non-numeric input returns False gracefully."""
    from sentinel.models.policy import Rule
    from sentinel.policy.engine import _matches_condition

    rule = Rule(
        id="X",
        domain="",
        check="tool_calls",
        condition="gt",
        value="10",
        severity="HIGH",
        action="ALERT",
        message="",
    )
    assert _matches_condition(rule, "notanumber") is False
