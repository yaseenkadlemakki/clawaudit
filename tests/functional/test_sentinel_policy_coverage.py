"""Functional tests — Sentinel policy consistency and cross-system alignment."""

from pathlib import Path

import pytest
import yaml

# ── fixtures ──────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).parent.parent.parent
DEFAULT_POLICY_FILE = REPO_ROOT / "sentinel" / "policies" / "default.yaml"


def _load_default_policies() -> dict:
    return yaml.safe_load(DEFAULT_POLICY_FILE.read_text())


def _default_rules() -> list:
    return _load_default_policies().get("rules", [])


# ── policy file structure ─────────────────────────────────────────────────────


@pytest.mark.functional
class TestDefaultPolicyStructure:
    def test_default_policy_file_exists(self):
        assert DEFAULT_POLICY_FILE.exists(), "sentinel/policies/default.yaml is missing"

    def test_policy_has_name_and_version(self):
        data = _load_default_policies()
        assert data.get("name"), "Policy file must have a 'name' field"
        assert data.get("version"), "Policy file must have a 'version' field"

    def test_policy_has_rules_list(self):
        data = _load_default_policies()
        assert isinstance(data.get("rules"), list), "Policy must have a 'rules' list"
        assert len(data["rules"]) > 0, "Policy must have at least one rule"

    def test_all_rule_ids_unique(self):
        ids = [r["id"] for r in _default_rules()]
        assert len(ids) == len(set(ids)), (
            f"Duplicate policy IDs: {[x for x in ids if ids.count(x) > 1]}"
        )

    def test_all_rules_have_required_fields(self):
        required = ("id", "domain", "check", "condition", "value", "severity", "action")
        for rule in _default_rules():
            for field in required:
                assert field in rule, f"Rule {rule.get('id')} missing field: {field}"

    def test_all_severities_valid(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for rule in _default_rules():
            assert rule["severity"] in valid, (
                f"Rule {rule['id']} has invalid severity: {rule['severity']}"
            )

    def test_all_actions_valid(self):
        valid = {"ALERT", "BLOCK", "WARN", "ALLOW"}
        for rule in _default_rules():
            action = rule["action"].upper()
            assert action in valid, f"Rule {rule['id']} has invalid action: {action}"

    def test_all_conditions_known(self):
        known = {
            "equals",
            "not_equals",
            "contains",
            "not_contains",
            "gt",
            "gte",
            "in",
            "not_in",
            "exists",
            "not_exists",
        }
        for rule in _default_rules():
            assert rule["condition"] in known, (
                f"Rule {rule['id']} has unknown condition: {rule['condition']}"
            )


# ── policy ↔ collector alignment ──────────────────────────────────────────────


@pytest.mark.functional
class TestPolicyCollectorAlignment:
    def test_pol_007_threshold_matches_session_collector(self):
        """POL-007 rate limit must match SessionCollector.TOOL_CALL_LIMIT_PER_MINUTE."""
        from sentinel.collector.session_collector import TOOL_CALL_LIMIT_PER_MINUTE

        pol_007 = next(r for r in _default_rules() if r["id"] == "POL-007")
        assert int(pol_007["value"]) == TOOL_CALL_LIMIT_PER_MINUTE, (
            f"POL-007 value ({pol_007['value']}) != TOOL_CALL_LIMIT_PER_MINUTE ({TOOL_CALL_LIMIT_PER_MINUTE})"
        )

    def test_pol_008_event_type_matches_cron_collector(self):
        """POL-008 must match the event_type emitted by CronCollector."""
        pol_008 = next(r for r in _default_rules() if r["id"] == "POL-008")
        assert pol_008["value"] == "unauthorized_cron"

    def test_pol_009_event_type_matches_skill_collector(self):
        """POL-009 must match the event_type emitted by SkillCollector."""
        pol_009 = next(r for r in _default_rules() if r["id"] == "POL-009")
        assert pol_009["value"] == "new_skill"

    def test_pol_010_event_type_matches_config_collector(self):
        """POL-010 must match the event_type emitted by ConfigCollector."""
        pol_010 = next(r for r in _default_rules() if r["id"] == "POL-010")
        assert pol_010["value"] == "config_drift"

    def test_pol_011_event_type_matches_session_collector_code_block(self):
        """POL-011 must match the event_type emitted by SessionCollector for code-block detection."""
        pol_011 = next(r for r in _default_rules() if r["id"] == "POL-011")
        assert pol_011["value"] == "code_block_as_command"
        assert pol_011["action"] == "BLOCK"
        assert pol_011["severity"] == "HIGH"

    def test_all_policy_ids_patterned_correctly(self):
        """All rule IDs follow POL-NNN format."""
        import re

        pattern = re.compile(r"^POL-\d{3}$")
        for rule in _default_rules():
            assert pattern.match(rule["id"]), (
                f"Rule ID '{rule['id']}' does not follow POL-NNN format"
            )


# ── policy engine loads default policies ─────────────────────────────────────


@pytest.mark.functional
class TestPolicyEngineLoadDefault:
    def test_engine_loads_all_default_rules(self):
        from sentinel.policy.engine import PolicyEngine

        engine = PolicyEngine(DEFAULT_POLICY_FILE.parent)
        assert len(engine.rules) == len(_default_rules()), (
            f"Engine loaded {len(engine.rules)} rules, expected {len(_default_rules())}"
        )

    def test_engine_evaluates_runaway_event_using_default_policies(self):
        from sentinel.models.event import Event
        from sentinel.policy.engine import PolicyEngine

        engine = PolicyEngine(DEFAULT_POLICY_FILE.parent)
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
        assert "POL-007" in decision.policy_ids

    def test_engine_evaluates_cron_event_using_default_policies(self):
        from sentinel.models.event import Event
        from sentinel.policy.engine import PolicyEngine

        engine = PolicyEngine(DEFAULT_POLICY_FILE.parent)
        event = Event(
            source="cron_collector",
            event_type="unauthorized_cron",
            severity="HIGH",
            entity="evil-cron",
            evidence="new_cron_id=evil-cron",
            action_taken="ALLOW",
        )
        decision = engine.evaluate(event)
        assert decision.action == "ALERT"
        assert "POL-008" in decision.policy_ids

    def test_engine_evaluates_code_block_event_using_default_policies(self):
        from sentinel.models.event import Event
        from sentinel.policy.engine import PolicyEngine

        engine = PolicyEngine(DEFAULT_POLICY_FILE.parent)
        event = Event(
            source="session_collector",
            event_type="code_block_as_command",
            severity="HIGH",
            entity="session-xyz",
            evidence="language=python confidence=HIGH tokens=python_from_import,python_class",
            action_taken="ALLOW",
        )
        decision = engine.evaluate(event)
        assert decision.action == "BLOCK"
        assert "POL-011" in decision.policy_ids

    def test_default_policy_evaluates_finding_with_fail_result(self):
        from sentinel.models.finding import Finding
        from sentinel.policy.engine import PolicyEngine

        engine = PolicyEngine(DEFAULT_POLICY_FILE.parent)
        finding = Finding(
            check_id="CONF-01",
            domain="config",
            title="Discord open",
            description="",
            severity="CRITICAL",
            result="FAIL",
            evidence="groupPolicy=open",
            location="openclaw.json",
            remediation="",
            run_id="r",
        )
        decision = engine.evaluate_finding(finding)
        # Default rule: FAIL + HIGH/CRITICAL → ALERT
        assert decision.action in ("ALERT", "BLOCK")


# ── renderer output is parseable ─────────────────────────────────────────────


@pytest.mark.functional
class TestRendererOutputFormat:
    def _findings(self, n=3):
        from sentinel.models.finding import Finding

        return [
            Finding(
                check_id=f"C-{i}",
                domain="config",
                title=f"F{i}",
                description="d",
                severity="HIGH",
                result="FAIL",
                evidence="e",
                location="loc",
                remediation="r",
                run_id="r1",
            )
            for i in range(n)
        ]

    def test_markdown_output_has_h1_header(self):
        from sentinel.reporter.renderer import render_markdown

        md = render_markdown(self._findings(), "run-001")
        assert md.startswith("#")

    def test_markdown_output_has_findings_section(self):
        from sentinel.reporter.renderer import render_markdown

        md = render_markdown(self._findings(), "run-001")
        assert "## Findings" in md

    def test_json_output_schema(self):
        import json

        from sentinel.reporter.renderer import render_json

        data = json.loads(render_json(self._findings(2), "run-001"))
        assert "run_id" in data
        assert "findings" in data
        assert "total" in data
        assert data["total"] == 2

    def test_finding_severity_order_in_markdown(self):
        from sentinel.models.finding import Finding
        from sentinel.reporter.renderer import render_markdown

        findings = [
            Finding(
                check_id="LOW-01",
                domain="config",
                title="Low finding",
                description="",
                severity="LOW",
                result="FAIL",
                evidence="",
                location="",
                remediation="",
                run_id="r",
            ),
            Finding(
                check_id="CRIT-01",
                domain="config",
                title="Critical finding",
                description="",
                severity="CRITICAL",
                result="FAIL",
                evidence="",
                location="",
                remediation="",
                run_id="r",
            ),
        ]
        md = render_markdown(findings, "r")
        # CRITICAL should appear before LOW
        assert md.index("CRIT-01") < md.index("LOW-01")
