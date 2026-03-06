"""Policy evaluation engine."""
from __future__ import annotations

from pathlib import Path
from typing import List, TYPE_CHECKING

from sentinel.models.policy import PolicyDecision, Rule
from sentinel.policy.loader import PolicyLoader
from sentinel.policy.actions import resolve_action

if TYPE_CHECKING:
    from sentinel.models.event import Event
    from sentinel.models.finding import Finding


SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _matches_condition(rule: Rule, value: str) -> bool:
    """Test if a value matches a rule condition."""
    cond = rule.condition.lower()
    rule_val = rule.value

    if cond == "equals":
        return value == rule_val
    if cond == "not_equals":
        return value != rule_val
    if cond == "contains":
        return rule_val in value
    if cond == "not_contains":
        return rule_val not in value
    if cond == "gt":
        try:
            return float(value) > float(rule_val)
        except (ValueError, TypeError):
            return False
    if cond == "gte":
        try:
            return float(value) >= float(rule_val)
        except (ValueError, TypeError):
            return False
    if cond == "exists":
        return value not in ("", None, "None")
    if cond == "not_exists":
        return value in ("", None, "None")
    if cond == "in":
        options = [v.strip() for v in rule_val.split(",")]
        return value in options
    if cond == "not_in":
        options = [v.strip() for v in rule_val.split(",")]
        return value not in options
    return False


def _get_event_value(event: "Event", check: str) -> str:
    """Extract the value to check from an event."""
    # Try event attributes first
    if check == "event_type":
        return event.event_type
    if check == "severity":
        return event.severity
    if check == "source":
        return event.source
    if check == "entity":
        return event.entity
    if check == "tool_calls_per_minute":
        # Parse from evidence
        import re
        m = re.search(r"tool_calls_per_minute=(\d+)", event.evidence)
        return m.group(1) if m else "0"
    # Generic: look in evidence for key=value
    import re
    pattern = re.compile(rf"{re.escape(check)}=([^\s,]+)")
    m = pattern.search(event.evidence)
    return m.group(1) if m else ""


def _get_finding_value(finding: "Finding", check: str) -> str:
    """Extract the value to check from a finding."""
    mapping = {
        "check_id": finding.check_id,
        "domain": finding.domain,
        "severity": finding.severity,
        "result": finding.result,
        "evidence": finding.evidence,
        "location": finding.location,
    }
    return mapping.get(check, "")


class PolicyEngine:
    """Evaluates events and findings against loaded policies."""

    def __init__(self, policies_dir: Path) -> None:
        self.loader = PolicyLoader(policies_dir)

    def reload(self) -> None:
        """Hot-reload policies from disk."""
        self.loader.reload()

    @property
    def rules(self) -> List[Rule]:
        return self.loader.rules

    def evaluate(self, event: "Event") -> PolicyDecision:
        """Evaluate an event against all loaded policies."""
        matched: List[Rule] = []
        actions: List[str] = []

        for rule in self.rules:
            # When the rule check is "event_type", match against event_type regardless of domain
            if rule.check == "event_type":
                pass  # domain filtering skipped; match by check value below
            elif rule.domain not in (event.source, event.event_type, "runtime", "*", ""):
                continue

            value = _get_event_value(event, rule.check)
            if _matches_condition(rule, value):
                matched.append(rule)
                actions.append(rule.action)

        if not matched:
            return PolicyDecision(action="ALLOW", reason="No matching rules")

        action = resolve_action(actions)
        reasons = [f"{r.id}: {r.message or r.check}" for r in matched]
        return PolicyDecision(
            action=action,
            matched_rules=matched,
            reason="; ".join(reasons),
            policy_ids=[r.id for r in matched],
        )

    def evaluate_finding(self, finding: "Finding") -> PolicyDecision:
        """Evaluate a finding against all loaded policies."""
        matched: List[Rule] = []
        actions: List[str] = []

        for rule in self.rules:
            if rule.domain and rule.domain not in (finding.domain, "config", "*"):
                if rule.domain != finding.domain:
                    continue
            value = _get_finding_value(finding, rule.check)
            if not value:
                # Match by severity threshold
                if rule.check == "severity":
                    value = finding.severity
                else:
                    continue
            if _matches_condition(rule, value):
                matched.append(rule)
                actions.append(rule.action)

        if not matched:
            # Default: alert on FAIL findings with HIGH/CRITICAL severity
            sev_ord = SEVERITY_ORDER.get(finding.severity, 0)
            if finding.result == "FAIL" and sev_ord >= 3:
                return PolicyDecision(action="ALERT", reason="Default: FAIL + HIGH/CRITICAL severity")
            return PolicyDecision(action="ALLOW", reason="No matching rules")

        action = resolve_action(actions)
        reasons = [f"{r.id}: {r.message or r.check}" for r in matched]
        return PolicyDecision(
            action=action,
            matched_rules=matched,
            reason="; ".join(reasons),
            policy_ids=[r.id for r in matched],
        )
