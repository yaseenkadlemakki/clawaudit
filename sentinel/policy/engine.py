"""Policy evaluation engine."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from sentinel.models.policy import PolicyDecision, Rule
from sentinel.policy.actions import resolve_action
from sentinel.policy.loader import PolicyLoader

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


def _get_event_value(event: Event, check: str) -> str:
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


def _get_finding_value(finding: Finding, check: str) -> str:
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


@dataclass
class ToolCallContext:
    """Context for a tool call evaluation."""

    tool: str
    params: dict
    skill_name: str | None = None
    skill_signed: bool = False
    skill_publisher: str | None = None
    skill_path: str | None = None
    session_id: str | None = None


def _extract_tool_call_value(ctx: ToolCallContext, check: str) -> str:
    """Extract the value to evaluate from a ToolCallContext."""
    if check == "tool":
        return ctx.tool
    if check.startswith("params."):
        key = check[len("params.") :]
        val = ctx.params.get(key)
        return str(val).lower() if val is not None else ""
    if check == "skill.name":
        return ctx.skill_name or ""
    if check == "skill.signed":
        return str(ctx.skill_signed).lower()
    if check == "skill.publisher":
        return ctx.skill_publisher or "null"
    if check == "skill.path":
        return ctx.skill_path or ""
    return ""


def _matches_condition_extended(rule: Rule, value: str) -> bool:
    """Extended matcher supporting matches/glob/starts_with/ends_with operators."""
    cond = rule.condition.lower()
    if cond == "matches":
        import re

        try:
            return bool(re.search(rule.value, value, re.IGNORECASE))
        except re.error:
            return False
    if cond == "glob":
        import fnmatch

        return fnmatch.fnmatch(value.lower(), rule.value.lower())
    if cond == "starts_with":
        return value.lower().startswith(rule.value.lower())
    if cond == "ends_with":
        return value.lower().endswith(rule.value.lower())
    return _matches_condition(rule, value)


class PolicyEngine:
    """Evaluates events and findings against loaded policies."""

    def __init__(self, policies_dir: Path) -> None:
        self.loader = PolicyLoader(policies_dir)
        self._rules: list[Rule] = []

    @classmethod
    def from_rules(cls, rules: list[Rule]) -> PolicyEngine:
        """Create engine from an explicit rule list (used by PolicySyncService)."""
        instance = cls.__new__(cls)
        instance.loader = None
        instance._rules = rules
        return instance

    def reload(self) -> None:
        """Hot-reload policies from disk."""
        if self.loader is not None:
            self.loader.reload()

    @property
    def rules(self) -> list[Rule]:
        if self.loader is not None:
            return self.loader.rules
        return self._rules

    def evaluate(self, event: Event) -> PolicyDecision:
        """Evaluate an event against all loaded policies."""
        matched: list[Rule] = []
        actions: list[str] = []

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

    def evaluate_finding(self, finding: Finding) -> PolicyDecision:
        """Evaluate a finding against all loaded policies."""
        matched: list[Rule] = []
        actions: list[str] = []

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
                return PolicyDecision(
                    action="ALERT", reason="Default: FAIL + HIGH/CRITICAL severity"
                )
            return PolicyDecision(action="ALLOW", reason="No matching rules")

        action = resolve_action(actions)
        reasons = [f"{r.id}: {r.message or r.check}" for r in matched]
        return PolicyDecision(
            action=action,
            matched_rules=matched,
            reason="; ".join(reasons),
            policy_ids=[r.id for r in matched],
        )

    def evaluate_tool_call(self, ctx: ToolCallContext) -> PolicyDecision:
        """Evaluate a tool call against all loaded tool_call-domain policies.

        Evaluates rules in priority order (highest priority first).
        Returns the highest-priority matching action.
        """
        matched: list[Rule] = []
        actions: list[str] = []

        # Sort by priority descending; filter to enabled rules only
        rules = sorted(
            [r for r in self.rules if getattr(r, "enabled", True)],
            key=lambda r: getattr(r, "priority", 0),
            reverse=True,
        )

        for rule in rules:
            if rule.domain not in ("tool_call", "*"):
                continue
            value = _extract_tool_call_value(ctx, rule.check)
            if _matches_condition_extended(rule, value):
                matched.append(rule)
                actions.append(rule.action)

        if not matched:
            return PolicyDecision(action="ALLOW", reason="No matching tool_call rules")

        action = resolve_action(actions)
        return PolicyDecision(
            action=action,
            matched_rules=matched,
            reason="; ".join(f"{r.id}: {r.message or r.check}" for r in matched),
            policy_ids=[r.id for r in matched],
        )
