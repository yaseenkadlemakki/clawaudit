"""Policy data models."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Rule:
    """A single policy rule."""

    id: str
    domain: str
    check: str
    condition: str
    value: str
    severity: str
    action: str
    message: str
    auto_remediate: bool = False
    description: str = ""
    # Phase 8 extensions
    enabled: bool = True
    builtin: bool = False
    tags: list[str] = field(default_factory=list)
    priority: int = 0


@dataclass
class Policy:
    """A collection of rules from a policy YAML file."""

    name: str
    version: str
    rules: list[Rule] = field(default_factory=list)
    description: str = ""


@dataclass
class PolicyDecision:
    """Result of evaluating an event or finding against policies.

    action: ALLOW / WARN / ALERT / BLOCK / QUARANTINE
    """

    action: str  # ALLOW / WARN / ALERT / BLOCK / QUARANTINE
    matched_rules: list[Rule] = field(default_factory=list)
    reason: str = ""
    policy_ids: list[str] = field(default_factory=list)
