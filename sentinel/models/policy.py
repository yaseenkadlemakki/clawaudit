"""Policy data models."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


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


@dataclass
class Policy:
    """A collection of rules from a policy YAML file."""

    name: str
    version: str
    rules: List[Rule] = field(default_factory=list)
    description: str = ""


@dataclass
class PolicyDecision:
    """Result of evaluating an event or finding against policies."""

    action: str  # ALLOW / WARN / ALERT / BLOCK
    matched_rules: List[Rule] = field(default_factory=list)
    reason: str = ""
    policy_ids: List[str] = field(default_factory=list)
