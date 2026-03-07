"""YAML policy loader with hot-reload support."""

from __future__ import annotations

from pathlib import Path

import yaml

from sentinel.models.policy import Policy, Rule


def _parse_rule(data: dict) -> Rule:
    """Parse a rule dict into a Rule object."""
    return Rule(
        id=data.get("id", ""),
        domain=data.get("domain", ""),
        check=data.get("check", ""),
        condition=data.get("condition", "equals"),
        value=str(data.get("value", "")),
        severity=data.get("severity", "MEDIUM"),
        action=data.get("action", "alert").upper(),
        message=data.get("message", ""),
        auto_remediate=bool(data.get("auto_remediate", False)),
        description=data.get("description", ""),
    )


def load_policy_file(path: Path) -> Policy | None:
    """Load a single YAML policy file."""
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except (OSError, yaml.YAMLError):
        return None

    rules = [_parse_rule(r) for r in data.get("rules", [])]
    return Policy(
        name=data.get("name", path.stem),
        version=str(data.get("version", "1")),
        rules=rules,
        description=data.get("description", ""),
    )


class PolicyLoader:
    """Loads policies from a directory, supporting hot-reload."""

    def __init__(self, policies_dir: Path) -> None:
        self._dir = policies_dir
        self._policies: list[Policy] = []
        self._load_all()

    def _load_all(self) -> None:
        """Load all YAML files in the policies directory."""
        self._policies = []
        if not self._dir.exists():
            return
        for p in sorted(self._dir.glob("*.yaml")):
            policy = load_policy_file(p)
            if policy:
                self._policies.append(policy)

    def reload(self) -> None:
        """Reload all policies from disk."""
        self._load_all()

    @property
    def policies(self) -> list[Policy]:
        return list(self._policies)

    @property
    def rules(self) -> list[Rule]:
        return [r for p in self._policies for r in p.rules]
