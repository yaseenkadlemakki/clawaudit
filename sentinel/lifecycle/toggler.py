"""Enable/disable skills by renaming SKILL.md."""

from __future__ import annotations

import logging
from pathlib import Path

from sentinel.lifecycle.registry import SkillRegistry

logger = logging.getLogger(__name__)

PROTECTED_PATHS = [
    Path("/opt/homebrew/lib/node_modules/openclaw/skills"),
    Path("/usr/local/lib/node_modules/openclaw/skills"),
    Path("/usr/lib/node_modules/openclaw/skills"),
]


class SkillToggler:
    """Toggle skills between enabled and disabled states."""

    def __init__(self, registry: SkillRegistry) -> None:
        self._registry = registry

    def disable(self, name: str) -> None:
        """Disable a skill by renaming SKILL.md -> SKILL.md.disabled.

        Raises:
            FileNotFoundError: If the skill is not in the registry.
            PermissionError: If the skill is in a protected path.
            ValueError: If the skill is already disabled.
        """
        record = self._registry.get(name)
        if record is None:
            raise FileNotFoundError(f"Skill '{name}' not found in registry")

        skill_path = Path(record.path)
        if self.is_protected(skill_path):
            raise PermissionError(f"Skill '{name}' is in a protected path and cannot be disabled")

        skill_md = skill_path / "SKILL.md"
        if not skill_md.exists():
            raise ValueError(f"Skill '{name}' is already disabled")

        skill_md.rename(skill_path / "SKILL.md.disabled")
        record.enabled = False
        self._registry.register(record)
        logger.info("Disabled skill '%s'", name)

    def enable(self, name: str) -> None:
        """Enable a skill by renaming SKILL.md.disabled -> SKILL.md.

        Raises:
            FileNotFoundError: If the skill is not in the registry.
            PermissionError: If the skill is in a protected path.
            ValueError: If the skill is already enabled.
        """
        record = self._registry.get(name)
        if record is None:
            raise FileNotFoundError(f"Skill '{name}' not found in registry")

        skill_path = Path(record.path)
        if self.is_protected(skill_path):
            raise PermissionError(f"Skill '{name}' is in a protected path and cannot be enabled")

        disabled_md = skill_path / "SKILL.md.disabled"
        if not disabled_md.exists():
            raise ValueError(f"Skill '{name}' is already enabled")

        disabled_md.rename(skill_path / "SKILL.md")
        record.enabled = True
        self._registry.register(record)
        logger.info("Enabled skill '%s'", name)

    def is_protected(self, skill_path: Path) -> bool:
        """Check if a skill resides under a protected system path."""
        resolved = skill_path.resolve()
        for protected in PROTECTED_PATHS:
            try:
                if resolved.is_relative_to(protected):
                    return True
            except (ValueError, TypeError):
                continue
        return False

    def get_status(self, skill_path: Path) -> bool:
        """Return True if the skill is enabled (SKILL.md exists), False if disabled."""
        return (skill_path / "SKILL.md").exists()
