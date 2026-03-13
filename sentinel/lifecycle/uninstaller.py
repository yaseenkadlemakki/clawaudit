"""Uninstall skills by moving to trash (never delete)."""

from __future__ import annotations

import logging
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from sentinel.lifecycle import PROTECTED_PATHS
from sentinel.lifecycle.registry import SkillRecord, SkillRegistry

# Trash dir name format: <skill-name>-<YYYYMMDD>-<HHMMSS>
# Use a regex to reliably extract skill name even when name contains hyphens.
_TRASH_NAME_RE = re.compile(r"^(.+)-(\d{8})-(\d{6})$")

logger = logging.getLogger(__name__)

TRASH_DIR = Path.home() / ".openclaw" / "sentinel" / "skill-trash"


class SkillUninstaller:
    """Move skill directories to trash and manage recovery."""

    def __init__(self, registry: SkillRegistry) -> None:
        self._registry = registry

    def uninstall(self, name: str) -> Path:
        """Move a skill to the trash directory.

        Raises:
            FileNotFoundError: If skill is not in registry.
            PermissionError: If skill is in a protected path.

        Returns:
            Path to the trash directory for this skill.
        """
        record = self._registry.get(name)
        if record is None:
            raise FileNotFoundError(f"Skill '{name}' not found in registry")

        skill_path = Path(record.path)
        if self._is_protected(skill_path):
            raise PermissionError(
                f"Skill '{name}' is in a protected path and cannot be uninstalled"
            )

        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")  # noqa: UP017
        trash_dest = TRASH_DIR / f"{name}-{ts}"
        TRASH_DIR.mkdir(parents=True, exist_ok=True)

        shutil.move(str(skill_path), str(trash_dest))
        self._registry.unregister(name)
        logger.info("Uninstalled skill '%s' → %s", name, trash_dest)
        return trash_dest

    def list_trash(self) -> list[Path]:
        """Return all items in the trash directory."""
        if not TRASH_DIR.exists():
            return []
        return sorted(p for p in TRASH_DIR.iterdir() if p.is_dir())

    def recover(self, trash_name: str, skills_dir: Path) -> SkillRecord:
        """Recover a skill from trash back into the skills directory.

        Raises:
            FileNotFoundError: If trash entry doesn't exist.
        """
        trash_path = TRASH_DIR / trash_name
        if not trash_path.exists():
            raise FileNotFoundError(f"Trash entry '{trash_name}' not found")

        # Extract original skill name (strip timestamp suffix).
        # Format: <name>-<YYYYMMDD>-<HHMMSS>
        # Use regex so hyphenated skill names (e.g. "my-cool-skill") are handled
        # correctly — rsplit("-", 2) would only split the last 2 hyphens and
        # would mangle names that themselves contain hyphens. (Fixes #21)
        match = _TRASH_NAME_RE.match(trash_name)
        if match:
            skill_name = match.group(1)
        else:
            skill_name = trash_name

        dest = skills_dir / skill_name
        skills_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(trash_path), str(dest))

        enabled = (dest / "SKILL.md").exists()
        record = SkillRecord(
            name=skill_name,
            path=str(dest),
            source="recovered",
            version="unknown",
            installed_at=datetime.now(timezone.utc).isoformat(),  # noqa: UP017
            enabled=enabled,
        )
        self._registry.register(record)
        logger.info("Recovered skill '%s' from trash → %s", skill_name, dest)
        return record

    def _is_protected(self, skill_path: Path) -> bool:
        """Check if a skill resides under a protected system path."""
        resolved = skill_path.resolve()
        for protected in PROTECTED_PATHS:
            try:
                if resolved.is_relative_to(protected):
                    return True
            except (ValueError, TypeError):
                continue
        return False
