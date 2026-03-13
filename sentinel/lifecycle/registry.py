"""JSON-backed skill registry for tracking installed skills."""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from sentinel.lifecycle import PROTECTED_PATHS

try:
    import fcntl

    _HAS_FCNTL = True
except ImportError:  # Windows
    _HAS_FCNTL = False

logger = logging.getLogger(__name__)

# In-process lock as a fallback (and to serialise within the same process)
_REGISTRY_LOCK = threading.Lock()


@dataclass
class SkillRecord:
    """A single registered skill entry."""

    name: str
    path: str  # absolute path to skill dir
    source: str  # "local", "system", "clawhub", or URL
    version: str  # from SKILL.md metadata or "unknown"
    installed_at: str  # ISO8601
    enabled: bool  # True if SKILL.md exists (not .disabled)
    content_hash: str = ""  # SHA-256 of all files for integrity verification

    @classmethod
    def from_dict(cls, data: dict) -> SkillRecord:
        return cls(
            **{
                k: data.get(k, "") if k == "content_hash" else data[k]
                for k in cls.__dataclass_fields__
                if k in data or k == "content_hash"
            }
        )


class SkillRegistry:
    """Manages ~/.openclaw/sentinel/skill-registry.json."""

    REGISTRY_PATH = Path.home() / ".openclaw" / "sentinel" / "skill-registry.json"

    def __init__(self, registry_path: Path | None = None) -> None:
        self._path = registry_path or self.REGISTRY_PATH

    def load(self) -> dict[str, SkillRecord]:
        """Load the registry from disk. Returns empty dict if file missing."""
        if not self._path.exists():
            return {}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return {k: SkillRecord.from_dict(v) for k, v in data.items()}
        except (json.JSONDecodeError, KeyError, TypeError):
            logger.warning("Corrupt registry at %s — starting fresh", self._path)
            return {}

    def save(self, records: dict[str, SkillRecord]) -> None:
        """Atomically write registry to disk (tmp + rename)."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        payload = {k: asdict(v) for k, v in records.items()}
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self._path)

    @contextmanager
    def _locked(self) -> Generator[None, None, None]:
        """Acquire in-process + optional OS-level file lock for safe read-modify-write."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        lock_file = self._path.with_suffix(".lock")
        with _REGISTRY_LOCK:
            if _HAS_FCNTL:
                fh = lock_file.open("a+")
                try:
                    fcntl.flock(fh, fcntl.LOCK_EX)
                    try:
                        yield
                    finally:
                        fcntl.flock(fh, fcntl.LOCK_UN)
                finally:
                    fh.close()
            else:
                yield

    def register(self, record: SkillRecord) -> None:
        """Add or update a skill in the registry (atomic, locked)."""
        with self._locked():
            records = self.load()
            records[record.name] = record
            self.save(records)

    def unregister(self, name: str) -> None:
        """Remove a skill from the registry (atomic, locked)."""
        with self._locked():
            records = self.load()
            records.pop(name, None)
            self.save(records)

    def get(self, name: str) -> SkillRecord | None:
        """Retrieve a single skill record by name."""
        return self.load().get(name)

    def list_all(self) -> list[SkillRecord]:
        """Return all registered skills."""
        return list(self.load().values())

    def sync(self, skills_dirs: list[Path]) -> None:
        """Reconcile registry with the filesystem.

        - Skills found on disk but not in registry are added.
        - Skills in registry but missing from disk are removed.
        """
        records = self.load()

        # Collect all skill dirs that have SKILL.md or SKILL.md.disabled
        found: dict[str, Path] = {}
        for d in skills_dirs:
            if not d.exists():
                continue
            # Build list of directories to scan: the dir itself, plus a
            # ``skills/`` subdirectory if one exists (defensive fallback for
            # configs that point at a workspace root instead of its skills/ child).
            scan_dirs = [d]
            skills_sub = d / "skills"
            if skills_sub.is_dir():
                scan_dirs.append(skills_sub)
            for scan_dir in scan_dirs:
                for child in scan_dir.iterdir():
                    if not child.is_dir():
                        continue
                    skill_md = child / "SKILL.md"
                    skill_md_disabled = child / "SKILL.md.disabled"
                    if skill_md.exists() or skill_md_disabled.exists():
                        found[child.name] = child

        # Add missing / refresh source for existing entries
        for name, path in found.items():
            resolved = path.resolve()
            computed_source = (
                "system" if any(resolved.is_relative_to(p) for p in PROTECTED_PATHS) else "local"
            )
            if name not in records:
                enabled = (path / "SKILL.md").exists()
                records[name] = SkillRecord(
                    name=name,
                    path=str(path),
                    source=computed_source,
                    version="unknown",
                    installed_at=datetime.now(timezone.utc).isoformat(),  # noqa: UP017
                    enabled=enabled,
                )
            elif records[name].source in ("local", "system"):
                # Recompute source for entries that carry a path-derived value.
                # This migrates registries written before PROTECTED_PATHS was
                # checked, where homebrew skills were incorrectly tagged "local".
                records[name].source = computed_source

        # Remove stale
        stale = [n for n in records if n not in found]
        for n in stale:
            del records[n]

        self.save(records)
