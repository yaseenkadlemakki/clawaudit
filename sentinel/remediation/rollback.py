"""Snapshot and restore SKILL.md files for rollback support."""

from __future__ import annotations

import logging
import tarfile
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

SNAPSHOT_DIR = Path.home() / ".openclaw" / "sentinel" / "snapshots"


def create_snapshot(skill_path: Path, skill_name: str) -> Path:
    """Create a compressed snapshot of a skill directory.

    Args:
        skill_path: Path to the skill directory.
        skill_name: Name used in the snapshot filename.

    Returns:
        Path to the created snapshot file.
    """
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")  # noqa: UP017
    snapshot = SNAPSHOT_DIR / f"{ts}-{skill_name}.tar.gz"
    with tarfile.open(snapshot, "w:gz") as tar:
        tar.add(skill_path, arcname=skill_name)
    logger.info("Snapshot created: %s", snapshot)
    return snapshot


def restore_snapshot(snapshot_path: Path, target_parent: Path) -> None:
    """Restore a skill from a snapshot.

    Args:
        snapshot_path: Path to the .tar.gz snapshot.
        target_parent: Parent directory to extract into.
    """
    if not snapshot_path.exists():
        raise FileNotFoundError(f"Snapshot not found: {snapshot_path}")
    with tarfile.open(snapshot_path, "r:gz") as tar:
        tar.extractall(path=target_parent)  # noqa: S202 — trusted snapshots only
    logger.info("Snapshot restored: %s → %s", snapshot_path, target_parent)


def list_snapshots() -> list[Path]:
    """Return all snapshots sorted oldest → newest."""
    if not SNAPSHOT_DIR.exists():
        return []
    return sorted(SNAPSHOT_DIR.glob("*.tar.gz"))


def delete_snapshot(snapshot_path: Path) -> bool:
    """Delete a snapshot file. Returns True if deleted."""
    if snapshot_path.exists():
        snapshot_path.unlink()
        return True
    return False
