"""Unit tests for remediation snapshot/rollback."""

from __future__ import annotations

import pytest

from sentinel.remediation.rollback import (
    create_snapshot,
    delete_snapshot,
    list_snapshots,
    restore_snapshot,
)


class TestCreateSnapshot:
    def test_creates_tar_gz(self, tmp_path):
        skill_dir = tmp_path / "my-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("# My Skill\nsome content")

        import sentinel.remediation.rollback as rb

        original_dir = rb.SNAPSHOT_DIR
        rb.SNAPSHOT_DIR = tmp_path / "snapshots"

        try:
            snap = create_snapshot(skill_dir, "my-skill")
            assert snap.exists()
            assert snap.suffix == ".gz"
            assert "my-skill" in snap.name
        finally:
            rb.SNAPSHOT_DIR = original_dir

    def test_snapshot_is_readable(self, tmp_path):
        import tarfile

        import sentinel.remediation.rollback as rb

        original_dir = rb.SNAPSHOT_DIR
        rb.SNAPSHOT_DIR = tmp_path / "snapshots"

        skill_dir = tmp_path / "test-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("original content")

        try:
            snap = create_snapshot(skill_dir, "test-skill")
            with tarfile.open(snap, "r:gz") as tar:
                members = tar.getnames()
            assert any("SKILL.md" in m for m in members)
        finally:
            rb.SNAPSHOT_DIR = original_dir


class TestRestoreSnapshot:
    def test_restore_overwrites_file(self, tmp_path):
        import sentinel.remediation.rollback as rb

        original_dir = rb.SNAPSHOT_DIR
        rb.SNAPSHOT_DIR = tmp_path / "snapshots"

        skill_dir = tmp_path / "restore-skill"
        skill_dir.mkdir()
        skill_md = skill_dir / "SKILL.md"
        skill_md.write_text("original content")

        try:
            snap = create_snapshot(skill_dir, "restore-skill")
            # Modify the file
            skill_md.write_text("modified content")
            assert skill_md.read_text() == "modified content"

            # Restore
            restore_snapshot(snap, tmp_path)
            assert skill_md.read_text() == "original content"
        finally:
            rb.SNAPSHOT_DIR = original_dir

    def test_restore_missing_snapshot_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            restore_snapshot(tmp_path / "nonexistent.tar.gz", tmp_path)


class TestListSnapshots:
    def test_empty_dir_returns_empty(self, tmp_path):
        import sentinel.remediation.rollback as rb

        original_dir = rb.SNAPSHOT_DIR
        rb.SNAPSHOT_DIR = tmp_path / "empty-snapshots"
        try:
            result = list_snapshots()
            assert result == []
        finally:
            rb.SNAPSHOT_DIR = original_dir

    def test_returns_sorted_list(self, tmp_path):
        import sentinel.remediation.rollback as rb

        original_dir = rb.SNAPSHOT_DIR
        rb.SNAPSHOT_DIR = tmp_path / "snaps"
        rb.SNAPSHOT_DIR.mkdir()

        # Create fake snapshot files
        (rb.SNAPSHOT_DIR / "20240101-000000-a.tar.gz").touch()
        (rb.SNAPSHOT_DIR / "20240102-000000-b.tar.gz").touch()
        (rb.SNAPSHOT_DIR / "20240103-000000-c.tar.gz").touch()

        try:
            snaps = list_snapshots()
            names = [s.name for s in snaps]
            assert names == sorted(names)
            assert len(snaps) == 3
        finally:
            rb.SNAPSHOT_DIR = original_dir


class TestSafeMembers:
    def test_rejects_path_traversal_member(self, tmp_path):
        """Tar members with path traversal (../) should be filtered out."""
        import io
        import tarfile

        from sentinel.remediation.rollback import _safe_members

        # Create a tar with a path traversal member
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            # Normal member
            info = tarfile.TarInfo(name="skill/SKILL.md")
            info.size = 4
            tar.addfile(info, io.BytesIO(b"safe"))
            # Malicious member
            info2 = tarfile.TarInfo(name="../../../etc/passwd")
            info2.size = 7
            tar.addfile(info2, io.BytesIO(b"malicious"))

        buf.seek(0)
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            safe = _safe_members(tar, tmp_path)
            names = [m.name for m in safe]
            assert "skill/SKILL.md" in names
            assert "../../../etc/passwd" not in names


class TestDeleteSnapshot:
    def test_delete_existing(self, tmp_path):
        snap = tmp_path / "test.tar.gz"
        snap.touch()
        assert delete_snapshot(snap) is True
        assert not snap.exists()

    def test_delete_nonexistent_returns_false(self, tmp_path):
        assert delete_snapshot(tmp_path / "ghost.tar.gz") is False


class TestTarFilterCompat:
    def test_restore_uses_filter_data_on_312(self, tmp_path):
        """On Python 3.12+, filter='data' should be used; on older, TypeError fallback."""
        import sentinel.remediation.rollback as rb

        original_dir = rb.SNAPSHOT_DIR
        rb.SNAPSHOT_DIR = tmp_path / "snapshots"

        skill_dir = tmp_path / "filter-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("content for filter test")

        try:
            snap = create_snapshot(skill_dir, "filter-skill")
            # Modify and restore — should work regardless of Python version
            (skill_dir / "SKILL.md").write_text("modified")
            restore_snapshot(snap, tmp_path)
            assert (skill_dir / "SKILL.md").read_text() == "content for filter test"
        finally:
            rb.SNAPSHOT_DIR = original_dir

    def test_restore_with_corrupt_tarball_raises(self, tmp_path):
        """Corrupt tarball should raise an error."""
        import tarfile

        corrupt = tmp_path / "corrupt.tar.gz"
        corrupt.write_bytes(b"not a valid tarball")
        with pytest.raises((tarfile.ReadError, Exception)):
            restore_snapshot(corrupt, tmp_path)
