"""Unit tests for remediation strategies."""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.remediation.actions import ActionType
from sentinel.remediation.strategies import shell_access, secrets, permissions


class TestShellAccessStrategy:
    def _write_skill(self, tmp_path: Path, content: str) -> Path:
        skill_dir = tmp_path / "test-skill"
        skill_dir.mkdir(exist_ok=True)
        (skill_dir / "SKILL.md").write_text(content)
        return skill_dir

    def test_detects_pty_true(self, tmp_path):
        skill_dir = self._write_skill(tmp_path, "---\nname: test\n---\n\nexec:\n  pty: true\n")
        proposal = shell_access.propose("test-skill", skill_dir, "find-1")
        assert proposal is not None
        assert proposal.check_id == "ADV-001"
        assert proposal.action_type == ActionType.RESTRICT_SHELL
        assert "pty: false" in proposal.diff_preview

    def test_detects_security_full(self, tmp_path):
        skill_dir = self._write_skill(tmp_path, "---\nname: test\n---\nsecurity: full\n")
        proposal = shell_access.propose("test-skill", skill_dir, "find-1")
        assert proposal is not None
        assert "allowlist" in proposal.diff_preview

    def test_clean_skill_returns_none(self, tmp_path):
        skill_dir = self._write_skill(tmp_path, "---\nname: safe-skill\n---\n\nDoes safe things.\n")
        proposal = shell_access.propose("safe-skill", skill_dir, "find-1")
        assert proposal is None

    def test_missing_skill_md_returns_none(self, tmp_path):
        skill_dir = tmp_path / "no-md"
        skill_dir.mkdir()
        proposal = shell_access.propose("no-md", skill_dir, "find-1")
        assert proposal is None

    def test_proposal_has_impact(self, tmp_path):
        skill_dir = self._write_skill(tmp_path, "pty: true\n")
        proposal = shell_access.propose("test-skill", skill_dir, "find-1")
        assert proposal is not None
        assert len(proposal.impact) > 0

    def test_apply_patch_modifies_file(self, tmp_path):
        skill_dir = self._write_skill(tmp_path, "exec:\n  pty: true\n  security: full\n")
        shell_access.apply_patch(skill_dir)
        content = (skill_dir / "SKILL.md").read_text()
        assert "pty: false" in content
        assert "allowlist" in content

    def test_apply_patch_atomic_no_tmp_left(self, tmp_path):
        skill_dir = self._write_skill(tmp_path, "pty: true\n")
        shell_access.apply_patch(skill_dir)
        assert not (skill_dir / "SKILL.tmp").exists()


class TestSecretsStrategy:
    def _write_skill(self, tmp_path: Path, content: str) -> Path:
        skill_dir = tmp_path / "secret-skill"
        skill_dir.mkdir(exist_ok=True)
        (skill_dir / "SKILL.md").write_text(content)
        return skill_dir

    def test_detects_anthropic_key(self, tmp_path):
        skill_dir = self._write_skill(
            tmp_path, "Set the key: sk-ant-api123456789abcdefghij\n"
        )
        proposal = secrets.propose("secret-skill", skill_dir, "find-2")
        assert proposal is not None
        assert proposal.check_id == "ADV-005"
        assert proposal.action_type == ActionType.REDACT_SECRET
        assert "[REDACTED]" in proposal.diff_preview

    def test_detects_generic_api_key(self, tmp_path):
        skill_dir = self._write_skill(tmp_path, "api_key = 'supersecretpassword123456'\n")
        proposal = secrets.propose("secret-skill", skill_dir, "find-2")
        assert proposal is not None

    def test_clean_skill_returns_none(self, tmp_path):
        skill_dir = self._write_skill(tmp_path, "---\nname: clean\n---\nNo secrets here.\n")
        proposal = secrets.propose("clean-skill", skill_dir, "find-2")
        assert proposal is None

    def test_missing_skill_md_returns_none(self, tmp_path):
        skill_dir = tmp_path / "no-md"
        skill_dir.mkdir()
        proposal = secrets.propose("no-md", skill_dir, "find-2")
        assert proposal is None

    def test_apply_patch_redacts_key(self, tmp_path):
        skill_dir = self._write_skill(
            tmp_path, "token: sk-ant-api123456789abcdefghij\n"
        )
        secrets.apply_patch(skill_dir)
        content = (skill_dir / "SKILL.md").read_text()
        assert "[REDACTED]" in content
        assert "sk-ant" not in content

    def test_proposal_impact_mentions_rotation(self, tmp_path):
        skill_dir = self._write_skill(tmp_path, "api_key = 'mykey12345678901234'\n")
        proposal = secrets.propose("secret-skill", skill_dir, "find-2")
        assert proposal is not None
        impact_text = " ".join(proposal.impact).lower()
        assert "rotat" in impact_text


class TestPermissionsStrategy:
    def _write_skill(self, tmp_path: Path, content: str) -> Path:
        skill_dir = tmp_path / "perm-skill"
        skill_dir.mkdir(exist_ok=True)
        (skill_dir / "SKILL.md").write_text(content)
        return skill_dir

    def test_detects_wildcard_tools(self, tmp_path):
        skill_dir = self._write_skill(tmp_path, "allowed-tools: '*'\n")
        proposal = permissions.propose("perm-skill", skill_dir, "find-3")
        assert proposal is not None
        assert proposal.check_id == "PERM-001"
        assert proposal.action_type == ActionType.RESTRICT_PERMISSIONS

    def test_detects_permissions_all(self, tmp_path):
        skill_dir = self._write_skill(tmp_path, "permissions: all\n")
        proposal = permissions.propose("perm-skill", skill_dir, "find-3")
        assert proposal is not None

    def test_clean_skill_returns_none(self, tmp_path):
        skill_dir = self._write_skill(
            tmp_path, "allowed-tools:\n  - read\n  - write\n"
        )
        proposal = permissions.propose("clean-skill", skill_dir, "find-3")
        assert proposal is None

    def test_apply_patch_comments_out_wildcard(self, tmp_path):
        skill_dir = self._write_skill(tmp_path, "allowed-tools: '*'\n")
        permissions.apply_patch(skill_dir)
        content = (skill_dir / "SKILL.md").read_text()
        assert "# RESTRICTED:" in content
