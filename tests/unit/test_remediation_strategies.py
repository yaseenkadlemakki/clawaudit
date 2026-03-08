"""Unit tests for remediation strategies."""

from __future__ import annotations

from pathlib import Path

from sentinel.remediation.actions import ActionType
from sentinel.remediation.strategies import permissions, secrets, shell_access


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
        skill_dir = self._write_skill(tmp_path, "Set the key: sk-ant-api123456789abcdefghij\n")
        proposal = secrets.propose("secret-skill", skill_dir, "find-2")
        assert proposal is not None
        assert proposal.check_id == "ADV-005"
        assert proposal.action_type == ActionType.REDACT_SECRET
        assert "[REDACTED]" in proposal.diff_preview

    def test_detects_generic_api_key(self, tmp_path):
        skill_dir = self._write_skill(tmp_path, "api_key = 'supersecretpassword123456'\n")
        proposal = secrets.propose("secret-skill", skill_dir, "find-2")
        assert proposal is not None

    def test_detects_aws_key(self, tmp_path):
        skill_dir = self._write_skill(tmp_path, "aws_key: AKIAIOSFODNN7EXAMPLE\n")
        proposal = secrets.propose("secret-skill", skill_dir, "find-2")
        assert proposal is not None
        assert "[REDACTED]" in proposal.diff_preview
        assert (
            "AKIA" not in proposal.diff_preview.split("+")[-1]
            if "+" in proposal.diff_preview
            else True
        )

    def test_detects_github_token(self, tmp_path):
        skill_dir = self._write_skill(
            tmp_path, "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn\n"
        )
        proposal = secrets.propose("secret-skill", skill_dir, "find-2")
        assert proposal is not None
        assert "[REDACTED]" in proposal.diff_preview

    def test_detects_bearer_token(self, tmp_path):
        skill_dir = self._write_skill(
            tmp_path, "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.abc123\n"
        )
        proposal = secrets.propose("secret-skill", skill_dir, "find-2")
        assert proposal is not None
        assert "[REDACTED]" in proposal.diff_preview

    def test_bearer_redaction_preserves_prefix(self, tmp_path):
        skill_dir = self._write_skill(
            tmp_path, "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.abc123\n"
        )
        secrets.apply_patch(skill_dir)
        content = (skill_dir / "SKILL.md").read_text()
        assert "Bearer [REDACTED]" in content

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
        skill_dir = self._write_skill(tmp_path, "token: sk-ant-api123456789abcdefghij\n")
        secrets.apply_patch(skill_dir)
        content = (skill_dir / "SKILL.md").read_text()
        assert "[REDACTED]" in content
        assert "sk-ant" not in content

    def test_apply_patch_atomic_no_tmp_left(self, tmp_path):
        skill_dir = self._write_skill(tmp_path, "api_key = 'supersecretpassword123456'\n")
        secrets.apply_patch(skill_dir)
        assert not (skill_dir / "SKILL.tmp").exists()

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
        skill_dir = self._write_skill(tmp_path, "allowed-tools:\n  - read\n  - write\n")
        proposal = permissions.propose("clean-skill", skill_dir, "find-3")
        assert proposal is None

    def test_apply_patch_comments_out_wildcard(self, tmp_path):
        skill_dir = self._write_skill(tmp_path, "allowed-tools: '*'\n")
        permissions.apply_patch(skill_dir)
        content = (skill_dir / "SKILL.md").read_text()
        assert "# RESTRICTED:" in content

    def test_detects_tool_access_unrestricted(self, tmp_path):
        skill_dir = self._write_skill(tmp_path, "tool_access: unrestricted\n")
        proposal = permissions.propose("perm-skill", skill_dir, "find-3")
        assert proposal is not None
        assert proposal.check_id == "PERM-001"

    def test_missing_skill_md_returns_none(self, tmp_path):
        skill_dir = tmp_path / "no-md"
        skill_dir.mkdir()
        proposal = permissions.propose("no-md", skill_dir, "find-3")
        assert proposal is None

    def test_apply_patch_atomic_no_tmp_left(self, tmp_path):
        skill_dir = self._write_skill(tmp_path, "permissions: all\n")
        permissions.apply_patch(skill_dir)
        assert not (skill_dir / "SKILL.tmp").exists()

    def test_multiple_wildcards_in_one_file(self, tmp_path):
        content = "allowed-tools: '*'\npermissions: all\ntool_access: unrestricted\n"
        skill_dir = self._write_skill(tmp_path, content)
        proposal = permissions.propose("perm-skill", skill_dir, "find-3")
        assert proposal is not None
        # All three lines should be restricted
        permissions.apply_patch(skill_dir)
        result = (skill_dir / "SKILL.md").read_text()
        assert result.count("# RESTRICTED:") == 3


class TestSecretsContextBoundary:
    """Tests for the sk- pattern context boundary fix."""

    def _write_skill(self, tmp_path, content):
        skill_dir = tmp_path / "ctx-skill"
        skill_dir.mkdir(exist_ok=True)
        (skill_dir / "SKILL.md").write_text(content)
        return skill_dir

    def test_sk_as_yaml_key_not_matched(self, tmp_path):
        """A YAML key starting with sk- should not be redacted."""
        skill_dir = self._write_skill(tmp_path, "sk-yaml-key-name-that-is-long: some_value\n")
        proposal = secrets.propose("ctx-skill", skill_dir, "find-1")
        assert proposal is None

    def test_sk_after_colon_space_is_matched(self, tmp_path):
        """An sk- key appearing after ': ' should be redacted."""
        skill_dir = self._write_skill(tmp_path, "key: sk-ant-api123456789abcdefghij\n")
        proposal = secrets.propose("ctx-skill", skill_dir, "find-1")
        assert proposal is not None
        assert "[REDACTED]" in proposal.diff_preview

    def test_sk_after_equals_is_matched(self, tmp_path):
        """An sk- key appearing after '=' should be redacted."""
        skill_dir = self._write_skill(tmp_path, "KEY=sk-ant-api123456789abcdefghij\n")
        proposal = secrets.propose("ctx-skill", skill_dir, "find-1")
        assert proposal is not None

    def test_sk_in_quotes_is_matched(self, tmp_path):
        """An sk- key appearing inside quotes should be redacted."""
        skill_dir = self._write_skill(tmp_path, 'token = "sk-ant-api123456789abcdefghij"\n')
        proposal = secrets.propose("ctx-skill", skill_dir, "find-1")
        assert proposal is not None
