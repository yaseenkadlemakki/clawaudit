"""Integration tests for the full remediation pipeline."""

from __future__ import annotations

from pathlib import Path

from sentinel.remediation.actions import ActionType
from sentinel.remediation.engine import RemediationEngine


def _make_skill(parent: Path, name: str, content: str) -> Path:
    """Create a minimal skill directory with SKILL.md."""
    skill_dir = parent / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(content)
    return skill_dir


class TestDryRunMode:
    def test_proposals_generated_but_no_changes(self, tmp_path):
        skill_dir = _make_skill(tmp_path, "risky-skill", "pty: true\n")
        original_content = (skill_dir / "SKILL.md").read_text()

        engine = RemediationEngine(skills_dir=tmp_path, dry_run=True)
        findings = [
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "risky-skill",
                "location": str(skill_dir),
            }
        ]
        proposals = engine.scan_for_proposals(findings)
        assert len(proposals) > 0

        # Apply in dry-run — should not change the file
        result = engine.apply_proposal(proposals[0])
        assert result.success is False
        assert "dry_run" in (result.error or "")
        assert (skill_dir / "SKILL.md").read_text() == original_content

    def test_no_proposals_for_clean_skill(self, tmp_path):
        _make_skill(tmp_path, "clean-skill", "---\nname: clean\n---\nDoes safe things.\n")
        engine = RemediationEngine(skills_dir=tmp_path, dry_run=True)
        findings = [
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "clean-skill",
                "location": str(tmp_path / "clean-skill"),
            }
        ]
        proposals = engine.scan_for_proposals(findings)
        assert proposals == []


class TestApplyMode:
    def test_apply_changes_file(self, tmp_path):
        skill_dir = _make_skill(tmp_path, "apply-skill", "pty: true\n")

        import sentinel.remediation.rollback as rb

        original_snap_dir = rb.SNAPSHOT_DIR
        rb.SNAPSHOT_DIR = tmp_path / "snapshots"

        engine = RemediationEngine(skills_dir=tmp_path, dry_run=False)
        findings = [
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "apply-skill",
                "location": str(skill_dir),
            }
        ]
        proposals = engine.scan_for_proposals(findings)
        assert proposals

        try:
            result = engine.apply_proposal(proposals[0])
            assert result.success is True
            content = (skill_dir / "SKILL.md").read_text()
            assert "pty: false" in content
        finally:
            rb.SNAPSHOT_DIR = original_snap_dir

    def test_apply_creates_snapshot(self, tmp_path):
        skill_dir = _make_skill(tmp_path, "snap-skill", "pty: true\n")

        import sentinel.remediation.rollback as rb

        original_snap_dir = rb.SNAPSHOT_DIR
        rb.SNAPSHOT_DIR = tmp_path / "snapshots"

        engine = RemediationEngine(skills_dir=tmp_path, dry_run=False)
        findings = [
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "snap-skill",
                "location": str(skill_dir),
            }
        ]
        proposals = engine.scan_for_proposals(findings)

        try:
            result = engine.apply_proposal(proposals[0])
            assert result.snapshot_path is not None
            assert result.snapshot_path.exists()
        finally:
            rb.SNAPSHOT_DIR = original_snap_dir


class TestRollback:
    def test_rollback_restores_file(self, tmp_path):
        skill_dir = _make_skill(tmp_path, "rollback-skill", "pty: true\nsecurity: full\n")
        original_content = (skill_dir / "SKILL.md").read_text()

        import sentinel.remediation.rollback as rb

        original_snap_dir = rb.SNAPSHOT_DIR
        rb.SNAPSHOT_DIR = tmp_path / "snapshots"

        engine = RemediationEngine(skills_dir=tmp_path, dry_run=False)
        findings = [
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "rollback-skill",
                "location": str(skill_dir),
            }
        ]
        proposals = engine.scan_for_proposals(findings)

        try:
            result = engine.apply_proposal(proposals[0])
            assert result.success is True
            assert (skill_dir / "SKILL.md").read_text() != original_content

            # Rollback
            success = engine.rollback(result.snapshot_path)
            assert success is True
            assert (skill_dir / "SKILL.md").read_text() == original_content
        finally:
            rb.SNAPSHOT_DIR = original_snap_dir


class TestProtectedSkills:
    def test_system_skill_path_is_protected(self, tmp_path):
        engine = RemediationEngine(skills_dir=tmp_path, dry_run=False)
        system_path = Path("/opt/homebrew/lib/node_modules/openclaw/skills/test-skill")
        assert engine.is_protected(system_path) is True

    def test_user_skill_path_is_not_protected(self, tmp_path):
        engine = RemediationEngine(skills_dir=tmp_path, dry_run=False)
        assert engine.is_protected(tmp_path / "my-skill") is False

    def test_protected_skill_apply_blocked(self, tmp_path):
        from sentinel.remediation.actions import RemediationProposal

        engine = RemediationEngine(skills_dir=tmp_path, dry_run=False)
        proposal = RemediationProposal.create(
            finding_id="f1",
            check_id="ADV-001",
            skill_name="system-skill",
            skill_path=Path("/opt/homebrew/lib/node_modules/openclaw/skills/system-skill"),
            description="test",
            action_type=ActionType.RESTRICT_SHELL,
            diff_preview="",
        )
        result = engine.apply_proposal(proposal)
        assert result.success is False
        assert "protected" in (result.error or "").lower()


class TestApplyAll:
    def test_apply_all_returns_results_for_each(self, tmp_path):
        _make_skill(tmp_path, "skill-a", "pty: true\n")
        _make_skill(tmp_path, "skill-b", "pty: true\n")

        import sentinel.remediation.rollback as rb

        original_snap_dir = rb.SNAPSHOT_DIR
        rb.SNAPSHOT_DIR = tmp_path / "snapshots"

        engine = RemediationEngine(skills_dir=tmp_path, dry_run=False)
        findings = [
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "skill-a",
                "location": str(tmp_path / "skill-a"),
            },
            {
                "id": "f2",
                "check_id": "ADV-001",
                "skill_name": "skill-b",
                "location": str(tmp_path / "skill-b"),
            },
        ]
        proposals = engine.scan_for_proposals(findings)
        assert len(proposals) == 2

        try:
            results = engine.apply_all(proposals)
            assert len(results) == 2
            assert all(r.success for r in results)
            # Verify both files were actually modified
            assert "pty: false" in (tmp_path / "skill-a" / "SKILL.md").read_text()
            assert "pty: false" in (tmp_path / "skill-b" / "SKILL.md").read_text()
        finally:
            rb.SNAPSHOT_DIR = original_snap_dir

    def test_apply_all_dry_run_returns_all_failed(self, tmp_path):
        _make_skill(tmp_path, "skill-a", "pty: true\n")
        engine = RemediationEngine(skills_dir=tmp_path, dry_run=True)
        findings = [
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "skill-a",
                "location": str(tmp_path / "skill-a"),
            },
        ]
        proposals = engine.scan_for_proposals(findings)
        results = engine.apply_all(proposals)
        assert all(not r.success for r in results)
        assert all("dry_run" in (r.error or "") for r in results)


class TestEngineErrorPaths:
    def test_apply_with_unknown_strategy_fails(self, tmp_path):
        """Applying a proposal with a check_id not in _STRATEGY_MAP should fail gracefully."""
        from sentinel.remediation.actions import RemediationProposal

        engine = RemediationEngine(skills_dir=tmp_path, dry_run=False)
        proposal = RemediationProposal.create(
            finding_id="f1",
            check_id="UNKNOWN-999",
            skill_name="test",
            skill_path=tmp_path,
            description="test",
            action_type=ActionType.RESTRICT_SHELL,
            diff_preview="",
        )
        result = engine.apply_proposal(proposal)
        assert result.success is False
        assert "No strategy" in (result.error or "")

    def test_extra_protected_paths(self, tmp_path):
        custom_protected = tmp_path / "protected"
        custom_protected.mkdir()
        engine = RemediationEngine(
            skills_dir=tmp_path,
            dry_run=False,
            extra_protected_paths=[custom_protected],
        )
        assert engine.is_protected(custom_protected / "my-skill") is True
        assert engine.is_protected(tmp_path / "my-skill") is False

    def test_finding_with_missing_skill_name_skipped(self, tmp_path):
        _make_skill(tmp_path, "some-skill", "pty: true\n")
        engine = RemediationEngine(skills_dir=tmp_path, dry_run=True)
        findings = [
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "",
                "location": str(tmp_path / "some-skill"),
            },
        ]
        proposals = engine.scan_for_proposals(findings)
        assert proposals == []

    def test_finding_with_nonexistent_dir_skipped(self, tmp_path):
        engine = RemediationEngine(skills_dir=tmp_path, dry_run=True)
        findings = [
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "ghost",
                "location": "/nonexistent/path",
            },
        ]
        proposals = engine.scan_for_proposals(findings)
        assert proposals == []


class TestFilteredProposals:
    def test_filter_by_check_id(self, tmp_path):
        _make_skill(tmp_path, "multi-skill", "pty: true\napi_key = 'sk-ant-abc123456789abcdef'\n")
        engine = RemediationEngine(skills_dir=tmp_path, dry_run=True)
        findings = [
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "multi-skill",
                "location": str(tmp_path / "multi-skill"),
            },
            {
                "id": "f2",
                "check_id": "ADV-005",
                "skill_name": "multi-skill",
                "location": str(tmp_path / "multi-skill"),
            },
        ]
        proposals = engine.scan_for_proposals(findings, check_ids=["ADV-001"])
        assert all(p.check_id == "ADV-001" for p in proposals)

    def test_filter_by_skill_name(self, tmp_path):
        _make_skill(tmp_path, "skill-a", "pty: true\n")
        _make_skill(tmp_path, "skill-b", "pty: true\n")
        engine = RemediationEngine(skills_dir=tmp_path, dry_run=True)
        findings = [
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "skill-a",
                "location": str(tmp_path / "skill-a"),
            },
            {
                "id": "f2",
                "check_id": "ADV-001",
                "skill_name": "skill-b",
                "location": str(tmp_path / "skill-b"),
            },
        ]
        proposals = engine.scan_for_proposals(findings, skill_names=["skill-a"])
        assert all(p.skill_name == "skill-a" for p in proposals)

    def test_unknown_check_id_produces_no_proposals(self, tmp_path):
        _make_skill(tmp_path, "skill", "pty: true\n")
        engine = RemediationEngine(skills_dir=tmp_path, dry_run=True)
        findings = [
            {
                "id": "f1",
                "check_id": "UNKNOWN-999",
                "skill_name": "skill",
                "location": str(tmp_path / "skill"),
            }
        ]
        proposals = engine.scan_for_proposals(findings)
        assert proposals == []

    def test_both_check_id_and_skill_name_filters(self, tmp_path):
        """When both filters are given, they apply as AND — finding must match both."""
        _make_skill(tmp_path, "skill-a", "pty: true\napi_key = 'sk-ant-abc123456789abcdef'\n")
        _make_skill(tmp_path, "skill-b", "pty: true\n")
        engine = RemediationEngine(skills_dir=tmp_path, dry_run=True)
        findings = [
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "skill-a",
                "location": str(tmp_path / "skill-a"),
            },
            {
                "id": "f2",
                "check_id": "ADV-005",
                "skill_name": "skill-a",
                "location": str(tmp_path / "skill-a"),
            },
            {
                "id": "f3",
                "check_id": "ADV-001",
                "skill_name": "skill-b",
                "location": str(tmp_path / "skill-b"),
            },
        ]
        # Only ADV-001 for skill-a
        proposals = engine.scan_for_proposals(
            findings, check_ids=["ADV-001"], skill_names=["skill-a"]
        )
        assert len(proposals) == 1
        assert proposals[0].check_id == "ADV-001"
        assert proposals[0].skill_name == "skill-a"


class TestRollbackFailure:
    def test_rollback_with_missing_snapshot_returns_false(self, tmp_path):
        """Rollback with a non-existent snapshot should return False, not raise."""
        engine = RemediationEngine(skills_dir=tmp_path, dry_run=False)
        result = engine.rollback(tmp_path / "nonexistent.tar.gz")
        assert result is False

    def test_rollback_with_corrupt_snapshot_returns_false(self, tmp_path):
        """Rollback with a corrupt tarball should return False."""
        corrupt = tmp_path / "corrupt.tar.gz"
        corrupt.write_bytes(b"not a tarball")
        engine = RemediationEngine(skills_dir=tmp_path, dry_run=False)
        result = engine.rollback(corrupt, target_parent=tmp_path)
        assert result is False


class TestLocationFallback:
    def test_location_fallback_to_skills_dir(self, tmp_path):
        """When location is not a directory, engine falls back to skills_dir/skill_name."""
        _make_skill(tmp_path, "fallback-skill", "pty: true\n")
        engine = RemediationEngine(skills_dir=tmp_path, dry_run=True)
        findings = [
            {
                "id": "f1",
                "check_id": "ADV-001",
                "skill_name": "fallback-skill",
                "location": "/nonexistent/path",
            },
        ]
        proposals = engine.scan_for_proposals(findings)
        assert len(proposals) == 1
        assert proposals[0].skill_name == "fallback-skill"


class TestSecretsContextBoundary:
    def test_sk_pattern_requires_value_context(self, tmp_path):
        """sk- pattern should not match bare YAML keys like 'sk-something' at start of line."""
        skill_dir = _make_skill(tmp_path, "yaml-skill", "sk-something: this is a YAML key\n")
        from sentinel.remediation.strategies import secrets

        proposal = secrets.propose("yaml-skill", skill_dir, "find-1")
        # Should NOT flag a bare YAML key that starts the line
        assert proposal is None

    def test_sk_pattern_matches_in_value_context(self, tmp_path):
        """sk- pattern should match when in value context (after = or :)."""
        skill_dir = _make_skill(tmp_path, "key-skill", "token: sk-ant-abcdef1234567890abcdef\n")
        from sentinel.remediation.strategies import secrets

        proposal = secrets.propose("key-skill", skill_dir, "find-1")
        assert proposal is not None
        assert "[REDACTED]" in proposal.diff_preview
