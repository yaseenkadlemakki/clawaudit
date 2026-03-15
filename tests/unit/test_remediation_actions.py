"""Unit tests for remediation data models."""

from __future__ import annotations

from sentinel.remediation.actions import (
    ActionType,
    RemediationProposal,
    RemediationResult,
    RemediationStatus,
)


class TestRemediationStatus:
    def test_status_values(self):
        assert RemediationStatus.PENDING == "pending"
        assert RemediationStatus.APPLIED == "applied"
        assert RemediationStatus.ROLLED_BACK == "rolled_back"
        assert RemediationStatus.FAILED == "failed"

    def test_status_is_str(self):
        assert isinstance(RemediationStatus.PENDING, str)


class TestActionType:
    def test_action_type_values(self):
        assert ActionType.RESTRICT_SHELL == "restrict_shell"
        assert ActionType.REDACT_SECRET == "redact_secret"
        assert ActionType.RESTRICT_PERMISSIONS == "restrict_permissions"
        assert ActionType.REMOVE_ENV_VAR == "remove_env_var"

    def test_advisory_action_type_exists(self):
        assert ActionType.ADVISORY.value == "advisory"


class TestRemediationProposal:
    def test_create_factory(self, tmp_path):
        proposal = RemediationProposal.create(
            finding_id="find-1",
            check_id="ADV-001",
            skill_name="my-skill",
            skill_path=tmp_path,
            description="Test proposal",
            action_type=ActionType.RESTRICT_SHELL,
            diff_preview="--- a\n+++ b\n",
            impact=["Impact A", "Impact B"],
        )
        assert proposal.finding_id == "find-1"
        assert proposal.check_id == "ADV-001"
        assert proposal.skill_name == "my-skill"
        assert proposal.skill_path == tmp_path
        assert proposal.action_type == ActionType.RESTRICT_SHELL
        assert len(proposal.impact) == 2
        assert proposal.reversible is True
        assert proposal.status == RemediationStatus.PENDING
        assert len(proposal.proposal_id) == 36  # UUID format

    def test_create_unique_ids(self, tmp_path):
        p1 = RemediationProposal.create(
            finding_id="f1",
            check_id="ADV-001",
            skill_name="s",
            skill_path=tmp_path,
            description="d",
            action_type=ActionType.RESTRICT_SHELL,
            diff_preview="",
        )
        p2 = RemediationProposal.create(
            finding_id="f2",
            check_id="ADV-001",
            skill_name="s",
            skill_path=tmp_path,
            description="d",
            action_type=ActionType.RESTRICT_SHELL,
            diff_preview="",
        )
        assert p1.proposal_id != p2.proposal_id

    def test_default_impact_is_empty(self, tmp_path):
        proposal = RemediationProposal.create(
            finding_id="f",
            check_id="ADV-005",
            skill_name="s",
            skill_path=tmp_path,
            description="d",
            action_type=ActionType.REDACT_SECRET,
            diff_preview="",
        )
        assert proposal.impact == []

    def test_irreversible_proposal(self, tmp_path):
        proposal = RemediationProposal.create(
            finding_id="f",
            check_id="ADV-005",
            skill_name="s",
            skill_path=tmp_path,
            description="d",
            action_type=ActionType.REDACT_SECRET,
            diff_preview="",
            reversible=False,
        )
        assert proposal.reversible is False

    def test_apply_available_defaults_true(self, tmp_path):
        proposal = RemediationProposal.create(
            finding_id="f",
            check_id="ADV-001",
            skill_name="s",
            skill_path=tmp_path,
            description="d",
            action_type=ActionType.RESTRICT_SHELL,
            diff_preview="",
        )
        assert proposal.apply_available is True

    def test_apply_available_false_propagates(self, tmp_path):
        proposal = RemediationProposal.create(
            finding_id="f",
            check_id="ADV-002",
            skill_name="s",
            skill_path=tmp_path,
            description="d",
            action_type=ActionType.ADVISORY,
            diff_preview="",
            apply_available=False,
        )
        assert proposal.apply_available is False


class TestRemediationResult:
    def test_success_result(self, tmp_path):
        proposal = RemediationProposal.create(
            finding_id="f",
            check_id="ADV-001",
            skill_name="s",
            skill_path=tmp_path,
            description="d",
            action_type=ActionType.RESTRICT_SHELL,
            diff_preview="",
        )
        result = RemediationResult(
            proposal=proposal, success=True, snapshot_path=tmp_path / "snap.tar.gz"
        )
        assert result.success is True
        assert result.error is None
        assert result.snapshot_path is not None

    def test_failure_result(self, tmp_path):
        proposal = RemediationProposal.create(
            finding_id="f",
            check_id="ADV-001",
            skill_name="s",
            skill_path=tmp_path,
            description="d",
            action_type=ActionType.RESTRICT_SHELL,
            diff_preview="",
        )
        result = RemediationResult(proposal=proposal, success=False, error="Something went wrong")
        assert result.success is False
        assert result.error == "Something went wrong"
        assert result.snapshot_path is None
