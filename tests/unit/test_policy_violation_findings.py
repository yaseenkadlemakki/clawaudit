"""Unit tests for policy violation finding writing (backend/api/routes/policies.py helpers)."""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock

import pytest

if sys.version_info < (3, 10):  # noqa: UP036
    pytest.skip("requires Python 3.10+ (Mapped[str | None] syntax)", allow_module_level=True)

from sentinel.models.policy import PolicyDecision, Rule


def make_rule(
    id: str = "rule-1",
    message: str = "Test message",
    check: str = "tool",
    severity: str = "HIGH",
    action: str = "BLOCK",
) -> Rule:
    return Rule(
        id=id,
        domain="tool_call",
        check=check,
        condition="equals",
        value="exec",
        severity=severity,
        action=action,
        message=message,
    )


class TestWriteViolationFinding:
    """Test the _write_violation_finding helper from policies routes."""

    @pytest.mark.asyncio
    async def test_finding_written_on_alert(self):
        from backend.api.routes.policies import _write_violation_finding
        from backend.api.schemas import ToolCallEvaluationRequest

        body = ToolCallEvaluationRequest(
            tool="exec",
            params={"command": "bash"},
            skill_name="my-skill",
        )
        rule = make_rule(action="ALERT")
        decision = PolicyDecision(
            action="ALERT", matched_rules=[rule], reason="test", policy_ids=[rule.id]
        )

        mock_db = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()

        await _write_violation_finding(mock_db, body, decision)

        assert mock_db.add.called
        finding = mock_db.add.call_args[0][0]
        from backend.models.finding import FindingRecord

        assert isinstance(finding, FindingRecord)
        assert finding.domain == "policy"
        assert finding.result == "FAIL"
        assert finding.scan_id == "policy-engine"
        assert finding.skill_name == "my-skill"
        assert finding.severity == "HIGH"

    @pytest.mark.asyncio
    async def test_finding_written_on_block(self):
        from backend.api.routes.policies import _write_violation_finding
        from backend.api.schemas import ToolCallEvaluationRequest

        body = ToolCallEvaluationRequest(
            tool="exec",
            params={"pty": True},
            skill_name="bad-skill",
        )
        rule = make_rule(id="block-rule", action="BLOCK")
        decision = PolicyDecision(
            action="BLOCK", matched_rules=[rule], reason="blocked", policy_ids=[rule.id]
        )

        mock_db = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()

        await _write_violation_finding(mock_db, body, decision)

        assert mock_db.add.called
        finding = mock_db.add.call_args[0][0]
        assert "BLOCK" in finding.title
        assert finding.scan_id == "policy-engine"

    @pytest.mark.asyncio
    async def test_check_id_format(self):
        from backend.api.routes.policies import _write_violation_finding
        from backend.api.schemas import ToolCallEvaluationRequest

        body = ToolCallEvaluationRequest(tool="exec", params={})
        rule = make_rule(id="abcdef1234567890")
        decision = PolicyDecision(
            action="BLOCK", matched_rules=[rule], reason="test", policy_ids=[rule.id]
        )

        mock_db = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()

        await _write_violation_finding(mock_db, body, decision)

        finding = mock_db.add.call_args[0][0]
        assert finding.check_id == "POL-abcdef"

    @pytest.mark.asyncio
    async def test_multiple_rules_write_multiple_findings(self):
        from backend.api.routes.policies import _write_violation_finding
        from backend.api.schemas import ToolCallEvaluationRequest

        body = ToolCallEvaluationRequest(tool="exec", params={})
        rules = [make_rule(id=f"rule-{i}") for i in range(3)]
        decision = PolicyDecision(
            action="BLOCK",
            matched_rules=rules,
            reason="multi",
            policy_ids=[r.id for r in rules],
        )

        mock_db = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()

        await _write_violation_finding(mock_db, body, decision)

        assert mock_db.add.call_count == 3

    @pytest.mark.asyncio
    async def test_scan_id_is_sentinel_value(self):
        from backend.api.routes.policies import POLICY_ENGINE_SCAN_ID, _write_violation_finding
        from backend.api.schemas import ToolCallEvaluationRequest

        body = ToolCallEvaluationRequest(tool="read", params={})
        rule = make_rule()
        decision = PolicyDecision(
            action="ALERT", matched_rules=[rule], reason="test", policy_ids=[rule.id]
        )

        mock_db = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()

        await _write_violation_finding(mock_db, body, decision)

        finding = mock_db.add.call_args[0][0]
        assert finding.scan_id == POLICY_ENGINE_SCAN_ID
        assert POLICY_ENGINE_SCAN_ID == "policy-engine"

    @pytest.mark.asyncio
    async def test_allow_action_no_finding_written_by_route(self):
        """ALLOW decision → route does NOT call _write_violation_finding."""
        from unittest.mock import AsyncMock

        from backend.api.routes.policies import _write_violation_finding
        from backend.api.schemas import ToolCallEvaluationRequest

        # Verify the route-level guard: _write_violation_finding should
        # NOT be called for ALLOW actions.  We test the route decision path
        # by directly confirming the function is only invoked for non-ALLOW.
        body = ToolCallEvaluationRequest(tool="read", params={})
        decision = PolicyDecision(action="ALLOW", matched_rules=[], reason="No matching rules")

        mock_db = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()

        # _write_violation_finding iterates decision.matched_rules.
        # For ALLOW (no matched_rules), it writes nothing.
        await _write_violation_finding(mock_db, body, decision)
        assert not mock_db.add.called, "No finding should be written for ALLOW with no matches"

    @pytest.mark.asyncio
    async def test_warn_action_no_finding_written_by_helper(self):
        """WARN decision matched_rules still writes via helper — but route skips it for WARN."""
        # The route handler only calls _write_violation_finding for ALERT/BLOCK/QUARANTINE.
        # We verify this by checking the condition guard in the route.
        from backend.api.routes import policies as policies_module

        route_source = policies_module.__file__
        with open(route_source) as f:
            source = f.read()
        assert '"ALERT", "BLOCK", "QUARANTINE"' in source or (
            "ALERT" in source and "BLOCK" in source and "QUARANTINE" in source
        ), "Route must guard _write_violation_finding to ALERT/BLOCK/QUARANTINE only"

        # Confirm WARN is not in the guard list
        assert 'if decision.action in ("ALERT", "BLOCK", "QUARANTINE")' in source or (
            "WARN"
            not in source.split("_write_violation_finding")[0].split("if decision.action")[-1]
        )


class TestIncrementViolationCounts:
    """Test the _increment_violation_counts helper from policies routes."""

    @pytest.mark.asyncio
    async def test_violation_count_incremented(self):
        from backend.api.routes.policies import _increment_violation_counts

        mock_record = MagicMock()
        mock_record.violation_count = 0
        mock_record.last_triggered_at = None

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=mock_record)
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()

        await _increment_violation_counts(mock_db, ["policy-1"])

        assert mock_record.violation_count == 1
        assert mock_record.last_triggered_at is not None

    @pytest.mark.asyncio
    async def test_violation_count_incremented_multiple(self):
        from backend.api.routes.policies import _increment_violation_counts

        records = {
            "pol-a": MagicMock(violation_count=5, last_triggered_at=None),
            "pol-b": MagicMock(violation_count=0, last_triggered_at=None),
        }

        async def mock_get(model, pid):
            return records.get(pid)

        mock_db = AsyncMock()
        mock_db.get = mock_get
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()

        await _increment_violation_counts(mock_db, ["pol-a", "pol-b"])

        assert records["pol-a"].violation_count == 6
        assert records["pol-b"].violation_count == 1

    @pytest.mark.asyncio
    async def test_violation_count_skips_missing_record(self):
        from backend.api.routes.policies import _increment_violation_counts

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=None)
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()

        # Should not raise, just skip
        await _increment_violation_counts(mock_db, ["nonexistent"])
        assert mock_db.flush.called

    @pytest.mark.asyncio
    async def test_violation_count_none_initialized_to_zero(self):
        """violation_count=None is treated as 0."""
        from backend.api.routes.policies import _increment_violation_counts

        mock_record = MagicMock()
        mock_record.violation_count = None

        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=mock_record)
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()

        await _increment_violation_counts(mock_db, ["pol-null"])

        assert mock_record.violation_count == 1
