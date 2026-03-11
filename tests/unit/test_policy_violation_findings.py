"""Unit tests for policy violation finding writing (backend/api/routes/policies.py helpers)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

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
