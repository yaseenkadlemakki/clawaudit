"""Unit tests for PolicySyncService."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.policy.sync import PolicySyncService

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def make_record(
    id: str = "r1",
    name: str = "test-policy",
    domain: str = "tool_call",
    check: str = "tool",
    condition: str = "equals",
    value: str = "exec",
    severity: str = "HIGH",
    action: str = "BLOCK",
    enabled: bool = True,
    builtin: bool = False,
    priority: int = 0,
    description: str | None = None,
):
    r = MagicMock()
    r.id = id
    r.name = name
    r.domain = domain
    r.check = check
    r.condition = condition
    r.value = value
    r.severity = severity
    r.action = action
    r.enabled = enabled
    r.builtin = builtin
    r.priority = priority
    r.description = description
    return r


def make_mock_db():
    mock_db = AsyncMock()
    mock_db.__aenter__ = AsyncMock(return_value=mock_db)
    mock_db.__aexit__ = AsyncMock(return_value=None)
    return mock_db


def make_factory(mock_db):
    @asynccontextmanager
    async def factory():
        yield mock_db

    return factory


class MockRepo:
    """Mock PolicyRepository that returns configured records."""

    def __init__(self, records):
        self._records = records

    def __call__(self, _db):
        return self

    async def list_enabled(self):
        return self._records


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPolicySyncService:
    @pytest.mark.asyncio
    async def test_reload_returns_rule_count(self):
        records = [make_record("r1"), make_record("r2")]
        repo = MockRepo(records)
        mock_db = make_mock_db()
        factory = make_factory(mock_db)

        with patch("backend.storage.repository.PolicyRepository", repo):
            svc = PolicySyncService(factory)
            count = await svc.reload()

        assert count == 2

    @pytest.mark.asyncio
    async def test_get_rules_returns_copy(self):
        records = [make_record("r1")]
        repo = MockRepo(records)
        mock_db = make_mock_db()
        factory = make_factory(mock_db)

        with patch("backend.storage.repository.PolicyRepository", repo):
            svc = PolicySyncService(factory)
            await svc.reload()

        rules = svc.get_rules()
        assert len(rules) == 1
        # Mutating the returned list doesn't affect internal state
        rules.clear()
        assert len(svc.get_rules()) == 1

    @pytest.mark.asyncio
    async def test_empty_db_falls_back_to_yaml(self, tmp_path: Path):
        """When DB is empty, fall back to YAML files."""
        # Write a minimal policy YAML
        policy_yaml = tmp_path / "test.yaml"
        policy_yaml.write_text(
            """
name: test
version: "1"
rules:
  - id: yaml-rule
    domain: tool_call
    check: tool
    condition: equals
    value: exec
    severity: HIGH
    action: BLOCK
    message: YAML fallback rule
"""
        )

        repo = MockRepo([])
        mock_db = make_mock_db()
        factory = make_factory(mock_db)

        with patch("backend.storage.repository.PolicyRepository", repo):
            svc = PolicySyncService(factory, fallback_dir=tmp_path)
            count = await svc.reload()

        assert count == 1
        rules = svc.get_rules()
        assert rules[0].id == "yaml-rule"

    @pytest.mark.asyncio
    async def test_record_to_rule_field_mapping(self):
        """_record_to_rule maps all fields correctly."""
        rec = make_record(
            id="mapped-id",
            domain="tool_call",
            check="params.pty",
            condition="equals",
            value="true",
            severity="HIGH",
            action="BLOCK",
            enabled=True,
            builtin=True,
            priority=100,
            description="A test description",
        )
        repo = MockRepo([rec])
        mock_db = make_mock_db()
        factory = make_factory(mock_db)

        with patch("backend.storage.repository.PolicyRepository", repo):
            svc = PolicySyncService(factory)
            await svc.reload()

        rule = svc.get_rules()[0]
        assert rule.id == "mapped-id"
        assert rule.domain == "tool_call"
        assert rule.check == "params.pty"
        assert rule.condition == "equals"
        assert rule.value == "true"
        assert rule.severity == "HIGH"
        assert rule.action == "BLOCK"
        assert rule.enabled is True
        assert rule.builtin is True
        assert rule.priority == 100
        assert rule.message == "A test description"

    @pytest.mark.asyncio
    async def test_reload_after_update_reflects_new_rules(self):
        """Calling reload() again picks up new/changed records."""
        rec1 = make_record("r1")
        rec2 = make_record("r2")

        call_count = 0

        class CountingRepo:
            def __init__(self, _db):
                pass

            async def list_enabled(self):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return [rec1]
                return [rec1, rec2]

        mock_db = make_mock_db()
        factory = make_factory(mock_db)

        with patch("backend.storage.repository.PolicyRepository", CountingRepo):
            svc = PolicySyncService(factory)
            await svc.reload()
            assert len(svc.get_rules()) == 1
            await svc.reload()
            assert len(svc.get_rules()) == 2

    @pytest.mark.asyncio
    async def test_empty_db_no_fallback_returns_empty(self):
        repo = MockRepo([])
        mock_db = make_mock_db()
        factory = make_factory(mock_db)

        with patch("backend.storage.repository.PolicyRepository", repo):
            svc = PolicySyncService(factory, fallback_dir=None)
            count = await svc.reload()

        assert count == 0
        assert svc.get_rules() == []
