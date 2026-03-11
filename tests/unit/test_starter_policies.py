"""Unit tests for starter policy seeding."""

from __future__ import annotations

import pytest

from backend.seeds.starter_policies import STARTER_POLICIES


class TestStarterPolicies:
    def test_five_starter_policies_defined(self):
        assert len(STARTER_POLICIES) == 5

    def test_all_policies_have_required_fields(self):
        required = {"name", "domain", "check", "condition", "value", "severity", "action"}
        for p in STARTER_POLICIES:
            missing = required - set(p.keys())
            assert not missing, f"Policy {p.get('name')} missing fields: {missing}"

    def test_all_policies_are_builtin(self):
        for p in STARTER_POLICIES:
            assert p["builtin"] is True, f"Policy {p['name']} should be builtin=True"

    def test_all_policies_have_priority(self):
        for p in STARTER_POLICIES:
            assert "priority" in p, f"Policy {p['name']} missing priority"
            assert isinstance(p["priority"], int)
            assert p["priority"] > 0, f"Policy {p['name']} should have priority > 0"

    def test_policies_have_tool_call_domain(self):
        for p in STARTER_POLICIES:
            assert p["domain"] == "tool_call"

    def test_block_pty_exec_policy(self):
        policy = next(p for p in STARTER_POLICIES if p["name"] == "block-pty-exec")
        assert policy["action"] == "BLOCK"
        assert policy["check"] == "params.pty"
        assert policy["condition"] == "equals"
        assert policy["value"] == "true"
        assert policy["severity"] == "HIGH"
        assert policy["priority"] == 100

    def test_alert_credential_file_read_policy(self):
        policy = next(p for p in STARTER_POLICIES if p["name"] == "alert-credential-file-read")
        assert policy["action"] == "ALERT"
        assert policy["check"] == "params.path"
        assert policy["condition"] == "matches"
        assert policy["severity"] == "HIGH"

    def test_alert_elevated_exec_policy(self):
        policy = next(p for p in STARTER_POLICIES if p["name"] == "alert-elevated-exec")
        assert policy["action"] == "ALERT"
        assert policy["check"] == "params.elevated"
        assert policy["condition"] == "equals"
        assert policy["value"] == "true"

    def test_alert_browser_external_navigate_policy(self):
        policy = next(
            p for p in STARTER_POLICIES if p["name"] == "alert-browser-external-navigate"
        )
        assert policy["action"] == "ALERT"
        assert policy["check"] == "params.url"
        assert policy["condition"] == "matches"
        assert policy["severity"] == "MEDIUM"

    def test_alert_message_send_policy(self):
        policy = next(p for p in STARTER_POLICIES if p["name"] == "alert-message-send")
        assert policy["action"] == "ALERT"
        assert policy["check"] == "tool"
        assert policy["condition"] == "equals"
        assert policy["value"] == "message"

    def test_policy_names_are_unique(self):
        names = [p["name"] for p in STARTER_POLICIES]
        assert len(names) == len(set(names)), "Duplicate policy names found"

    def test_all_actions_are_valid(self):
        valid_actions = {"ALLOW", "WARN", "ALERT", "BLOCK", "QUARANTINE"}
        for p in STARTER_POLICIES:
            assert p["action"] in valid_actions, f"Invalid action in {p['name']}"

    def test_all_severities_are_valid(self):
        valid_severities = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for p in STARTER_POLICIES:
            assert p["severity"] in valid_severities, f"Invalid severity in {p['name']}"


class TestSeedStarterPoliciesIdempotent:
    @pytest.mark.asyncio
    async def test_seeding_is_idempotent(self, tmp_path):
        """Calling seed_starter_policies() twice doesn't create duplicates."""
        from unittest.mock import AsyncMock, patch

        from backend.seeds.starter_policies import seed_starter_policies

        created = []

        class MockRepo:
            def __init__(self, _db):
                pass

            async def get_by_name(self, name: str):
                for p in created:
                    if p["name"] == name:
                        m = type("obj", (), p)()
                        return m
                return None

            async def create(self, data: dict):
                created.append(data)

        mock_db = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=None)

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_session_factory():
            yield mock_db

        with patch("backend.database.AsyncSessionLocal", mock_session_factory):
            with patch("backend.storage.repository.PolicyRepository", MockRepo):
                await seed_starter_policies()
                first_count = len(created)
                await seed_starter_policies()
                second_count = len(created)

        assert first_count == 5
        assert second_count == 5  # No duplicates
