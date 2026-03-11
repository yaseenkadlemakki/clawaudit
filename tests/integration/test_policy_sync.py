"""Integration tests for PolicySyncService — DB-to-engine bridge."""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest
import pytest_asyncio

if sys.version_info < (3, 10):  # noqa: UP036
    pytest.skip("requires Python 3.10+ (Mapped[str | None] syntax)", allow_module_level=True)

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import backend.database
from backend.database import Base


@pytest_asyncio.fixture
async def db_engine():
    # Import all models so they're registered with Base.metadata before create_all
    from backend.models import chat, finding, policy, remediation, scan, skill  # noqa: F401

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session_factory(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    with patch.object(backend.database, "engine", db_engine):
        with patch.object(backend.database, "AsyncSessionLocal", factory):
            yield factory


@pytest.mark.integration
@pytest.mark.asyncio
async def test_create_via_api_sync_updates_rules(db_session_factory):
    """Create policy → sync.reload() → rules list updated."""
    from backend.storage.repository import PolicyRepository
    from sentinel.policy.sync import PolicySyncService

    svc = PolicySyncService(db_session_factory)
    await svc.reload()
    assert svc.get_rules() == []

    async with db_session_factory() as db:
        repo = PolicyRepository(db)
        await repo.create(
            {
                "name": "new-sync-policy",
                "domain": "tool_call",
                "check": "tool",
                "condition": "equals",
                "value": "exec",
                "severity": "HIGH",
                "action": "BLOCK",
                "enabled": True,
                "builtin": False,
                "priority": 50,
            }
        )

    await svc.reload()
    rules = svc.get_rules()
    assert len(rules) == 1
    assert rules[0].check == "tool"
    assert rules[0].action == "BLOCK"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_delete_via_api_sync_removes_rule(db_session_factory):
    """Delete policy → sync.reload() → rule no longer in list."""
    from backend.storage.repository import PolicyRepository
    from sentinel.policy.sync import PolicySyncService

    svc = PolicySyncService(db_session_factory)

    async with db_session_factory() as db:
        repo = PolicyRepository(db)
        record = await repo.create(
            {
                "name": "delete-sync-test",
                "domain": "tool_call",
                "check": "tool",
                "condition": "equals",
                "value": "exec",
                "severity": "HIGH",
                "action": "BLOCK",
                "enabled": True,
                "builtin": False,
                "priority": 50,
            }
        )
        policy_id = record.id

    await svc.reload()
    assert len(svc.get_rules()) == 1

    async with db_session_factory() as db:
        repo = PolicyRepository(db)
        await repo.delete(policy_id)

    await svc.reload()
    assert len(svc.get_rules()) == 0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_update_policy_sync_reflects_new_action(db_session_factory):
    """Update policy action → sync.reload() → rule has new action."""
    from backend.storage.repository import PolicyRepository
    from sentinel.policy.sync import PolicySyncService

    svc = PolicySyncService(db_session_factory)

    async with db_session_factory() as db:
        repo = PolicyRepository(db)
        record = await repo.create(
            {
                "name": "update-action-test",
                "domain": "tool_call",
                "check": "tool",
                "condition": "equals",
                "value": "exec",
                "severity": "HIGH",
                "action": "WARN",  # start as WARN
                "enabled": True,
                "builtin": False,
                "priority": 50,
            }
        )
        policy_id = record.id

    await svc.reload()
    rule = svc.get_rules()[0]
    assert rule.action == "WARN"

    # Update to BLOCK
    async with db_session_factory() as db:
        repo = PolicyRepository(db)
        await repo.update(policy_id, {"action": "BLOCK"})

    await svc.reload()
    rule = svc.get_rules()[0]
    assert rule.action == "BLOCK"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_disabled_policy_not_loaded(db_session_factory):
    """Disabled policies are not included in rules after reload."""
    from backend.storage.repository import PolicyRepository
    from sentinel.policy.sync import PolicySyncService

    svc = PolicySyncService(db_session_factory)

    async with db_session_factory() as db:
        repo = PolicyRepository(db)
        await repo.create(
            {
                "name": "disabled-policy",
                "domain": "tool_call",
                "check": "tool",
                "condition": "equals",
                "value": "exec",
                "severity": "HIGH",
                "action": "BLOCK",
                "enabled": False,  # disabled
                "builtin": False,
                "priority": 50,
            }
        )

    await svc.reload()
    assert len(svc.get_rules()) == 0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_multiple_policies_all_loaded(db_session_factory):
    """Multiple enabled policies are all loaded."""
    from backend.storage.repository import PolicyRepository
    from sentinel.policy.sync import PolicySyncService

    svc = PolicySyncService(db_session_factory)

    async with db_session_factory() as db:
        repo = PolicyRepository(db)
        for i in range(3):
            await repo.create(
                {
                    "name": f"policy-{i}",
                    "domain": "tool_call",
                    "check": "tool",
                    "condition": "equals",
                    "value": f"tool-{i}",
                    "severity": "HIGH",
                    "action": "BLOCK",
                    "enabled": True,
                    "builtin": False,
                    "priority": i * 10,
                }
            )

    await svc.reload()
    rules = svc.get_rules()
    assert len(rules) == 3
    names = [r.value for r in rules]
    assert "tool-0" in names
    assert "tool-1" in names
    assert "tool-2" in names
