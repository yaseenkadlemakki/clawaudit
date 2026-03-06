"""Shared fixtures for all backend API tests.

Every test in tests/backend/ gets an isolated in-memory SQLite database via
the ``isolated_db`` autouse fixture.  The fixture also stubs out
``ScanManager._execute_scan`` so background audit tasks complete instantly
and never outlive a test.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

import backend.database
import backend.engine.scan_manager
from backend.database import Base
from backend.engine.scan_manager import ScanManager


async def _noop_execute_scan(self, scan_id: str) -> None:
    """Stub: prevents real audit tasks from running during API tests."""
    return


@pytest_asyncio.fixture(autouse=True)
async def isolated_db():
    """Replace the module-level engine/session singletons with an isolated
    in-memory SQLite instance.  StaticPool ensures all sessions see the same
    data (required for SQLite :memory: with multiple connections).
    """
    test_engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestSessionLocal = async_sessionmaker(test_engine, expire_on_commit=False)

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    with (
        patch.object(backend.database, "engine", test_engine),
        patch.object(backend.database, "AsyncSessionLocal", TestSessionLocal),
        patch.object(backend.engine.scan_manager, "AsyncSessionLocal", TestSessionLocal),
        patch.object(ScanManager, "_execute_scan", _noop_execute_scan),
    ):
        yield

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await test_engine.dispose()
