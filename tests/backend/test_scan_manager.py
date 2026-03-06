"""Tests for scan lifecycle state machine."""
from __future__ import annotations

import pytest
import pytest_asyncio

from backend.database import Base, engine, AsyncSessionLocal
from backend.engine.scan_manager import ScanManager
from backend.models.scan import ScanStatus


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.mark.asyncio
async def test_start_scan_creates_record():
    mgr = ScanManager()
    scan = await mgr.start_scan(triggered_by="test")
    assert scan["status"] == ScanStatus.RUNNING
    assert scan["triggered_by"] == "test"
    assert "id" in scan


@pytest.mark.asyncio
async def test_get_scan_returns_record():
    mgr = ScanManager()
    scan = await mgr.start_scan(triggered_by="cli")
    result = await mgr.get_scan(scan["id"])
    assert result is not None
    assert result["id"] == scan["id"]


@pytest.mark.asyncio
async def test_get_scan_not_found():
    mgr = ScanManager()
    result = await mgr.get_scan("nonexistent-id")
    assert result is None


@pytest.mark.asyncio
async def test_list_scans():
    mgr = ScanManager()
    await mgr.start_scan(triggered_by="a")
    await mgr.start_scan(triggered_by="b")
    scans = await mgr.list_scans(limit=10)
    assert len(scans) >= 2


@pytest.mark.asyncio
async def test_stop_scan_not_found():
    mgr = ScanManager()
    result = await mgr.stop_scan("no-such-id")
    assert result is None
