"""Database abstraction layer — CRUD operations."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.finding import FindingRecord
from backend.models.policy import PolicyRecord
from backend.models.scan import ScanRun
from backend.models.skill import SkillRecord


class ScanRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def get(self, scan_id: str) -> ScanRun | None:
        return await self._db.get(ScanRun, scan_id)

    async def list(self, limit: int = 20, offset: int = 0) -> list[ScanRun]:
        result = await self._db.execute(
            select(ScanRun).order_by(ScanRun.started_at.desc()).limit(limit).offset(offset)
        )
        return list(result.scalars().all())

    async def count(self) -> int:
        from sqlalchemy import func

        result = await self._db.execute(select(func.count()).select_from(ScanRun))
        return result.scalar_one()


class FindingRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def get(self, finding_id: str) -> FindingRecord | None:
        return await self._db.get(FindingRecord, finding_id)

    async def list(
        self,
        scan_id: str | None = None,
        severity: str | None = None,
        domain: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[FindingRecord]:
        q = select(FindingRecord).order_by(FindingRecord.detected_at.desc())
        if scan_id:
            q = q.where(FindingRecord.scan_id == scan_id)
        if severity:
            q = q.where(FindingRecord.severity == severity.upper())
        if domain:
            q = q.where(FindingRecord.domain == domain)
        q = q.limit(limit).offset(offset)
        result = await self._db.execute(q)
        return list(result.scalars().all())


class SkillRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def get(self, skill_id: str) -> SkillRecord | None:
        return await self._db.get(SkillRecord, skill_id)

    async def list(
        self,
        scan_id: str | None = None,
        risk_level: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[SkillRecord]:
        q = select(SkillRecord).order_by(SkillRecord.risk_score.desc())
        if scan_id:
            q = q.where(SkillRecord.scan_id == scan_id)
        if risk_level:
            q = q.where(SkillRecord.risk_level == risk_level)
        q = q.limit(limit).offset(offset)
        result = await self._db.execute(q)
        return list(result.scalars().all())

    async def get_by_name(self, name: str) -> SkillRecord | None:
        result = await self._db.execute(
            select(SkillRecord)
            .where(SkillRecord.name == name)
            .order_by(SkillRecord.detected_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()


class PolicyRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def get(self, policy_id: str) -> PolicyRecord | None:
        return await self._db.get(PolicyRecord, policy_id)

    async def list(self, limit: int = 100, offset: int = 0) -> list[PolicyRecord]:
        result = await self._db.execute(
            select(PolicyRecord)
            .order_by(PolicyRecord.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    async def list_enabled(self) -> list[PolicyRecord]:
        result = await self._db.execute(
            select(PolicyRecord)
            .where(PolicyRecord.enabled == True)  # noqa: E712
            .order_by(PolicyRecord.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_by_name(self, name: str) -> PolicyRecord | None:
        result = await self._db.execute(select(PolicyRecord).where(PolicyRecord.name == name))
        return result.scalars().first()

    async def create(self, data: dict[str, Any]) -> PolicyRecord:
        record = PolicyRecord(**data)
        self._db.add(record)
        await self._db.flush()
        await self._db.commit()
        return record

    async def update(self, policy_id: str, data: dict[str, Any]) -> PolicyRecord | None:
        record = await self.get(policy_id)
        if not record:
            return None
        for k, v in data.items():
            setattr(record, k, v)
        await self._db.flush()
        await self._db.commit()
        return record

    async def delete(self, policy_id: str) -> bool:
        record = await self.get(policy_id)
        if not record:
            return False
        await self._db.delete(record)
        await self._db.flush()
        await self._db.commit()
        return True
