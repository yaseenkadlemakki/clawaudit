"""Scan lifecycle manager with async execution and WebSocket broadcast."""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import AsyncSessionLocal
from backend.engine.audit_engine import AuditEngine
from backend.engine.knowledge_graph import knowledge_graph
from backend.models.finding import FindingRecord
from backend.models.scan import ScanRun, ScanStatus
from backend.models.skill import SkillRecord
from sentinel.models.finding import Finding
from sentinel.models.skill import SkillProfile

logger = logging.getLogger(__name__)


class ScanManager:
    """
    Manages scan lifecycle: IDLE → RUNNING → (STOPPING →) COMPLETED / FAILED.

    Runs audits in background asyncio tasks, streams events to WebSocket
    subscribers, and persists results to the database.
    """

    def __init__(self) -> None:
        self._active_tasks: dict[str, asyncio.Task] = {}
        self._stop_flags: dict[str, bool] = {}
        # WebSocket subscribers: scan_id → list of queues
        self._ws_subscribers: dict[str, list[asyncio.Queue]] = {}

    # ── Public API ────────────────────────────────────────────────────────

    async def start_scan(self, triggered_by: str = "api") -> dict:
        """Create a new scan record, set status=RUNNING, and kick off async execution."""
        scan_id = str(uuid.uuid4())

        async with AsyncSessionLocal() as db:
            scan = ScanRun(
                id=scan_id,
                started_at=datetime.utcnow(),
                status=ScanStatus.RUNNING,
                triggered_by=triggered_by,
            )
            db.add(scan)
            await db.commit()
            await db.refresh(scan)
            scan_dict = scan.to_dict()

        self._stop_flags[scan_id] = False
        task = asyncio.create_task(self._execute_scan(scan_id))
        self._active_tasks[scan_id] = task
        task.add_done_callback(lambda t: self._active_tasks.pop(scan_id, None))

        logger.info("Scan %s started (triggered_by=%s)", scan_id, triggered_by)
        return scan_dict  # type: ignore[return-value]

    async def stop_scan(self, scan_id: str) -> dict | None:
        """Request stop for a running scan; set status→STOPPING."""
        async with AsyncSessionLocal() as db:
            scan = await db.get(ScanRun, scan_id)
            if not scan:
                return None
            if scan.status == ScanStatus.RUNNING:
                scan.status = ScanStatus.STOPPING
                self._stop_flags[scan_id] = True
                await db.commit()
                await db.refresh(scan)
            return scan.to_dict()

    async def get_scan(self, scan_id: str) -> dict | None:
        """Fetch a scan record by ID."""
        async with AsyncSessionLocal() as db:
            scan = await db.get(ScanRun, scan_id)
            return scan.to_dict() if scan else None

    async def list_scans(self, limit: int = 20) -> list[dict]:
        """List recent scan records."""
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(ScanRun).order_by(ScanRun.started_at.desc()).limit(limit)
            )
            scans = result.scalars().all()
            return [s.to_dict() for s in scans]

    # ── WebSocket subscription ────────────────────────────────────────────

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        """Create and register a queue for WebSocket streaming."""
        q: asyncio.Queue = asyncio.Queue()
        self._ws_subscribers.setdefault(scan_id, []).append(q)
        return q

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        """Remove a WebSocket queue."""
        subs = self._ws_subscribers.get(scan_id, [])
        if queue in subs:
            subs.remove(queue)

    def _broadcast(self, scan_id: str, event: dict[str, Any]) -> None:
        """Push an event to all WebSocket subscribers for this scan."""
        for q in self._ws_subscribers.get(scan_id, []):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

    # ── Internal execution ────────────────────────────────────────────────

    async def _execute_scan(self, scan_id: str) -> None:
        """Run the full audit pipeline, persist results, and stream events."""
        engine = AuditEngine()
        knowledge_graph.clear()

        finding_records: list[dict] = []
        skill_records: list[dict] = []

        def on_finding(finding: Finding, skill_name: str | None) -> None:
            finding_records.append({
                "id": finding.id,
                "scan_id": scan_id,
                "check_id": finding.check_id,
                "domain": finding.domain,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "result": finding.result,
                "evidence": finding.evidence,
                "location": finding.location,
                "remediation": finding.remediation,
                "detected_at": finding.detected_at,
                "skill_name": skill_name,
            })
            self._broadcast(scan_id, {
                "type": "finding",
                "data": {**finding.to_dict(), "skill_name": skill_name},
            })

        def on_skill(profile: SkillProfile, risk_score: int, risk_level: str) -> None:
            skill_records.append({
                "scan_id": scan_id,
                "name": profile.name,
                "source": profile.source,
                "path": profile.path,
                "shell_access": profile.shell_access,
                "outbound_domains": json.dumps(profile.outbound_domains),
                "injection_risk": profile.injection_risk,
                "trust_score": profile.trust_score,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "detected_at": datetime.utcnow(),
            })
            knowledge_graph.add_skill(profile, risk_score, risk_level)
            self._broadcast(scan_id, {
                "type": "skill",
                "data": {**profile.to_dict(), "risk_score": risk_score, "risk_level": risk_level},
            })

        def on_progress(current: int, total: int, skill_name: str) -> None:
            self._broadcast(scan_id, {
                "type": "progress",
                "current": current,
                "total": total,
                "skill": skill_name,
            })

        def stop_flag() -> bool:
            return self._stop_flags.get(scan_id, False)

        try:
            all_findings, _ = await engine.run_full_audit(
                run_id=scan_id,
                on_finding=on_finding,
                on_skill=on_skill,
                on_progress=on_progress,
                stop_flag=stop_flag,
            )

            # Persist to DB
            async with AsyncSessionLocal() as db:
                for fr in finding_records:
                    db.add(FindingRecord(**fr))
                for sr in skill_records:
                    db.add(SkillRecord(**sr))
                await db.flush()

                # Update scan record
                summary: dict = {}
                scan = await db.get(ScanRun, scan_id)
                if scan:
                    sev_counts = _count_severities(all_findings)
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.total_findings = len(all_findings)
                    scan.critical_count = sev_counts.get("CRITICAL", 0)
                    scan.high_count = sev_counts.get("HIGH", 0)
                    scan.medium_count = sev_counts.get("MEDIUM", 0)
                    scan.low_count = sev_counts.get("LOW", 0)
                    scan.skills_scanned = len(skill_records)
                    await db.commit()
                    summary = scan.to_dict()

            self._broadcast(scan_id, {"type": "completed", "summary": summary})
            logger.info("Scan %s completed: %d findings", scan_id, len(all_findings))

        except Exception as exc:
            logger.exception("Scan %s failed: %s", scan_id, exc)
            async with AsyncSessionLocal() as db:
                scan = await db.get(ScanRun, scan_id)
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.completed_at = datetime.utcnow()
                    scan.error_message = str(exc)
                    await db.commit()
            self._broadcast(scan_id, {"type": "error", "message": str(exc)})
        finally:
            self._stop_flags.pop(scan_id, None)


def _count_severities(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


# Module-level singleton
scan_manager = ScanManager()
