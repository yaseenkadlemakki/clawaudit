"""ClawAudit FastAPI application entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from backend.api.routes import (
    chat,
    findings,
    graph,
    hooks,
    lifecycle,
    policies,
    remediation,
    scans,
    skills,
    ws,
)
from backend.api.schemas import DashboardResponse
from backend.config import settings
from backend.database import AsyncSessionLocal, get_db, init_db
from backend.engine.knowledge_graph import knowledge_graph
from backend.models.finding import FindingRecord
from backend.models.scan import ScanRun
from backend.models.skill import SkillRecord

logger = logging.getLogger(__name__)

# Global policy sync service — initialized in lifespan startup
policy_sync = None


POLICY_ENGINE_SCAN_ID = "policy-engine"
POLICY_DIR = None  # Optional YAML fallback dir


async def _run_startup_migrations() -> None:
    """Add new columns to existing SQLite tables (idempotent)."""

    from sqlalchemy import text

    migrations = [
        # policies table
        "ALTER TABLE policies ADD COLUMN condition TEXT NOT NULL DEFAULT 'equals'",
        "ALTER TABLE policies ADD COLUMN value TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE policies ADD COLUMN priority INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE policies ADD COLUMN builtin BOOLEAN NOT NULL DEFAULT 0",
        "ALTER TABLE policies ADD COLUMN tags TEXT",
        "ALTER TABLE policies ADD COLUMN violation_count INTEGER DEFAULT 0",
        "ALTER TABLE policies ADD COLUMN last_triggered_at DATETIME",
        # chat_messages table
        "ALTER TABLE chat_messages ADD COLUMN conversation_id TEXT",
        # skills table
        "ALTER TABLE skills ADD COLUMN quarantined BOOLEAN NOT NULL DEFAULT 0",
        "ALTER TABLE skills ADD COLUMN quarantined_at DATETIME",
        "ALTER TABLE skills ADD COLUMN quarantine_reason TEXT",
    ]
    async with AsyncSessionLocal() as db:
        for stmt in migrations:
            try:
                await db.execute(text(stmt))
                await db.commit()
            except Exception as exc:
                await db.rollback()
                logger.debug("Migration skipped (likely already applied): %s — %s", stmt[:60], exc)


async def _ensure_policy_engine_scan_row() -> None:
    """Insert sentinel scan_runs row for policy violation findings (idempotent)."""
    async with AsyncSessionLocal() as db:
        existing = await db.get(ScanRun, POLICY_ENGINE_SCAN_ID)
        if not existing:
            db.add(
                ScanRun(
                    id=POLICY_ENGINE_SCAN_ID,
                    status="completed",
                    triggered_by="system",
                )
            )
            await db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the database on startup."""
    await init_db()
    await _run_startup_migrations()
    await _ensure_policy_engine_scan_row()

    from backend.seeds.starter_policies import seed_starter_policies
    from sentinel.policy.sync import PolicySyncService

    global policy_sync
    policy_sync = PolicySyncService(AsyncSessionLocal, fallback_dir=POLICY_DIR)
    await seed_starter_policies()
    await policy_sync.reload()

    logger.info(
        "ClawAudit API v%s started on %s:%s", settings.API_VERSION, settings.HOST, settings.PORT
    )
    yield


app = FastAPI(
    title=settings.API_TITLE,
    description=settings.API_DESCRIPTION,
    version=settings.API_VERSION,
    lifespan=lifespan,
)

_MAX_BODY_BYTES = 64 * 1024  # 64 KB


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """Reject requests whose Content-Length exceeds the limit.

    Note: This checks the declared Content-Length header. Chunked-encoded
    requests without Content-Length are handled by field-level Pydantic limits.
    """

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
            except ValueError:
                # Malformed Content-Length — let the request through; Pydantic handles field limits
                return await call_next(request)
            if length > _MAX_BODY_BYTES:
                return Response(
                    content='{"detail": "Request body too large"}',
                    status_code=413,
                    media_type="application/json",
                )
        return await call_next(request)


# Bearer token auth — must come before CORS so auth runs first
from backend.middleware.auth import AuthMiddleware  # noqa: E402

app.add_middleware(AuthMiddleware)

# Body size limit — added after auth so it's outermost (runs first in Starlette LIFO order)
app.add_middleware(MaxBodySizeMiddleware)

# CORS — allow_credentials=True requires explicit origins (never "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# Routers
app.include_router(scans.router, prefix="/api/v1/scans")
app.include_router(findings.router, prefix="/api/v1/findings")
app.include_router(skills.router, prefix="/api/v1/skills")
app.include_router(policies.router, prefix="/api/v1/policies")
app.include_router(graph.router, prefix="/api/v1/graph")
app.include_router(ws.router)  # WebSocket at /ws/scans/{id}/stream
app.include_router(chat.router)  # Chat at /api/v1/chat
app.include_router(remediation.router)  # Remediation at /api/v1/remediation
app.include_router(lifecycle.router, prefix="/api/v1/lifecycle")  # Skill lifecycle management
app.include_router(hooks.router, prefix="/api/v1/hooks")  # Runtime hook integration


@app.get("/api/v1/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "version": settings.API_VERSION}


@app.get("/api/v1/dashboard", response_model=DashboardResponse)
async def dashboard_summary(db: AsyncSession = Depends(get_db)):
    """Return overall security posture summary."""
    # Total skills
    total_skills_result = await db.execute(select(func.count()).select_from(SkillRecord))
    total_skills = total_skills_result.scalar_one()

    # Critical findings
    crit_result = await db.execute(
        select(func.count()).select_from(FindingRecord).where(FindingRecord.severity == "CRITICAL")
    )
    critical_findings = crit_result.scalar_one()

    # Risk distribution from knowledge graph
    graph_data = knowledge_graph.export_graph()
    risk_dist: dict[str, int] = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for node in graph_data.get("nodes", []):
        if node["kind"] == "skill":
            level = node["attrs"].get("risk_level", "Low")
            risk_dist[level] = risk_dist.get(level, 0) + 1

    # Overall score: average trust_score_value from most recent scan's skills
    overall_score_result = await db.execute(select(func.avg(SkillRecord.risk_score)))
    avg_risk = overall_score_result.scalar_one() or 0
    overall_score = max(0, 100 - int(avg_risk))

    # Recent scans
    recent_result = await db.execute(select(ScanRun).order_by(ScanRun.started_at.desc()).limit(5))
    recent_scans = [s.to_dict() for s in recent_result.scalars().all()]

    return DashboardResponse(
        overall_score=overall_score,
        total_skills=total_skills,
        critical_findings=critical_findings,
        risk_distribution=risk_dist,
        recent_scans=recent_scans,
    )


def start():
    """CLI entrypoint: launch uvicorn server."""
    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        log_level=settings.LOG_LEVEL,
        reload=False,
    )


if __name__ == "__main__":
    start()
