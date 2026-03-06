"""ClawAudit FastAPI application entrypoint."""
from __future__ import annotations

import logging

import uvicorn
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.routes import scans, findings, skills, policies, graph, ws
from backend.api.schemas import DashboardResponse
from backend.config import settings
from backend.database import get_db, init_db
from backend.engine.knowledge_graph import knowledge_graph
from backend.models.finding import FindingRecord
from backend.models.scan import ScanRun
from backend.models.skill import SkillRecord

logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.API_TITLE,
    description=settings.API_DESCRIPTION,
    version=settings.API_VERSION,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(scans.router, prefix="/api/v1/scans")
app.include_router(findings.router, prefix="/api/v1/findings")
app.include_router(skills.router, prefix="/api/v1/skills")
app.include_router(policies.router, prefix="/api/v1/policies")
app.include_router(graph.router, prefix="/api/v1/graph")
app.include_router(ws.router)  # WebSocket at /ws/scans/{id}/stream


@app.on_event("startup")
async def startup():
    """Initialize the database on startup."""
    await init_db()
    logger.info("ClawAudit API v%s started on %s:%s", settings.API_VERSION, settings.HOST, settings.PORT)


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
