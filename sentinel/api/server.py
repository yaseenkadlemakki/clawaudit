"""FastAPI application (Phase 2 — disabled by default in v1)."""

from __future__ import annotations

from fastapi import FastAPI

from sentinel.api.routes import alerts, findings, policies, skills

app = FastAPI(
    title="ClawAudit Sentinel API",
    description="Security monitoring API for OpenClaw deployments",
    version="1.0.0",
)

app.include_router(findings.router)
app.include_router(policies.router)
app.include_router(skills.router)
app.include_router(alerts.router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "clawaudit-sentinel"}


def start(host: str = "127.0.0.1", port: int = 18790) -> None:
    """Start the API server."""
    import uvicorn

    uvicorn.run(app, host=host, port=port)
