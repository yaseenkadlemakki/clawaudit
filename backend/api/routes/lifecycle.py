"""Skill lifecycle management routes — install, enable/disable, uninstall, health."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from sentinel.analyzer.skill_analyzer import SkillAnalyzer
from sentinel.config import load_config
from sentinel.lifecycle.installer import SkillInstaller
from sentinel.lifecycle.registry import SkillRegistry
from sentinel.lifecycle.toggler import SkillToggler
from sentinel.lifecycle.uninstaller import SkillUninstaller

logger = logging.getLogger(__name__)
router = APIRouter(tags=["lifecycle"])


# ── Request / Response models ──────────────────────────────────────────────────


class InstallRequest(BaseModel):
    source: str  # "file" or "url"
    path: str | None = None
    url: str | None = None


class SkillInfo(BaseModel):
    name: str
    path: str
    source: str
    version: str
    enabled: bool
    installed_at: str
    risk_level: str = "unknown"


class ToggleResponse(BaseModel):
    name: str
    enabled: bool


class UninstallResponse(BaseModel):
    name: str
    trash_path: str


class HealthResponse(BaseModel):
    name: str
    findings: list[dict[str, Any]]
    risk_level: str


# ── Helpers ────────────────────────────────────────────────────────────────────


def _get_registry() -> SkillRegistry:
    return SkillRegistry()


def _get_skills_dir() -> Path:
    cfg = load_config()
    return cfg.workspace_skills_dir


def _risk_from_score(score: int) -> str:
    if score >= 80:
        return "low"
    if score >= 60:
        return "medium"
    if score >= 40:
        return "high"
    return "critical"


# ── Routes ─────────────────────────────────────────────────────────────────────


@router.get("", response_model=list[SkillInfo])
async def list_lifecycle_skills():
    """List all skills from the registry, merged with filesystem state."""
    registry = _get_registry()
    cfg = load_config()
    registry.sync([cfg.skills_dir, cfg.workspace_skills_dir])
    records = registry.list_all()
    return [
        SkillInfo(
            name=r.name,
            path=r.path,
            source=r.source,
            version=r.version,
            enabled=r.enabled,
            installed_at=r.installed_at,
        )
        for r in records
    ]


@router.post("/install", response_model=SkillInfo)
async def install_skill(req: InstallRequest):
    """Install a skill from a local file or URL."""
    registry = _get_registry()
    skills_dir = _get_skills_dir()
    installer = SkillInstaller(skills_dir, registry)

    try:
        if req.source == "file":
            if not req.path:
                raise HTTPException(status_code=400, detail="'path' is required for file installs")
            record = installer.install_from_file(Path(req.path))
        elif req.source == "url":
            if not req.url:
                raise HTTPException(status_code=400, detail="'url' is required for URL installs")
            record = installer.install_from_url(req.url)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown source: {req.source}")
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return SkillInfo(
        name=record.name,
        path=record.path,
        source=record.source,
        version=record.version,
        enabled=record.enabled,
        installed_at=record.installed_at,
    )


@router.post("/{name}/enable", response_model=ToggleResponse)
async def enable_skill(name: str):
    """Enable a disabled skill."""
    registry = _get_registry()
    toggler = SkillToggler(registry)
    try:
        toggler.enable(name)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ToggleResponse(name=name, enabled=True)


@router.post("/{name}/disable", response_model=ToggleResponse)
async def disable_skill(name: str):
    """Disable an enabled skill."""
    registry = _get_registry()
    toggler = SkillToggler(registry)
    try:
        toggler.disable(name)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ToggleResponse(name=name, enabled=False)


@router.delete("/{name}", response_model=UninstallResponse)
async def uninstall_skill(name: str):
    """Uninstall a skill (move to trash)."""
    registry = _get_registry()
    uninstaller = SkillUninstaller(registry)
    try:
        trash_path = uninstaller.uninstall(name)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return UninstallResponse(name=name, trash_path=str(trash_path))


@router.get("/{name}/health", response_model=HealthResponse)
async def skill_health(name: str):
    """Run SkillAnalyzer on a single skill and return findings."""
    registry = _get_registry()
    record = registry.get(name)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Skill '{name}' not found")

    skill_md = Path(record.path) / "SKILL.md"
    if not skill_md.exists():
        skill_md = Path(record.path) / "SKILL.md.disabled"
    if not skill_md.exists():
        raise HTTPException(status_code=404, detail=f"SKILL.md not found for '{name}'")

    analyzer = SkillAnalyzer()
    profile = analyzer.analyze(skill_md)

    risk_level = _risk_from_score(profile.trust_score_value)
    return HealthResponse(
        name=name,
        findings=[f.to_dict() for f in profile.findings],
        risk_level=risk_level,
    )
