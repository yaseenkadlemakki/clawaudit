"""Pydantic request/response schemas for the ClawAudit API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class ScanCreate(BaseModel):
    triggered_by: str = "api"


class ScanResponse(BaseModel):
    id: str
    started_at: str | None
    completed_at: str | None
    status: str
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    skills_scanned: int = 0
    triggered_by: str
    error_message: str | None = None

    model_config = {"from_attributes": True}


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    check_id: str
    domain: str
    title: str
    description: str
    severity: str
    result: str
    evidence: str
    location: str
    remediation: str
    detected_at: str | None
    skill_name: str | None = None

    model_config = {"from_attributes": True}


class SkillResponse(BaseModel):
    id: str
    scan_id: str
    name: str
    source: str
    path: str
    shell_access: bool
    outbound_domains: Any  # parsed list
    injection_risk: str
    trust_score: str
    risk_score: int
    risk_level: str
    detected_at: str | None

    model_config = {"from_attributes": True}


class PolicyCreate(BaseModel):
    name: str
    domain: str
    check: str
    severity: str
    action: str
    enabled: bool = True
    description: str | None = None


class PolicyUpdate(BaseModel):
    name: str | None = None
    domain: str | None = None
    check: str | None = None
    severity: str | None = None
    action: str | None = None
    enabled: bool | None = None
    description: str | None = None


class PolicyResponse(BaseModel):
    id: str
    name: str
    domain: str
    check: str
    severity: str
    action: str
    enabled: bool
    description: str | None
    created_at: str | None
    updated_at: str | None

    model_config = {"from_attributes": True}


class DashboardResponse(BaseModel):
    overall_score: int
    total_skills: int
    critical_findings: int
    risk_distribution: dict[str, int]
    recent_scans: list[dict]
