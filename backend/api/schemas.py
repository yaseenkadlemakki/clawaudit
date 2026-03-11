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
    condition: str = "equals"
    value: str = ""
    severity: str
    action: str
    enabled: bool = True
    description: str | None = None
    priority: int = 0
    tags: list[str] = []
    builtin: bool = False


class PolicyUpdate(BaseModel):
    name: str | None = None
    domain: str | None = None
    check: str | None = None
    condition: str | None = None
    value: str | None = None
    severity: str | None = None
    action: str | None = None
    enabled: bool | None = None
    description: str | None = None
    priority: int | None = None
    tags: list[str] | None = None


class PolicyResponse(BaseModel):
    id: str
    name: str
    domain: str
    check: str
    condition: str = "equals"
    value: str = ""
    severity: str
    action: str
    enabled: bool
    description: str | None
    created_at: str | None
    updated_at: str | None
    priority: int = 0
    builtin: bool = False
    tags: str | None = None
    violation_count: int = 0
    last_triggered_at: str | None = None

    model_config = {"from_attributes": True}


class ToolCallEvaluationRequest(BaseModel):
    tool: str
    params: dict[str, Any]
    skill_name: str | None = None
    skill_signed: bool = False
    skill_publisher: str | None = None
    skill_path: str | None = None
    session_id: str | None = None


class PolicyEvaluationResponse(BaseModel):
    action: str
    reason: str
    matched_rules: list[str]


class PolicyStatsResponse(BaseModel):
    active_count: int
    violations_today: int
    blocked_today: int
    alerted_today: int
    quarantined_skills: int


class DashboardResponse(BaseModel):
    overall_score: int
    total_skills: int
    critical_findings: int
    risk_distribution: dict[str, int]
    recent_scans: list[dict]
