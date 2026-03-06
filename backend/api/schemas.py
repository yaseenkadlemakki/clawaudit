"""Pydantic request/response schemas for the ClawAudit API."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    triggered_by: str = "api"


class ScanResponse(BaseModel):
    id: str
    started_at: Optional[str]
    completed_at: Optional[str]
    status: str
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    skills_scanned: int = 0
    triggered_by: str
    error_message: Optional[str] = None

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
    detected_at: Optional[str]
    skill_name: Optional[str] = None

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
    detected_at: Optional[str]

    model_config = {"from_attributes": True}


class PolicyCreate(BaseModel):
    name: str
    domain: str
    check: str
    severity: str
    action: str
    enabled: bool = True
    description: Optional[str] = None


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    domain: Optional[str] = None
    check: Optional[str] = None
    severity: Optional[str] = None
    action: Optional[str] = None
    enabled: Optional[bool] = None
    description: Optional[str] = None


class PolicyResponse(BaseModel):
    id: str
    name: str
    domain: str
    check: str
    severity: str
    action: str
    enabled: bool
    description: Optional[str]
    created_at: Optional[str]
    updated_at: Optional[str]

    model_config = {"from_attributes": True}


class DashboardResponse(BaseModel):
    overall_score: int
    total_skills: int
    critical_findings: int
    risk_distribution: dict[str, int]
    recent_scans: list[dict]
