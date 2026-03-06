"""Pydantic response models for the REST API."""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class FindingResponse(BaseModel):
    id: str
    check_id: str
    domain: str
    title: str
    description: str
    severity: str
    result: str
    evidence: str
    location: str
    remediation: str
    detected_at: datetime
    resolved_at: Optional[datetime] = None
    run_id: str


class PolicyRuleResponse(BaseModel):
    id: str
    domain: str
    check: str
    condition: str
    value: str
    severity: str
    action: str
    message: str


class SkillResponse(BaseModel):
    name: str
    path: str
    trust_score: str
    trust_score_value: int
    shell_access: bool
    injection_risk: str
    credential_exposure: bool


class AlertResponse(BaseModel):
    ts: str
    finding_id: str
    check_id: str
    severity: str
    action: str
    message: str
    acknowledged: bool = False
