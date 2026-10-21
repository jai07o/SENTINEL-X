from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field


class TargetScopeCreate(BaseModel):
    target: str = Field(..., description="Target domain, IP, or URL")
    target_type: str = "DOMAIN"  # DOMAIN, IP_RANGE, SINGLE_IP, URL
    owner_organization: str
    authorization_reference: str
    approved_by: str
    expires_at: datetime
    allowed_methods: List[str] = ["HTTP_HEADERS", "TLS_CIPHERS", "PORT_SCAN_SAFE", "VERSION_AUDIT"]
    excluded_targets: List[str] = []
    rate_limit_rps: int = 5


class TargetScopeResponse(BaseModel):
    id: str
    project_id: str
    target: str
    target_type: str
    owner_organization: str
    authorization_reference: str
    approved_by: str
    valid_from: datetime
    expires_at: datetime
    allowed_methods: str
    excluded_targets: str
    rate_limit_rps: int
    is_active: bool

    class Config:
        from_attributes = True


class VulnerabilityFindingCreate(BaseModel):
    title: str
    target: str
    severity: str = "MEDIUM"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    cvss_score: float = 5.0
    confidence: float = 0.90
    owasp_category: Optional[str] = None
    cwe_id: Optional[str] = None
    description: str
    evidence_data: Optional[str] = None
    remediation: str


class VulnerabilityFindingResponse(BaseModel):
    id: str
    finding_id: str
    project_id: str
    title: str
    target: str
    severity: str
    cvss_score: float
    confidence: float
    owasp_category: Optional[str] = None
    cwe_id: Optional[str] = None
    description: str
    evidence_data: Optional[str] = None
    remediation: str
    discovered_at: datetime

    class Config:
        from_attributes = True


class AssessmentProjectCreate(BaseModel):
    name: str
    description: str
    target_scopes: List[TargetScopeCreate] = []


class AssessmentProjectResponse(BaseModel):
    id: str
    project_code: str
    name: str
    description: str
    created_at: datetime
    created_by_id: str
    target_scopes: List[TargetScopeResponse] = []
    findings: List[VulnerabilityFindingResponse] = []

    class Config:
        from_attributes = True


class ScopeValidationRequest(BaseModel):
    project_id: str
    requested_target: str
    method: str


class ScopeValidationResponse(BaseModel):
    is_authorized: bool
    scope_id: Optional[str] = None
    rejection_reason: Optional[str] = None
    rate_limit_rps: int = 5
