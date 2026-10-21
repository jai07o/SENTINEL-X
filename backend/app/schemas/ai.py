from typing import Optional, List
from pydantic import BaseModel, Field


class AIExplanationRequest(BaseModel):
    incident_id: str
    target_audience: str = "security_analyst"  # security_analyst | beginner_friendly | executive
    include_defensive_remediation: bool = True


class AISafeInvestigativeStep(BaseModel):
    step_number: int
    action_description: str
    rationale: str
    tool_or_command: str
    safety_precaution: str


class AIDefensiveReference(BaseModel):
    title: str
    source: str  # MITRE ATT&CK, NIST SP 800-61, OWASP, CIS Benchmark
    url_or_reference: str
    applicability: str


class AIInvestigationReport(BaseModel):
    incident_id: str
    executive_summary: str
    detection_rationale: str
    cited_event_ids: List[str] = Field(
        ..., description="Exact internal event IDs cited from genuine evidence"
    )
    missing_evidence_identified: List[str]
    safe_investigative_steps: List[AISafeInvestigativeStep]
    defensive_references: List[AIDefensiveReference]
    prompt_injection_defense_applied: bool = True
    secrets_redacted_count: int = 0
    ai_provider: str = "SENTINEL-X Defensive Intelligence"
