from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel


class ReportGenerateRequest(BaseModel):
    title: str
    report_type: str  # INCIDENT_DOSSIER, VULN_ASSESSMENT, FORENSIC_CASE, COMPLIANCE_SUMMARY
    resource_id: Optional[str] = None  # incident_id, project_id, or case_id
    export_format: str = "markdown"    # markdown, json, html


class SecurityReportResponse(BaseModel):
    id: str
    report_number: str
    title: str
    report_type: str
    generated_by_id: str
    created_at: datetime
    content_markdown: str
    content_json: str
    export_filepath: Optional[str] = None

    class Config:
        from_attributes = True
