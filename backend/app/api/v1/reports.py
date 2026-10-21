import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from backend.app.database import get_db
from backend.app.core.permissions import get_current_user, require_analyst, require_viewer
from backend.app.models.auth import User
from backend.app.models.report import SecurityReport
from backend.app.schemas.report import ReportGenerateRequest, SecurityReportResponse
from backend.app.services.report_service import report_service

router = APIRouter(prefix="/reports", tags=["Security Reporting & Export"])


@router.get("/", response_model=List[SecurityReportResponse])
async def list_reports(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    """List all generated security reports and dossiers."""
    res = await db.execute(select(SecurityReport).order_by(desc(SecurityReport.created_at)))
    return res.scalars().all()


@router.post("/generate", response_model=SecurityReportResponse)
async def generate_custom_report(
    req: ReportGenerateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Generate and archive a security dossier (INCIDENT_DOSSIER, VULN_ASSESSMENT, FORENSIC_CASE)."""
    rpt_num = f"RPT-{datetime.utcnow().strftime('%Y')}-{uuid.uuid4().hex[:4].upper()}"
    
    # Generic template content
    markdown_content = f"""# {req.title}
**Report Number:** {rpt_num}  
**Classification:** DEFENSIVE SECURITY REPORT  
**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Analyst:** {current_user.username}  

## Executive Summary
This report summarizes findings and forensic telemetry collected during operations under profile `{req.report_type}`.
"""
    report = SecurityReport(
        report_number=rpt_num,
        title=req.title,
        report_type=req.report_type,
        generated_by_id=current_user.id,
        content_markdown=markdown_content,
        content_json="{}",
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return report


@router.get("/{report_id}")
async def get_report_content(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    """Retrieve full Markdown content of a security report."""
    res = await db.execute(select(SecurityReport).where(SecurityReport.id == report_id))
    report = res.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {
        "report_number": report.report_number,
        "title": report.title,
        "report_type": report.report_type,
        "content_markdown": report.content_markdown,
        "created_at": report.created_at,
    }


@router.delete("/{report_id}")
async def delete_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    """Delete a security report."""
    from backend.app.services.data_management_service import data_management_service
    deleted = await data_management_service.delete_report(db, report_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"success": True, "message": f"Report {report_id} deleted"}

