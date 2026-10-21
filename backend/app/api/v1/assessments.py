import uuid
from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from backend.app.database import get_db
from backend.app.core.permissions import get_current_user, require_analyst, require_viewer
from backend.app.models.auth import User
from backend.app.models.assessment import AssessmentProject, TargetScope, VulnerabilityFinding
from backend.app.schemas.assessment import (
    AssessmentProjectCreate,
    AssessmentProjectResponse,
    TargetScopeCreate,
    TargetScopeResponse,
    VulnerabilityFindingResponse,
)
from backend.app.services.assessment_service import assessment_service

router = APIRouter(prefix="/assessments", tags=["Authorized Penetration Testing & Vulnerability Assessment"])


@router.post("/projects", response_model=AssessmentProjectResponse)
async def create_project(
    project_in: AssessmentProjectCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Create an authorized security assessment project workspace."""
    code = f"ASSESS-{datetime.utcnow().strftime('%Y')}-{uuid.uuid4().hex[:4].upper()}"
    project = AssessmentProject(
        project_code=code,
        name=project_in.name,
        description=project_in.description,
        created_by_id=current_user.id,
    )
    db.add(project)
    await db.flush()

    for s_in in project_in.target_scopes:
        scope = TargetScope(
            project_id=project.id,
            target=s_in.target,
            target_type=s_in.target_type,
            owner_organization=s_in.owner_organization,
            authorization_reference=s_in.authorization_reference,
            approved_by=s_in.approved_by,
            expires_at=s_in.expires_at,
            allowed_methods=str(s_in.allowed_methods),
            excluded_targets=str(s_in.excluded_targets),
            rate_limit_rps=s_in.rate_limit_rps,
        )
        db.add(scope)

    await db.commit()
    await db.refresh(project)

    res = await db.execute(
        select(AssessmentProject)
        .options(
            selectinload(AssessmentProject.target_scopes),
            selectinload(AssessmentProject.findings),
        )
        .where(AssessmentProject.id == project.id)
    )
    return res.scalar_one()


@router.get("/projects", response_model=List[AssessmentProjectResponse])
async def list_projects(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    """List all authorized assessment projects, active scopes, and discovered findings."""
    res = await db.execute(
        select(AssessmentProject)
        .options(
            selectinload(AssessmentProject.target_scopes),
            selectinload(AssessmentProject.findings),
        )
        .order_by(AssessmentProject.created_at.desc())
    )
    return res.scalars().all()


@router.post("/projects/{project_id}/scopes", response_model=TargetScopeResponse)
async def add_target_scope(
    project_id: str,
    scope_in: TargetScopeCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Register explicitly authorized target scope with non-bypassable authorization reference and expiration."""
    proj_res = await db.execute(select(AssessmentProject).where(AssessmentProject.id == project_id))
    if not proj_res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")

    scope = TargetScope(
        project_id=project_id,
        target=scope_in.target,
        target_type=scope_in.target_type,
        owner_organization=scope_in.owner_organization,
        authorization_reference=scope_in.authorization_reference,
        approved_by=scope_in.approved_by,
        expires_at=scope_in.expires_at,
        allowed_methods=str(scope_in.allowed_methods),
        excluded_targets=str(scope_in.excluded_targets),
        rate_limit_rps=scope_in.rate_limit_rps,
        is_active=True,
    )
    db.add(scope)
    await db.commit()
    await db.refresh(scope)
    return scope


@router.post("/projects/{project_id}/scan-headers", response_model=List[VulnerabilityFindingResponse])
async def scan_http_headers(
    project_id: str,
    target: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Executes safe HTTP security headers check against OWASP WSTG-CONF-07/12.
    MANDATORY SCOPE GATE ENFORCED BEFORE ANY NETWORK TRANSMISSION.
    """
    proj_res = await db.execute(
        select(AssessmentProject)
        .options(selectinload(AssessmentProject.target_scopes))
        .where(AssessmentProject.id == project_id)
    )
    project = proj_res.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # MANDATORY SCOPE GATE VERIFICATION
    is_authorized, reason = assessment_service.validate_target_scope(
        target=target,
        authorized_scopes=project.target_scopes,
        method="HTTP_HEADERS",
        allow_private_lab=True,
    )
    if not is_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"SCOPE GATE ENFORCEMENT BLOCKED TARGET: {reason}",
        )

    # Perform safe scan
    raw_findings = await assessment_service.scan_http_security_headers(target)

    saved_findings = []
    for f in raw_findings:
        finding_id = f"VULN-{datetime.utcnow().strftime('%Y')}-{uuid.uuid4().hex[:4].upper()}"
        model = VulnerabilityFinding(
            finding_id=finding_id,
            project_id=project.id,
            title=f["title"],
            target=f["target"],
            severity=f["severity"],
            cvss_score=f["cvss_score"],
            confidence=f["confidence"],
            owasp_category=f.get("owasp_category"),
            description=f["description"],
            evidence_data=f.get("evidence_data"),
            remediation=f["remediation"],
        )
        db.add(model)
        saved_findings.append(model)

    await db.commit()
    for sf in saved_findings:
        await db.refresh(sf)

    return saved_findings


@router.post("/projects/{project_id}/scan-tls")
async def scan_tls_configuration(
    project_id: str,
    hostname: str,
    port: int = 443,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Executes safe TLS cipher and certificate assessment against OWASP WSTG-CRYP-01.
    MANDATORY SCOPE GATE ENFORCED.
    """
    proj_res = await db.execute(
        select(AssessmentProject)
        .options(selectinload(AssessmentProject.target_scopes))
        .where(AssessmentProject.id == project_id)
    )
    project = proj_res.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # SCOPE GATE
    is_authorized, reason = assessment_service.validate_target_scope(
        target=hostname,
        authorized_scopes=project.target_scopes,
        method="TLS_CIPHERS",
        allow_private_lab=True,
    )
    if not is_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"SCOPE GATE ENFORCEMENT BLOCKED TARGET: {reason}",
        )

    tls_result = assessment_service.check_tls_configuration(hostname, port)
    
    # Store any critical TLS findings
    for f in tls_result.get("findings", []):
        finding_id = f"VULN-{datetime.utcnow().strftime('%Y')}-{uuid.uuid4().hex[:4].upper()}"
        model = VulnerabilityFinding(
            finding_id=finding_id,
            project_id=project.id,
            title=f["title"],
            target=f["target"],
            severity=f["severity"],
            cvss_score=f["cvss_score"],
            confidence=f["confidence"],
            owasp_category=f.get("owasp_category"),
            description=f["description"],
            evidence_data=f.get("evidence_data"),
            remediation=f["remediation"],
        )
        db.add(model)

    await db.commit()
    return tls_result
