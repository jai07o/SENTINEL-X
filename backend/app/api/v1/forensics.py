import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from backend.app.database import get_db
from backend.app.core.permissions import get_current_user, require_analyst, require_viewer
from backend.app.models.auth import User
from backend.app.models.forensic import ForensicCase, CaseTimelineItem, ForensicNote
from backend.app.models.evidence import EvidenceItem, ChainOfCustodyRecord
from backend.app.schemas.forensic import (
    ForensicCaseCreate,
    ForensicCaseResponse,
    TimelineItemCreate,
    TimelineItemResponse,
    ForensicNoteCreate,
    ForensicNoteResponse,
)
from backend.app.schemas.evidence import (
    EvidenceItemResponse,
    CustodyRecordCreate,
    CustodyRecordResponse,
    HashVerificationResponse,
)
from backend.app.services.forensics_service import forensics_service

router = APIRouter(prefix="/forensics", tags=["Digital Forensics & Chain of Custody"])


@router.post("/cases", response_model=ForensicCaseResponse)
async def create_case(
    case_in: ForensicCaseCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Create a new digital forensics case workspace."""
    case_num = f"CASE-{datetime.utcnow().strftime('%Y')}-{uuid.uuid4().hex[:4].upper()}"
    new_case = ForensicCase(
        case_number=case_num,
        title=case_in.title,
        description=case_in.description,
        priority=case_in.priority.upper(),
        status="ACTIVE",
        lead_analyst_id=current_user.id,
    )
    db.add(new_case)
    await db.commit()
    await db.refresh(new_case)

    # Initial timeline item
    init_timeline = CaseTimelineItem(
        case_id=new_case.id,
        timestamp=datetime.utcnow(),
        title="Case Opened",
        description=f"Forensics case opened by lead analyst {current_user.username}.",
        source_type="INVESTIGATION",
    )
    db.add(init_timeline)
    await db.commit()

    res = await db.execute(
        select(ForensicCase)
        .options(
            selectinload(ForensicCase.evidence_items).selectinload(EvidenceItem.custody_records),
            selectinload(ForensicCase.timeline_items),
            selectinload(ForensicCase.notes),
        )
        .where(ForensicCase.id == new_case.id)
    )
    return res.scalar_one()


@router.get("/cases", response_model=List[ForensicCaseResponse])
async def list_cases(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    """List all active and archived digital forensics cases."""
    res = await db.execute(
        select(ForensicCase)
        .options(
            selectinload(ForensicCase.evidence_items).selectinload(EvidenceItem.custody_records),
            selectinload(ForensicCase.timeline_items),
            selectinload(ForensicCase.notes),
        )
        .order_by(ForensicCase.created_at.desc())
    )
    return res.scalars().all()


@router.get("/cases/{case_id}", response_model=ForensicCaseResponse)
async def get_case(
    case_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    """Retrieve full forensics case details, chain of custody logs, and timeline."""
    res = await db.execute(
        select(ForensicCase)
        .options(
            selectinload(ForensicCase.evidence_items).selectinload(EvidenceItem.custody_records),
            selectinload(ForensicCase.timeline_items),
            selectinload(ForensicCase.notes),
        )
        .where((ForensicCase.id == case_id) | (ForensicCase.case_number == case_id))
    )
    case = res.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.post("/cases/{case_id}/evidence", response_model=EvidenceItemResponse)
async def intake_evidence(
    case_id: str,
    name: str = Form(...),
    source_description: str = Form(...),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Intake digital evidence item into isolated vault with cryptographic hash fingerprinting.
    Establishes immutable chain-of-custody log.
    """
    case_res = await db.execute(select(ForensicCase).where(ForensicCase.id == case_id))
    case = case_res.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    contents = await file.read()
    evidence_num = f"EV-{datetime.utcnow().strftime('%Y')}-{uuid.uuid4().hex[:4].upper()}"

    stored = forensics_service.store_evidence_file(
        file_bytes=contents,
        original_filename=file.filename,
        evidence_number=evidence_num,
    )

    evidence_item = EvidenceItem(
        evidence_number=evidence_num,
        name=name,
        source_description=source_description,
        original_filename=file.filename,
        sha256_hash=stored["sha256_hash"],
        md5_hash=stored["md5_hash"],
        file_size_bytes=stored["file_size_bytes"],
        mime_type=file.content_type or "application/octet-stream",
        storage_path=stored["storage_path"],
        acquired_by_id=current_user.id,
        case_id=case.id,
        is_read_only=True,
    )
    db.add(evidence_item)
    await db.flush()

    # Initial Chain-of-Custody record
    custody_rec = ChainOfCustodyRecord(
        evidence_id=evidence_item.id,
        analyst_id=current_user.id,
        action="INTAKE",
        verified_hash=stored["sha256_hash"],
        hash_matched=True,
        notes=f"Evidence acquired from {source_description}. Pristine copy hashed and stored in vault.",
    )
    db.add(custody_rec)

    # Timeline event
    timeline_item = CaseTimelineItem(
        case_id=case.id,
        timestamp=datetime.utcnow(),
        title=f"Evidence Acquired: {evidence_num}",
        description=f"Evidence item '{name}' added with SHA-256 fingerprint {stored['sha256_hash'][:16]}...",
        source_type="EVIDENCE_ACQUISITION",
        evidence_id=evidence_item.id,
    )
    db.add(timeline_item)

    await db.commit()

    reloaded = await db.execute(
        select(EvidenceItem)
        .options(selectinload(EvidenceItem.custody_records))
        .where(EvidenceItem.id == evidence_item.id)
    )
    return reloaded.scalar_one()


@router.get("/evidence/{evidence_id}/verify-hash", response_model=HashVerificationResponse)
async def verify_evidence_hash(
    evidence_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    """
    Verifies cryptographic hash on disk against recorded intake hash.
    Detects unauthorized tampering or disk corruption.
    """
    res = await db.execute(select(EvidenceItem).where(EvidenceItem.id == evidence_id))
    item = res.scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=404, detail="Evidence item not found")

    is_valid, current_hash = forensics_service.verify_evidence_integrity(
        storage_path=item.storage_path,
        expected_sha256=item.sha256_hash,
    )

    # Log verification action in chain of custody
    custody_rec = ChainOfCustodyRecord(
        evidence_id=item.id,
        analyst_id=current_user.id,
        action="HASH_VERIFIED",
        verified_hash=current_hash,
        hash_matched=is_valid,
        notes=f"Periodic cryptographic integrity verification by analyst {current_user.username}.",
    )
    db.add(custody_rec)
    await db.commit()

    return HashVerificationResponse(
        evidence_id=item.id,
        expected_sha256=item.sha256_hash,
        calculated_sha256=current_hash,
        is_integrity_valid=is_valid,
        verification_timestamp=datetime.utcnow(),
    )


@router.post("/cases/{case_id}/timeline", response_model=TimelineItemResponse)
async def add_timeline_event(
    case_id: str,
    timeline_in: TimelineItemCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Add chronological event to case timeline."""
    item = CaseTimelineItem(
        case_id=case_id,
        timestamp=timeline_in.timestamp,
        title=timeline_in.title,
        description=timeline_in.description,
        source_type=timeline_in.source_type,
        evidence_id=timeline_in.evidence_id,
    )
    db.add(item)
    await db.commit()
    await db.refresh(item)
    return item


@router.delete("/cases/{case_id}")
async def delete_forensic_case(
    case_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Delete a forensic case and linked timeline/notes."""
    from backend.app.services.data_management_service import data_management_service
    deleted = await data_management_service.delete_forensic_case(db, case_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Forensic case not found")
    return {"success": True, "message": f"Forensic case {case_id} deleted"}


@router.delete("/evidence/{evidence_id}")
async def delete_evidence_item(
    evidence_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Delete an evidence item and its custody records."""
    from backend.app.services.data_management_service import data_management_service
    deleted = await data_management_service.delete_evidence_item(db, evidence_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Evidence item not found")
    return {"success": True, "message": f"Evidence item {evidence_id} deleted"}

