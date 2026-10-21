from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel


class CustodyRecordCreate(BaseModel):
    action: str  # INTAKE, HASH_VERIFIED, COPY_CREATED, EXPORTED, ARCHIVED
    notes: Optional[str] = None


class CustodyRecordResponse(BaseModel):
    id: str
    evidence_id: str
    analyst_id: str
    action: str
    timestamp: datetime
    verified_hash: str
    hash_matched: bool
    notes: Optional[str] = None

    class Config:
        from_attributes = True


class EvidenceItemCreate(BaseModel):
    name: str
    source_description: str
    original_filename: str
    case_id: Optional[str] = None


class EvidenceItemResponse(BaseModel):
    id: str
    evidence_number: str
    name: str
    source_description: str
    original_filename: str
    sha256_hash: str
    md5_hash: Optional[str] = None
    file_size_bytes: int
    mime_type: str
    is_read_only: bool
    is_derived_artifact: bool
    parent_evidence_id: Optional[str] = None
    acquired_at: datetime
    acquired_by_id: str
    case_id: Optional[str] = None
    custody_records: List[CustodyRecordResponse] = []

    class Config:
        from_attributes = True


class HashVerificationResponse(BaseModel):
    evidence_id: str
    expected_sha256: str
    calculated_sha256: str
    is_integrity_valid: bool
    verification_timestamp: datetime
