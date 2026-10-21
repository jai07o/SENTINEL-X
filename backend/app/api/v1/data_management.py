"""
SENTINEL-X Data Management & Storage Purge API Router
Enables database row telemetry inspection, granular record deletion,
and complete category-wide data purge requests.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.core.permissions import get_current_user, require_role
from backend.app.models.auth import User

from backend.app.services.data_management_service import data_management_service

router = APIRouter(prefix="/data-management", tags=["Data Management & Purge"])


class PurgeRequest(BaseModel):
    category: str = Field(..., description="Category to purge: 'events', 'incidents', 'hosts', 'evidence', 'forensics', 'malware', 'network', 'assessments', 'reports', 'audit', or 'all'")
    confirm: bool = Field(..., description="Must be true to confirm permanent data deletion")


@router.get("/stats")
async def get_data_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Returns row counts across all operational tables."""
    return await data_management_service.get_storage_statistics(db)


@router.post("/purge")
async def purge_data_category(
    request: PurgeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    """
    Purges data for a specific category or wipes all operational data.
    Requires confirm=True.
    """
    if not request.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Data purge requires explicit confirmation (confirm: true).",
        )

    valid_categories = {
        "events", "incidents", "hosts", "evidence", "forensics",
        "malware", "network", "assessments", "reports", "audit", "all"
    }
    if request.category.lower() not in valid_categories:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid category '{request.category}'. Valid categories are: {sorted(list(valid_categories))}",
        )

    result = await data_management_service.purge_category(db, request.category)
    return result


@router.delete("/entity/{entity_type}/{entity_id}")
async def delete_specific_entity(
    entity_type: str,
    entity_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    """Directly deletes a specific entity by type and ID."""
    t = entity_type.lower().strip()
    deleted = False

    if t in ("event", "events"):
        deleted = await data_management_service.delete_event(db, entity_id)
    elif t in ("incident", "incidents"):
        deleted = await data_management_service.delete_incident(db, entity_id)
    elif t in ("host", "hosts"):
        deleted = await data_management_service.delete_host(db, entity_id)
    elif t in ("case", "forensics", "forensic_case"):
        deleted = await data_management_service.delete_forensic_case(db, entity_id)
    elif t in ("evidence", "evidence_item"):
        deleted = await data_management_service.delete_evidence_item(db, entity_id)
    elif t in ("malware", "sample", "malware_sample"):
        deleted = await data_management_service.delete_malware_sample(db, entity_id)
    elif t in ("report", "reports"):
        deleted = await data_management_service.delete_report(db, entity_id)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown entity type '{entity_type}'.",
        )

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{entity_type} with ID '{entity_id}' not found.",
        )

    return {"success": True, "message": f"Successfully deleted {entity_type} '{entity_id}'."}
