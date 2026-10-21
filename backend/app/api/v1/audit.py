from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from backend.app.database import get_db
from backend.app.core.permissions import get_current_user, require_admin
from backend.app.models.auth import User
from backend.app.models.report import AuditLog

router = APIRouter(prefix="/audit", tags=["Audit Logs & System Integrity"])


@router.get("/")
async def list_audit_logs(
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """List system audit log trail (Admin only)."""
    query = select(AuditLog).order_by(desc(AuditLog.timestamp))
    if action:
        query = query.where(AuditLog.action == action)
    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)
    query = query.limit(limit)

    res = await db.execute(query)
    logs = res.scalars().all()
    return logs
