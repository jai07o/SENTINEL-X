from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from backend.app.services.folder_scanner_service import folder_scanner_service
from backend.app.core.permissions import get_current_user
from backend.app.models.auth import User

router = APIRouter()


class ScanFolderRequest(BaseModel):
    directory_path: Optional[str] = None
    max_files: Optional[int] = 500


@router.post("/scan-workspace")
async def scan_workspace_folder(
    req: ScanFolderRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Recursively scans 'everything in this folder', computing cryptographic hashes,
    evaluating Shannon entropy, and analyzing suspicious script patterns.
    """
    return folder_scanner_service.scan_directory(
        target_dir=req.directory_path,
        max_files=req.max_files or 500
    )


@router.get("/quick-scan")
async def quick_scan_workspace(
    limit: int = Query(200, description="Max files to scan"),
    current_user: User = Depends(get_current_user),
):
    """
    Performs immediate scan of the current project directory.
    """
    return folder_scanner_service.scan_directory(max_files=limit)
