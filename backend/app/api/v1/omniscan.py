import os
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status
from pydantic import BaseModel, HttpUrl

from backend.app.services.omni_scanner_service import omni_threat_scanner
from backend.app.services.autonomous_sentinel_service import autonomous_sentinel_service
from backend.app.core.permissions import get_current_user
from backend.app.models.auth import User
from backend.app.config import settings

router = APIRouter()

MAX_SCAN_FILE_SIZE = 50 * 1024 * 1024  # 50MB


class ScanLinkRequest(BaseModel):
    url: str


@router.post("/link")
async def scan_link(
    req: ScanLinkRequest,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Deep-audits an input link:
    - Traces 301/302 redirect chains
    - Inspects HTTP headers, Server banner, MIME Content-Type
    - Checks obfuscated IP addresses, typo-squatting, and malicious TLDs
    - Inspects destination payload (drive-by executables, web shells)
    """
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="Target URL cannot be empty")
    return await omni_threat_scanner.scan_link(req.url.strip())


@router.post("/deep-scan")
async def scan_deep_link(
    req: ScanLinkRequest,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Deep Recursive Link, Path & Software Payload Inspector:
    - Recursively traces redirect chain
    - Downloads and statically scans any destination software payload or archive (.exe, .zip, .msi, etc.)
    - If web page, parses HTML for linked software downloads, scripts, and iframes
    - Deep-audits nested binaries inside archives until path is verified completely clean or flagged
    """
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="Target URL cannot be empty")
    return await omni_threat_scanner.scan_deep_link_and_software(req.url.strip())


# =============================================================================
# AUTONOMOUS BACKGROUND SENTINEL CONTROL (LAPTOP & MOBILE)
# =============================================================================
@router.post("/autonomous-sentinel/start")
async def start_autonomous_sentinel(
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Activates the Autonomous Real-Time Background Sentinel.
    Runs persistently in the background across laptop and mobile companion systems:
    - Inspects connected sockets & C2 trojans every 5 seconds
    - Audits camera/mic hardware handles for background spyware
    - Hunts background rogue processes and miners
    - Broadcasts live WebSocket alerts to dashboard
    """
    return await autonomous_sentinel_service.start()


@router.post("/autonomous-sentinel/stop")
async def stop_autonomous_sentinel(
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Stops and exits the Autonomous Background Sentinel loop cleanly.
    """
    return await autonomous_sentinel_service.stop()


@router.get("/autonomous-sentinel/status")
async def get_autonomous_sentinel_status(
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Retrieves real-time execution status, stats, active threats, and pulse metrics.
    """
    return autonomous_sentinel_service.get_status()



@router.post("/qr")
async def scan_qr_code(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Scans and decodes a QR code image for quishing and payload distribution:
    - Decodes QR matrix points
    - Recursively inspects destination URL redirect chain and endpoint virus payloads
    - Analyzes raw text QR codes for shellcode and automated script executions
    """
    contents = await file.read()
    if len(contents) > MAX_SCAN_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Image size exceeds {MAX_SCAN_FILE_SIZE // (1024 * 1024)}MB limit"
        )
    return await omni_threat_scanner.scan_qr_code(
        contents,
        filename=file.filename or "uploaded_qr.png"
    )


@router.post("/picture")
async def scan_picture(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Scans pictures for hidden trojans, steganography, and polyglots:
    - Detects trailing appended bytes past standard EOF (JPEG FF D9 / PNG IEND)
    - Checks EXIF metadata for injected PHP, XSS, or shellcode payloads
    - Detects embedded scripts and XXE inside SVG vector graphics
    - Analyzes Shannon entropy anomalies
    """
    contents = await file.read()
    if len(contents) > MAX_SCAN_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Picture exceeds {MAX_SCAN_FILE_SIZE // (1024 * 1024)}MB limit"
        )
    return omni_threat_scanner.scan_picture(
        contents,
        filename=file.filename or "uploaded_picture.jpg"
    )


@router.post("/file")
async def scan_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Scans files and documents for multi-stage malware:
    - Double extension trickery (e.g. invoice.pdf.exe)
    - Malicious Office VBA macros (AutoOpen, Shell execution)
    - Suspicious PDF action triggers (/Launch, /JavaScript)
    - Compressed archive dropper inspection (ZIP, TAR)
    - Shannon entropy calculation & cryptographic hashing (SHA-256, MD5)
    """
    contents = await file.read()
    if len(contents) > MAX_SCAN_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds {MAX_SCAN_FILE_SIZE // (1024 * 1024)}MB limit"
        )
    return omni_threat_scanner.scan_file(
        contents,
        filename=file.filename or "uploaded_file.bin"
    )


@router.get("/samples")
async def get_test_samples(
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Provides curated test vectors for fast testing across all 4 scanners.
    """
    return {
        "links": [
            {"title": "Clean Safe Link (Google)", "url": "https://www.google.com"},
            {"title": "Obfuscated Decimal IP (Phishing Pattern)", "url": "http://2130706433/login.php"},
            {"title": "Suspicious TLD Dropper URL", "url": "http://malicious-update.top/setup.exe"},
            {"title": "Direct Remote Script Dropper", "url": "https://pastebin.com/raw/malware_dropper.ps1"},
        ],
        "descriptions": {
            "link": "Traces HTTP redirects, inspects final payload stream, checks typosquatting and suspicious TLDs.",
            "qr": "Decodes matrix barcode, checks quishing vectors, and audits the destination link.",
            "picture": "Finds hidden binaries appended after JPEG/PNG EOF markers, analyzes EXIF code injection and SVG scripts.",
            "file": "Deep audits double extensions, Office macros, PDF /Launch actions, and archive droppers."
        }
    }
