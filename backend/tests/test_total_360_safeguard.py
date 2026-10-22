"""
Comprehensive Automated Test Suite:
SENTINEL-X 360° Total Safeguard Engine & Multi-Vector Workflows.

Verifies:
1. 360° multi-vector audit evaluates all 6 threat sectors (Hardware, Wi-Fi, Sockets, Processes, Privacy, Offline Shield).
2. Deterministic consensus yields >= 99.0% accuracy confidence index and verified recall.
3. One-Click 360° master rectification seals volatile crime-scene evidence in data/evidence/ (0400 read-only).
4. Master 360° Rectification Certificate is issued in data/reports/ signed by K. Jaideep Raj (Student & Security Enthusiast).
5. REST API endpoints (/api/v1/total-360/status, /audit, /rectify) return 200 OK and valid telemetry.
"""

import os
import sys
import json
import stat
import pytest
from pathlib import Path
from httpx import AsyncClient, ASGITransport

from backend.app.main import app
from backend.app.config import EVIDENCE_DIR, REPORTS_DIR
from backend.app.services.total_360_safeguard_service import total_360_safeguard


@pytest.mark.asyncio
async def test_360_total_safeguard_audit_posture():
    """
    Verifies that the 360° audit evaluates all 6 threat sectors
    and reports a deterministic accuracy index >= 99.0%.
    """
    audit = total_360_safeguard.audit_360_total_posture()

    assert "overall_security_score" in audit
    assert "accuracy_confidence_index" in audit
    assert audit["accuracy_confidence_index"] >= 99.0
    assert audit["total_sectors"] == 6
    assert "sectors" in audit

    sectors = audit["sectors"]
    expected_sectors = [
        "sector_1_hardware_wired",
        "sector_2_wireless_network",
        "sector_3_sockets_backdoors",
        "sector_4_host_processes",
        "sector_5_privacy_sensors",
        "sector_6_offline_shield",
    ]
    for s_key in expected_sectors:
        assert s_key in sectors
        assert "degrees" in sectors[s_key]
        assert "clean" in sectors[s_key]
        assert "threats_count" in sectors[s_key]

    # Verify student attribution
    assert "K. Jaideep Raj" in audit["creator"]
    assert "Student" in audit["creator"]
    assert "Google Antigravity" in audit["platform"]


@pytest.mark.asyncio
async def test_360_total_safeguard_rectification_and_evidence_vault():
    """
    Verifies that One-Click 360° Rectification:
    1. Seals volatile crime-scene evidence into data/evidence/ (0400).
    2. Issues signed court-admissible Master Certificate in data/reports/.
    3. Reaches 100% security score and >= 99.0% accuracy index.
    """
    rect = total_360_safeguard.execute_360_total_rectification(analyst_id="test_student_analyst")

    assert rect["status"] == "360_TOTAL_SAFEGUARD_RECTIFIED_AND_IMMUNIZED"
    assert rect["security_score_after"] == 100.0
    assert rect["accuracy_confidence_index"] >= 99.0
    assert "sha256_hash" in rect
    assert len(rect["sha256_hash"]) == 64
    assert len(rect["md5_hash"]) == 32

    # Verify Evidence Vault File on Disk
    vault_path = Path(rect["evidence_vault_path"])
    assert vault_path.exists()
    vault_data = json.loads(vault_path.read_text(encoding="utf-8"))
    assert vault_data["preservation_status"] == "LOCKED_IMMUTABLE_READONLY_0400"
    assert vault_data["accuracy_confidence_index"] >= 99.0
    assert "K. Jaideep Raj" in vault_data["creator"]

    # Check read-only permissions
    mode = stat.S_IMODE(os.stat(vault_path).st_mode)
    assert (mode & stat.S_IWUSR) == 0 or sys.platform == "win32"

    # Verify Master 360 Certificate
    cert_path = Path(rect["certificate_path"])
    assert cert_path.exists()
    cert_text = cert_path.read_text(encoding="utf-8")
    assert "SENTINEL-X 360° TOTAL SAFEGUARD RECTIFICATION CERTIFICATE" in cert_text
    assert "K. Jaideep Raj" in cert_text
    assert "Student" in cert_text
    assert "Google Antigravity" in cert_text
    assert rect["sha256_hash"] in cert_text


@pytest.mark.asyncio
async def test_360_total_safeguard_api_endpoints():
    """
    Verifies the REST API endpoints:
    - GET /api/v1/total-360/status
    - GET /api/v1/total-360/audit
    - POST /api/v1/total-360/rectify
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Authenticate
        login_res = await client.post(
            "/api/v1/auth/login",
            data={"username": "admin", "password": "SentinelX@2026!"},
        )
        assert login_res.status_code == 200
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Status endpoint
        status_res = await client.get("/api/v1/total-360/status", headers=headers)
        assert status_res.status_code == 200
        assert status_res.json()["status"] == "OPERATIONAL"
        assert status_res.json()["accuracy_confidence_index"] >= 99.0
        assert "K. Jaideep Raj" in status_res.json()["creator"]

        # 2. Audit endpoint
        audit_res = await client.get("/api/v1/total-360/audit", headers=headers)
        assert audit_res.status_code == 200
        assert audit_res.json()["total_sectors"] == 6
        assert "sectors" in audit_res.json()

        # 3. Rectify endpoint
        rect_res = await client.post("/api/v1/total-360/rectify", headers=headers)
        assert rect_res.status_code == 200
        assert rect_res.json()["status"] == "360_TOTAL_SAFEGUARD_RECTIFIED_AND_IMMUNIZED"
        assert rect_res.json()["security_score_after"] == 100.0
