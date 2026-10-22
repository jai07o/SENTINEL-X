"""
Automated Test Suite for Active System & Connected Devices Guardian.
Author: K. Jaideep Raj (Student & Security Enthusiast) via Google Antigravity.

Verifies:
1. Live active host fingerprinting (detects Laptop vs Desktop, battery status, CPU/RAM, network identity).
2. Connected devices enumeration (mobile devices, USB storage, Bluetooth accessories, local network peers).
3. In-depth OS deep scan (processes, listening sockets, temporary files, security health score).
4. Targeted connected device deep scan (juice-jacking verification and file sanitization).
5. REST API endpoints (/api/v1/system/active-host, /deep-scan, /connected-devices, /scan-connected-device, /sync-local-host).
"""

import pytest
from httpx import AsyncClient, ASGITransport

from backend.app.main import app
from backend.app.services.active_system_service import active_system_guardian


@pytest.mark.asyncio
async def test_active_system_profile_and_laptop_detection():
    """Verifies that the service retrieves real host identity and profiles hardware accurately."""
    profile = active_system_guardian.get_system_profile()

    assert "hostname" in profile
    assert profile["hostname"] != ""
    assert "device_classification" in profile
    assert profile["device_classification"] in ("Laptop", "Desktop PC")
    assert "battery" in profile
    assert "operating_system" in profile
    assert "cpu_cores_logical" in profile
    assert profile["cpu_cores_logical"] >= 1
    assert "ram_total_gb" in profile
    assert profile["ram_total_gb"] > 0
    assert "primary_ip" in profile
    assert "primary_mac" in profile
    assert profile["connected_and_active"] is True
    assert "K. Jaideep Raj" in profile["creator"]
    assert "Student" in profile["creator"]


@pytest.mark.asyncio
async def test_connected_devices_detection():
    """Verifies discovery of connected mobiles, external storage, peripherals, and network peers."""
    devices = active_system_guardian.detect_connected_devices()

    assert "connected_mobiles_count" in devices
    assert "external_storage_count" in devices
    assert "connected_peripherals_count" in devices
    assert "network_neighbors_count" in devices
    assert isinstance(devices["connected_mobiles"], list)
    assert isinstance(devices["external_storage"], list)
    assert isinstance(devices["connected_peripherals"], list)
    assert isinstance(devices["network_neighbors"], list)


@pytest.mark.asyncio
async def test_in_depth_os_deep_scan():
    """Verifies deep scan of processes, sockets, temporary files, and security score computation."""
    scan = active_system_guardian.execute_deep_os_scan()

    assert "scan_id" in scan
    assert scan["scan_id"].startswith("DEEP-SCAN-")
    assert scan["status"] == "COMPLETED"
    assert "security_score" in scan
    assert 0.0 <= scan["security_score"] <= 100.0
    assert "overall_posture" in scan
    assert scan["overall_posture"] in ("SECURE", "ATTENTION", "COMPROMISED")
    assert "statistics" in scan
    assert scan["statistics"]["processes_analyzed"] >= 0
    assert scan["statistics"]["sockets_analyzed"] >= 0
    assert scan["statistics"]["files_vetted"] >= 0
    assert "K. Jaideep Raj" in scan["creator"]


@pytest.mark.asyncio
async def test_scan_connected_device_juice_jacking_check():
    """Verifies targeted scanning of a connected mobile phone."""
    dev_scan = active_system_guardian.scan_connected_device(
        device_id="mobile_test_phone_usb",
        device_type="mobile",
    )

    assert "scan_id" in dev_scan
    assert dev_scan["status"] == "SCANNED_AND_VERIFIED"
    assert dev_scan["juice_jacking_secured"] is True
    assert dev_scan["immunized"] is True
    assert dev_scan["threats_count"] == 0


@pytest.mark.asyncio
async def test_api_active_system_endpoints():
    """Verifies REST API endpoints with host-derived dynamic authentication and hardware port matrix."""
    from backend.app.core.system_credentials import get_or_create_system_credentials
    creds = get_or_create_system_credentials()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 0. Check /auth/system-credentials-info without auth
        creds_res = await client.get("/api/v1/auth/system-credentials-info")
        assert creds_res.status_code == 200
        assert creds_res.json()["status"] == "HOST_DERIVED_CREDENTIALS_ACTIVE"

        # Authenticate with system credentials
        login_res = await client.post(
            "/api/v1/auth/login",
            data={"username": "admin", "password": creds["system_password"]},
        )
        assert login_res.status_code == 200
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 1. GET /api/v1/system/active-host
        host_res = await client.get("/api/v1/system/active-host", headers=headers)
        assert host_res.status_code == 200
        assert host_res.json()["connected_and_active"] is True

        # 2. GET /api/v1/system/connected-devices
        dev_res = await client.get("/api/v1/system/connected-devices", headers=headers)
        assert dev_res.status_code == 200
        assert "connected_mobiles_count" in dev_res.json()
        assert "all_hardware_ports" in dev_res.json()

        # 2.1 GET /api/v1/system/hardware-ports-full
        ports_res = await client.get("/api/v1/system/hardware-ports-full", headers=headers)
        assert ports_res.status_code == 200
        ports_data = ports_res.json()
        assert "total_ports_count" in ports_data
        assert "categories" in ports_data
        assert "usb_ports" in ports_data["categories"]
        assert "network_cable_ports" in ports_data["categories"]
        assert "display_video_ports" in ports_data["categories"]
        assert "audio_jack_ports" in ports_data["categories"]

        # 3. POST /api/v1/system/deep-scan
        deep_res = await client.post("/api/v1/system/deep-scan", headers=headers)
        assert deep_res.status_code == 200
        assert deep_res.json()["status"] == "COMPLETED"

        # 4. POST /api/v1/system/scan-connected-device
        scan_dev_res = await client.post(
            "/api/v1/system/scan-connected-device",
            json={"device_id": "phone-usb-001", "device_type": "mobile"},
            headers=headers,
        )
        assert scan_dev_res.status_code == 200
        assert scan_dev_res.json()["juice_jacking_secured"] is True

        # 5. POST /api/v1/system/sync-local-host
        sync_res = await client.post("/api/v1/system/sync-local-host", headers=headers)
        assert sync_res.status_code == 200
        assert sync_res.json()["status"] in ("SUCCESS", "LOCAL_ONLY")

        # 6. POST /api/v1/system/repair
        repair_res = await client.post("/api/v1/system/repair", headers=headers)
        assert repair_res.status_code == 200
        repair_data = repair_res.json()
        assert repair_data["status"] == "SYSTEM_COMPLETELY_REPAIRED_AND_IMMUNIZED"
        assert repair_data["court_admissible_verified"] is True
        assert "certificate_path" in repair_data
        assert "golden_forensics_snapshot" in repair_data


@pytest.mark.asyncio
async def test_complete_system_repair_service_direct():
    """Verifies that the repair service enforces Golden Forensics freeze, executes remediations, and issues signed certificate."""
    rep = active_system_guardian.repair_system_completely(analyst_id="test_admin")

    assert rep["status"] == "SYSTEM_COMPLETELY_REPAIRED_AND_IMMUNIZED"
    assert "golden_forensics_snapshot" in rep
    assert "sha256_evidence_seal" in rep
    assert len(rep["sha256_evidence_seal"]) == 64
    assert rep["remediation_actions_count"] >= 1
    assert "certificate_path" in rep
    assert rep["court_admissible_verified"] is True
    assert "K. Jaideep Raj" in rep["creator"]
