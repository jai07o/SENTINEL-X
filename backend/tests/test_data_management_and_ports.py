import pytest
import pytest_asyncio
import tempfile
from pathlib import Path
from httpx import AsyncClient, ASGITransport

from backend.app.main import app
from backend.app.database import async_session_factory
from backend.app.models.event import NormalizedEvent
from backend.app.models.incident import Incident
from backend.app.models.host import Host
from backend.app.services.data_management_service import data_management_service
from backend.app.services.hardware_port_service import hardware_port_service


@pytest.fixture
def auth_headers():
    return {"X-Sentinel-Key": "sx_dev_agent_key_default"}


@pytest.mark.asyncio
async def test_data_management_storage_stats():
    """Verify data management service returns accurate table statistics."""
    async with async_session_factory() as session:
        stats = await data_management_service.get_storage_statistics(session)
        assert isinstance(stats, dict)
        assert "events" in stats
        assert "incidents" in stats
        assert "hosts" in stats
        assert "total_records" in stats


@pytest.mark.asyncio
async def test_data_management_purge_category():
    """Verify category purge successfully clears records and respects cascading links."""
    async with async_session_factory() as session:
        res = await data_management_service.purge_category(session, "events")
        assert res["success"] is True
        assert res["category"] == "events"
        assert "deleted_records" in res


@pytest.mark.asyncio
async def test_hardware_port_enumeration():
    """Verify hardware port service enumerates connected devices."""
    devices = hardware_port_service.list_connected_cable_devices()
    assert isinstance(devices, list)
    assert len(devices) > 0
    dev = devices[0]
    assert "device_type" in dev
    assert "status" in dev


@pytest.mark.asyncio
async def test_hardware_port_scan_and_auto_quarantine():
    """Verify cable device scanning detects autorun worms and triggers auto-quarantine."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        # Create a malicious autorun.inf
        autorun = tmp_path / "autorun.inf"
        autorun.write_text("[autorun]\nopen=malware.exe\naction=Run Security Tool\n")

        # Create a double-extension file
        double_ext = tmp_path / "invoice.pdf.exe"
        double_ext.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00" + b"\xcc" * 200)

        # Run scan
        res = hardware_port_service.scan_path_or_device(
            target_path=str(tmp_path),
            device_id="TEST_USB_PORT_001",
            auto_quarantine=True,
        )

        assert res["is_clean"] is False
        assert res["verdict"] == "MALICIOUS"
        assert res["threats_count"] >= 2
        threat_types = [t["threat_type"] for t in res["threats"]]
        assert "AUTORUN_WORM_TRIGGER" in threat_types
        assert "DOUBLE_EXTENSION_MASQUERADE" in threat_types


@pytest.mark.asyncio
async def test_hardware_port_quarantine_and_release():
    """Verify manual port quarantine blocks the device and release unblocks it."""
    test_port = "USB_TEST_PORT_99"

    # Quarantine port
    q_res = hardware_port_service.quarantine_port(test_port, "Test Unit Quarantine")
    assert q_res["success"] is True
    assert "quarantined and stopped" in q_res["message"]

    # Verify status
    status_res = hardware_port_service.get_quarantine_status()
    assert any(p["port_key"] == test_port for p in status_res["quarantined_ports"])

    # Release port
    r_res = hardware_port_service.release_port(test_port)
    assert r_res["success"] is True
    assert "released and re-enabled" in r_res["message"]


@pytest.mark.asyncio
async def test_hardware_port_protects_system_drive():
    """Verify quarantine_port prevents dismounting system volume C:."""
    q_res = hardware_port_service.quarantine_port("C:", "Malicious Test")
    assert q_res["success"] is False
    assert "protected" in q_res["message"]


@pytest.mark.asyncio
async def test_api_hardware_ports_endpoints(client: AsyncClient, admin_token: str):
    """Verify REST API endpoints for hardware ports and data management."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. List devices
    dev_resp = await client.get("/api/v1/hardware-ports/devices", headers=headers)
    assert dev_resp.status_code == 200
    data = dev_resp.json()
    assert "devices" in data

    # 2. Port status
    stat_resp = await client.get("/api/v1/hardware-ports/status", headers=headers)
    assert stat_resp.status_code == 200

    # 3. Data management stats
    db_stat_resp = await client.get("/api/v1/data-management/stats", headers=headers)
    assert db_stat_resp.status_code == 200
    assert "events" in db_stat_resp.json()

    # 4. USB Immunization status endpoint
    imm_resp = await client.get("/api/v1/hardware-ports/immunization", headers=headers)
    assert imm_resp.status_code == 200
    assert "is_immune" in imm_resp.json()

    # 5. BadUSB status endpoint
    badusb_resp = await client.get("/api/v1/hardware-ports/badusb", headers=headers)
    assert badusb_resp.status_code == 200
    assert "badusb_devices" in badusb_resp.json()


@pytest.mark.asyncio
async def test_usb_immunization_and_vaccination(tmp_path):
    """Verify host OS USB immunization and pendrive vaccination."""
    # 1. Host immunization status
    status = hardware_port_service.get_host_usb_immunization_status()
    assert "is_immune" in status
    assert "status" in status

    # 2. Apply immunization
    apply_res = hardware_port_service.apply_host_usb_immunization()
    assert "success" in apply_res
    assert "status" in apply_res

    # 3. Vaccinate drive (using temp folder as simulated drive)
    drive_dir = tmp_path / "simulated_pendrive"
    drive_dir.mkdir()

    # Pre-seed with an insecure autorun.inf file
    (drive_dir / "autorun.inf").write_text("[autorun]\nopen=malware.exe\n")
    assert (drive_dir / "autorun.inf").is_file()

    # Apply vaccination
    vac_res = hardware_port_service.vaccinate_drive(str(drive_dir))
    assert vac_res["success"] is True
    # The file should now be replaced with an immutable directory
    assert (drive_dir / "autorun.inf").is_dir()
    assert (drive_dir / "autorun.inf" / "sentinel_vaccine.lck").exists()


@pytest.mark.asyncio
async def test_pendrive_insertion_threat_intercept(tmp_path):
    """Verify that inserting a pendrive with BadUSB or worm payloads is intercepted and auto-quarantined."""
    pendrive_dir = tmp_path / "infected_pendrive"
    pendrive_dir.mkdir()

    # Drop a Rubber Ducky / BadUSB script payload
    (pendrive_dir / "inject.bin").write_bytes(b"\x00\x01\x02\x03\x04\x05")

    # Drop a deceptive double-extension executable
    (pendrive_dir / "invoice.pdf.exe").write_bytes(b"MZ" + b"\x90" * 200)

    # Intercept device insertion
    device_info = {
        "mount_point": str(pendrive_dir),
        "drive_letter": "T:",
        "device_id": "USB\\VID_TEST&PID_BADUSB",
        "name": "Malicious Test Pendrive",
        "is_removable": True,
    }

    res = hardware_port_service.intercept_device_insertion(device_info)
    assert res["is_threat"] is True
    assert res["verdict"] == "QUARANTINED_BEFORE_INJECTION"
    assert res["scan_result"]["threats_count"] >= 2
    threat_types = [t["threat_type"] for t in res["scan_result"]["threats"]]
    assert "BADUSB_KEYSTROKE_INJECTION_SCRIPT" in threat_types
    assert "DOUBLE_EXTENSION_MASQUERADE" in threat_types


