import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.app.main import app
from backend.app.database import AsyncSessionLocal
from simulator.attack_simulation_pipeline import attack_simulation_pipeline
from backend.app.models.incident import Incident
from backend.app.models.evidence import EvidenceItem, ChainOfCustodyRecord


@pytest.mark.asyncio
async def test_kali_linux_rat_attack_containment_and_forensics():
    """
    Test End-to-End Cycle for Kali Linux:
    Telemetry Ingest -> RAT C2 Detection -> Forensic Scene Evidence Sealed -> Safe Containment -> Hash Verification.
    """
    async with AsyncSessionLocal() as session:
        result = await attack_simulation_pipeline.run_pipeline("kali_linux", db=session)

        assert result["status"] == "SUCCESS_DEFENSIVE_CYCLE_VERIFIED"
        assert result["target_platform"] == "kali"
        assert "Meterpreter" in result["scenario"]

        # 1. Detection Verified
        assert result["detection"]["severity"] == "CRITICAL"
        assert result["detection"]["incident_number"].startswith("INC-")

        # 2. Forensic Evidence Verified
        ev_info = result["evidence_preservation"]
        assert ev_info["evidence_number"].startswith("EV-HACK-")
        assert len(ev_info["sha256_hash"]) == 64
        assert ev_info["tamper_verified"] is True
        assert ev_info["chain_of_custody_status"] == "SEALED_READ_ONLY"

        # 3. Containment Verified
        assert result["containment_execution"]["host_isolation"] == "ACTIVATED"


@pytest.mark.asyncio
async def test_windows_reverse_shell_containment_and_forensics():
    """
    Test End-to-End Cycle for Windows Workstation:
    PowerShell Reverse Shell -> Detection -> Scene Sealed -> Host Isolated.
    """
    async with AsyncSessionLocal() as session:
        result = await attack_simulation_pipeline.run_pipeline("windows", db=session)

        assert result["status"] == "SUCCESS_DEFENSIVE_CYCLE_VERIFIED"
        assert result["target_platform"] == "windows"
        assert "PowerShell" in result["scenario"]
        assert result["evidence_preservation"]["tamper_verified"] is True


@pytest.mark.asyncio
async def test_mobile_companion_spyware_containment_and_forensics():
    """
    Test End-to-End Cycle for Mobile Companion (Android):
    Background Camera/Sensor Hijack -> Detection -> Vault Sealed -> Containment.
    """
    async with AsyncSessionLocal() as session:
        result = await attack_simulation_pipeline.run_pipeline("android", db=session)

        assert result["status"] == "SUCCESS_DEFENSIVE_CYCLE_VERIFIED"
        assert result["target_platform"] == "android"
        assert "Mobile" in result["scenario"]
        assert result["evidence_preservation"]["tamper_verified"] is True


@pytest.mark.asyncio
async def test_one_click_incident_contain_and_preserve_api():
    """
    Verify POST /api/v1/incidents/{incident_id}/contain-and-preserve endpoint.
    """
    from backend.app.core.system_credentials import get_or_create_system_credentials
    creds = get_or_create_system_credentials()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # First login as admin to get auth token
        login_res = await client.post(
            "/api/v1/auth/login",
            data={"username": "admin", "password": creds["system_password"]},
        )
        assert login_res.status_code == 200
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Query existing incidents
        inc_res = await client.get("/api/v1/incidents/", headers=headers)
        assert inc_res.status_code == 200
        items = inc_res.json()["items"]
        assert len(items) > 0

        target_inc_id = items[0]["id"]

        # Call contain-and-preserve
        cp_res = await client.post(
            f"/api/v1/incidents/{target_inc_id}/contain-and-preserve",
            headers=headers,
            json={
                "process_name": "malicious_rat.exe",
                "pid": 9999,
                "remote_ip": "198.51.100.99",
                "remote_port": 4444,
            },
        )
        assert cp_res.status_code == 200
        data = cp_res.json()

        assert data["status"] == "CONTAINED_AND_PRESERVED"
        assert data["evidence"]["evidence_number"].startswith("EV-HACK-")
        assert len(data["evidence"]["sha256"]) == 64
        assert "vault_path" in data["evidence"]
