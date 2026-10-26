import os
import json
import pytest
from pathlib import Path
from httpx import AsyncClient

from backend.app.services.footprint_sanitizer_service import footprint_sanitizer, EthicalHackerFootprintService


def test_discover_operator_footprints():
    """Verify that footprint discovery inventories shell histories, droppers, and system state."""
    report = footprint_sanitizer.discover_operator_footprints()
    assert isinstance(report, dict)
    assert "timestamp" in report
    assert "hostname" in report
    assert "os" in report
    assert "shell_histories" in report
    assert isinstance(report["shell_histories"], list)
    assert "temporary_droppers" in report
    assert "total_footprints_found" in report
    assert isinstance(report["total_footprints_found"], int)


def test_file_shredding_and_truncation(tmp_path: Path):
    """Verify zero-fill shredder and truncation utilities eliminate traces."""
    # Test truncation
    test_hist = tmp_path / "test_shell_history.txt"
    test_hist.write_text("sudo nmap -sS 192.168.1.1\nhcat -m 1000 hashes.txt\n", encoding="utf-8")
    assert test_hist.stat().st_size > 0
    res = EthicalHackerFootprintService._truncate_file(test_hist)
    assert res is True
    assert test_hist.exists()
    assert test_hist.stat().st_size == 0

    # Test secure shredding
    dropper = tmp_path / "sentinel_payload_dropper.py"
    dropper.write_bytes(b"\x90" * 2048)  # NOP sled mock
    assert dropper.exists()
    shred_res = EthicalHackerFootprintService._secure_shred_file(dropper, passes=2)
    assert shred_res is True
    assert not dropper.exists()


def test_clean_and_purge_all_footprints(tmp_path: Path):
    """Verify complete anti-trace purging issues a signed certificate and shreds droppers."""
    from backend.app.services.footprint_sanitizer_service import UPLOADS_DIR
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    dummy_artifact = UPLOADS_DIR / "temp_operator_payload.bin"
    dummy_artifact.write_bytes(b"TEMPORARY_TEST_ARTIFACT")

    result = footprint_sanitizer.clean_and_purge_all_footprints()
    assert isinstance(result, dict)
    assert result["status"] == "SUCCESS"
    assert "purged_files_count" in result
    assert "actions_taken" in result
    assert len(result["actions_taken"]) > 0

    # Verify dummy artifact was shredded
    assert not dummy_artifact.exists()

    # Verify certificate creation and content
    cert_path = Path(result["certificate_path"])
    assert cert_path.exists()
    cert_content = cert_path.read_text(encoding="utf-8")
    assert "SENTINEL-X Clean Disengagement & Anti-Trace Certificate" in cert_content
    assert "ZERO FORENSIC REMANENCE" in cert_content
    assert "SHA-256 Digest" in cert_content


def test_surveil_active_footprinting():
    """Verify surveillance engine monitors external socket probes and reconnaissance attempts."""
    surveil = footprint_sanitizer.surveil_active_footprinting()
    assert isinstance(surveil, dict)
    assert surveil["status"] == "SURVEILLANCE_ACTIVE"
    assert "footprinting_threat_level" in surveil
    assert "reconnaissance_threat_score" in surveil
    assert "monitored_vectors" in surveil
    assert len(surveil["monitored_vectors"]) >= 4


def test_mislead_attacker_footprints():
    """Verify deception engine deploys fake OS fingerprints, canary files, and honeypaths."""
    deception = footprint_sanitizer.mislead_attacker_footprints(fake_os_identity="DECOY_CISCO_IOS")
    assert isinstance(deception, dict)
    assert deception["status"] == "DECEPTION_ACTIVE"
    assert "active_profile" in deception
    assert deception["active_profile"]["simulated_ttl"] == 254
    assert len(deception["canary_files"]) >= 3
    assert "certificate_path" in deception

    cert_path = Path(deception["certificate_path"])
    assert cert_path.exists()
    cert_text = cert_path.read_text(encoding="utf-8")
    assert "Cyber Deception & Reconnaissance Misdirection Certificate" in cert_text
    assert "Cisco IOS" in cert_text


def test_intercept_third_party_intrusion():
    """Verify third-party intrusion containment collects evidence, freezes vault, and issues certificate."""
    test_ip = "198.51.100.77"
    test_port = 4444
    res = footprint_sanitizer.intercept_third_party_intrusion(
        remote_ip=test_ip,
        remote_port=test_port,
        threat_description="Cobalt Strike Beacon Ingress Attempt"
    )

    assert isinstance(res, dict)
    assert res["status"] == "CONTAINED_AND_SEALED"
    assert "incident_id" in res
    assert res["remote_ip"] == test_ip

    # Verify volatile evidence vault exists
    evidence_vault = Path(res["evidence_vault_path"])
    assert evidence_vault.exists()
    with open(evidence_vault, "r", encoding="utf-8") as f:
        evidence_json = json.load(f)
    assert evidence_json["threat_category"] == "THIRD_PARTY_REMOTE_INVASION"
    assert evidence_json["origin_details"]["remote_ip"] == test_ip
    assert evidence_json["origin_details"]["remote_port"] == test_port

    # Verify incident certificate
    cert_path = Path(res["certificate_path"])
    assert cert_path.exists()
    cert_content = cert_path.read_text(encoding="utf-8")
    assert "SENTINEL-X Third-Party Intrusion Interception & Forensic Seal" in cert_content
    assert test_ip in cert_content


@pytest.mark.asyncio
async def test_footprint_api_routes(client: AsyncClient, admin_token: str):
    """Verify FastAPI endpoints for footprint surveillance, deception, cleanup, and intrusion interception."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Surveil
    resp_surv = await client.get("/api/v1/footprints/surveil", headers=headers)
    assert resp_surv.status_code == 200
    assert resp_surv.json()["status"] == "SURVEILLANCE_ACTIVE"

    # 2. Mislead
    resp_mis = await client.post("/api/v1/footprints/mislead", json={"fake_os_identity": "DECOY_LEGACY_WIN"}, headers=headers)
    assert resp_mis.status_code == 200
    assert resp_mis.json()["status"] == "DECEPTION_ACTIVE"

    # 3. Discover
    resp = await client.get("/api/v1/footprints/discover", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "hostname" in data
    assert "shell_histories" in data

    # 4. Clean all
    resp_clean = await client.post("/api/v1/footprints/clean-all", headers=headers)
    assert resp_clean.status_code == 200
    clean_data = resp_clean.json()
    assert clean_data["status"] == "SUCCESS"
    assert "certificate_path" in clean_data

    # 5. Stop intrusion
    payload = {
        "remote_ip": "203.0.113.88",
        "remote_port": 8080,
        "description": "Suspicious reverse shell connection",
    }
    resp_stop = await client.post("/api/v1/footprints/stop-intrusion", json=payload, headers=headers)
    assert resp_stop.status_code == 200
    stop_data = resp_stop.json()
    assert stop_data["status"] == "CONTAINED_AND_SEALED"
    assert stop_data["remote_ip"] == "203.0.113.88"
