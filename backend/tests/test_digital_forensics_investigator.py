"""
Unit and Integration Tests for Digital Forensics Cyber Detective & Timeline Reconstruction Engine
Tests the 4 Attack Stages, Key Artifacts (Event Logs, Memory Dump RAM, MFT/MACB),
Timeline Reconstruction, Cryptographic Sealing, and Ethical Hacker Disengagement.
"""
import os
import json
import pytest
from pathlib import Path
from httpx import AsyncClient

from backend.app.services.digital_forensics_investigator_service import (
    digital_forensics_investigator,
    DigitalForensicsInvestigatorService
)


def test_macb_timestamp_extraction(tmp_path: Path):
    """Verify MACB timestamp extraction accurately captures Modified, Accessed, Changed, Born times."""
    test_file = tmp_path / "forensic_sample_payload.bin"
    test_file.write_bytes(b"DIGITAL_FORENSICS_SAMPLE_BINARY")

    macb = DigitalForensicsInvestigatorService.extract_macb_timestamps(test_file)
    assert isinstance(macb, dict)
    assert "modified_m" in macb
    assert "accessed_a" in macb
    assert "changed_c" in macb
    assert "born_b" in macb
    assert "timestomp_anomaly" in macb
    assert macb["size_bytes"] == len(b"DIGITAL_FORENSICS_SAMPLE_BINARY")


def test_stage_1_initial_access():
    """Verify Stage 1 (Initial Access) audits credentials, phishing artifacts, and server vulnerabilities."""
    creds = digital_forensics_investigator.audit_compromised_credentials()
    assert creds["stage"] == "STAGE_1_INITIAL_ACCESS"
    assert "brute_force_evidence_count" in creds
    assert "remote_logons_identified" in creds

    phish = digital_forensics_investigator.audit_phishing_artifacts()
    assert phish["stage"] == "STAGE_1_INITIAL_ACCESS"
    assert "phishing_artifacts_detected" in phish

    vulns = digital_forensics_investigator.audit_exploited_vulnerabilities()
    assert vulns["stage"] == "STAGE_1_INITIAL_ACCESS"
    assert "vulnerability_indicators_found" in vulns


def test_stage_2_lateral_movement():
    """Verify Stage 2 (Lateral Movement) audits event log clearances, rogue accounts, and command history."""
    logs = digital_forensics_investigator.audit_log_clearances()
    assert logs["stage"] == "STAGE_2_LATERAL_MOVEMENT"
    assert "log_tampering_detected" in logs
    assert "clearance_events_count" in logs

    rogue = digital_forensics_investigator.audit_rogue_accounts()
    assert rogue["stage"] == "STAGE_2_LATERAL_MOVEMENT"
    assert "rogue_accounts_detected" in rogue

    cmd = digital_forensics_investigator.audit_command_history()
    assert cmd["stage"] == "STAGE_2_LATERAL_MOVEMENT"
    assert "suspicious_commands_identified" in cmd


def test_stage_3_persistence():
    """Verify Stage 3 (Persistence) audits staged malware, registry Run keys, and LotL dual-use tools."""
    malw = digital_forensics_investigator.audit_malicious_executables()
    assert malw["stage"] == "STAGE_3_PERSISTENCE"
    assert "staged_binaries_count" in malw

    reg = digital_forensics_investigator.audit_registry_modifications()
    assert reg["stage"] == "STAGE_3_PERSISTENCE"
    assert "total_startup_keys_inspected" in reg
    assert "suspicious_registry_hooks" in reg

    lotl = digital_forensics_investigator.audit_living_off_the_land_tools()
    assert lotl["stage"] == "STAGE_3_PERSISTENCE"
    assert "abused_lotl_processes_detected" in lotl


def test_stage_4_data_exfiltration():
    """Verify Stage 4 (Data Exfiltration) audits staging archives, network spikes, and cloud API logs."""
    stage = digital_forensics_investigator.audit_staging_files()
    assert stage["stage"] == "STAGE_4_DATA_EXFILTRATION"
    assert "staged_archives_count" in stage

    net = digital_forensics_investigator.audit_unusual_network_spikes()
    assert net["stage"] == "STAGE_4_DATA_EXFILTRATION"
    assert "suspicious_outbound_exfiltrations" in net

    cloud = digital_forensics_investigator.audit_cloud_api_logs()
    assert cloud["stage"] == "STAGE_4_DATA_EXFILTRATION"
    assert "corporate_cloud_stores_monitored" in cloud


def test_volatile_ram_memory_dump_analysis():
    """Verify active volatile memory inspection surveys running processes for masquerading and temp binaries."""
    ram = digital_forensics_investigator.audit_active_memory_dump()
    assert ram["artifact_type"] == "MEMORY_DUMP_VOLATILE_RAM_ANALYSIS"
    assert "total_active_processes_inspected" in ram
    assert ram["total_active_processes_inspected"] > 0
    assert "volatile_ram_anomalies_found" in ram


def test_run_complete_forensic_investigation():
    """Verify complete master investigation reconstructs chronological timeline and seals evidence vault."""
    inv = digital_forensics_investigator.run_complete_forensic_investigation()
    assert isinstance(inv, dict)
    assert "investigation_id" in inv
    assert "cyber_detective_verdict" in inv
    assert "threat_risk_score" in inv
    assert "reconstructed_breach_timeline" in inv
    assert isinstance(inv["reconstructed_breach_timeline"], list)

    # Verify 4 attack stages are populated
    assert "stage_1_initial_access" in inv
    assert "stage_2_lateral_movement" in inv
    assert "stage_3_persistence" in inv
    assert "stage_4_data_exfiltration" in inv
    assert "summary_of_key_artifacts" in inv

    # Verify cryptographic seal & vault write
    seal = inv["cryptographic_evidence_seal"]
    assert "sha256_fingerprint" in seal
    assert "hmac_signature" in seal
    assert Path(inv["sealed_evidence_filepath"]).exists()
    assert Path(inv["investigation_certificate_path"]).exists()


def test_ethical_hacker_safe_disengagement():
    """Verify ethical operator disengagement purges histories and issues signed certificate."""
    res = digital_forensics_investigator.disengage_ethical_hacker_footprints()
    assert isinstance(res, dict)
    assert res["status"] == "OPERATOR_FOOTPRINTS_PURGED_AND_SEALED"
    assert "actions_executed" in res
    assert Path(res["certificate_path"]).exists()
