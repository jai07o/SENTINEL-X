"""
Unit and Integration Tests for SENTINEL-X AI Linux Threat Investigator
Verifies the 4 critical attack signals:
  1. Suspicious Processes (volatile execution, masquerading, reverse shells)
  2. Login Attempts (SSH brute force, sudo escalation, external IP logins)
  3. Modified System Files (FIM: /etc/passwd, /etc/shadow, /etc/sudoers, /etc/crontab)
  4. Unusual Network Connections (RAT/C2 ports, scripting engines)
Also verifies Multi-Signal Correlation (0-100), AI Threat Explanation, Incident Timeline,
Safe Remediation Recommendations, Cryptographic Sealing (HMAC/SHA-256), and REST API endpoints.
"""
import os
import json
import pytest
from pathlib import Path
from httpx import AsyncClient

from backend.app.services.ai_threat_investigator_service import (
    ai_threat_investigator,
    AIThreatInvestigatorService,
)


def test_signal_1_audit_suspicious_processes():
    """Verify Signal 1 audits live processes for masquerading, volatile execution, and shellcode."""
    res = ai_threat_investigator.audit_suspicious_processes()
    assert isinstance(res, dict)
    assert res["signal_type"] == "SUSPICIOUS_PROCESSES"
    assert "total_processes_scanned" in res
    assert res["total_processes_scanned"] > 0
    assert "suspicious_process_count" in res
    assert "findings" in res
    assert isinstance(res["findings"], list)


def test_signal_2_audit_login_attempts():
    """Verify Signal 2 audits login attempts across auth logs and Windows security logs."""
    res = ai_threat_investigator.audit_login_attempts()
    assert isinstance(res, dict)
    assert res["signal_type"] == "LOGIN_ATTEMPTS"
    assert "total_failed_logins" in res
    assert "total_successful_logins" in res
    assert "findings" in res
    assert isinstance(res["findings"], list)


def test_signal_3_audit_modified_system_files(tmp_path: Path):
    """Verify Signal 3 audits critical system files against cryptographic baselines and detects modifications."""
    service = AIThreatInvestigatorService()
    # Add a temporary test file to baselines to test change detection
    test_file = tmp_path / "passwd_decoy"
    test_file.write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")
    
    # Register baseline
    service.CRITICAL_SYSTEM_FILES.append(str(test_file))
    service._initialize_file_baselines()
    assert str(test_file) in service._file_baselines
    
    # Audit before modification -> should be clean
    res_clean = service.audit_modified_system_files()
    assert res_clean["signal_type"] == "MODIFIED_SYSTEM_FILES"
    
    # Modify file -> tamper
    test_file.write_text("root:x:0:0:root:/root:/bin/bash\nhacker:x:0:0::/root:/bin/sh\n", encoding="utf-8")
    res_tampered = service.audit_modified_system_files()
    findings = [f for f in res_tampered["findings"] if f["file_path"] == str(test_file)]
    assert len(findings) == 1
    assert findings[0]["subtype"] == "CRITICAL_CONFIG_MODIFICATION"


def test_signal_4_audit_unusual_network_connections():
    """Verify Signal 4 audits network connections for RAT/C2 ports, scripts, and wildcard listeners."""
    res = ai_threat_investigator.audit_unusual_network_connections()
    assert isinstance(res, dict)
    assert res["signal_type"] == "UNUSUAL_NETWORK_CONNECTIONS"
    assert "total_sockets_audited" in res
    assert "anomalous_connections_count" in res
    assert "findings" in res
    assert 4444 in AIThreatInvestigatorService.HIGH_RISK_PORTS


def test_multi_signal_correlation_and_investigation():
    """Verify end-to-end multi-signal correlation, AI explanation, timeline, and safe remediation."""
    res = ai_threat_investigator.correlate_and_investigate()
    assert isinstance(res, dict)
    assert "investigation_id" in res
    assert res["investigation_id"].startswith("AI-INVESTIGATION-")
    assert "threat_status" in res
    assert "threat_correlation_score" in res
    assert 0 <= res["threat_correlation_score"] <= 100
    assert "signal_breakdown" in res
    
    sb = res["signal_breakdown"]
    assert "suspicious_processes" in sb
    assert "login_attempts" in sb
    assert "modified_system_files" in sb
    assert "unusual_network_connections" in sb
    
    # AI Threat Explanation
    ai_exp = res.get("ai_threat_explanation", {})
    assert "summary" in ai_exp
    assert "analyst_rationale" in ai_exp
    assert "mitre_alignment" in ai_exp
    
    # Incident Timeline
    timeline = res.get("incident_timeline", [])
    assert isinstance(timeline, list)
    if timeline:
        first_event = timeline[0]
        assert "sequence_number" in first_event
        assert "timestamp" in first_event
        assert "severity" in first_event
        assert "title" in first_event
    
    # Safe Remediation Recommendations
    remed = res.get("safe_remediation_recommendations", [])
    assert isinstance(remed, list)
    assert len(remed) > 0
    assert "recommended_command" in remed[0]
    assert "safety_precaution" in remed[0]
    
    # Cryptographic Evidence Seal & Vault File
    seal = res.get("cryptographic_evidence_seal", {})
    assert "HMAC-SHA256" in seal["algorithm"]
    assert "sha256_fingerprint" in seal
    assert "hmac_signature" in seal
    assert Path(res["sealed_evidence_filepath"]).exists()
    assert Path(res["investigation_certificate_path"]).exists()


@pytest.mark.asyncio
async def test_api_threat_investigator_endpoints(client: AsyncClient, admin_token: str):
    """Verify REST API endpoints for AI Linux Threat Investigator."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # 1. Trigger correlation investigation
    resp = await client.post("/api/v1/ai/threat-investigator", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "investigation_id" in data
    assert "threat_correlation_score" in data
    assert "signal_breakdown" in data
    
    # 2. Query 4 live signals directly
    resp_sig = await client.get("/api/v1/ai/threat-investigator/signals", headers=headers)
    assert resp_sig.status_code == 200
    sig_data = resp_sig.json()
    assert "processes" in sig_data
    assert "logins" in sig_data
    assert "files" in sig_data
    assert "network" in sig_data
    
    # 3. Retrieve latest sealed investigation dossier
    resp_latest = await client.get("/api/v1/ai/threat-investigator/latest", headers=headers)
    assert resp_latest.status_code == 200
    latest_data = resp_latest.json()
    assert "investigation_id" in latest_data
    assert "cryptographic_evidence_seal" in latest_data
