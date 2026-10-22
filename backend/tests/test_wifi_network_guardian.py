import pytest
import os
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from httpx import AsyncClient

from backend.app.services.wifi_guard_service import (
    WiFiNetworkAuditor,
    WiFiThreatDetector,
    WiFiNetworkHardener,
    WiFiForensicVault,
    WiFiTrustedStore,
    TRUSTED_WIFI_STORE,
)


def test_arp_cache_duplicate_mac_detection():
    """Validates that duplicate MAC addresses (ARP poisoning) are correctly parsed and detected."""
    mock_arp_output = """
Interface: 192.168.1.100 --- 0xb
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.45          aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.254         11-22-33-44-55-66     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
"""
    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value = MagicMock(returncode=0, stdout=mock_arp_output, stderr="")
        arp_data = WiFiNetworkAuditor.get_arp_cache()

        assert arp_data["has_duplicate_macs"] is True
        assert "aa:bb:cc:dd:ee:ff" in arp_data["duplicate_macs"]
        assert len(arp_data["duplicate_macs"]["aa:bb:cc:dd:ee:ff"]) == 2
        assert "192.168.1.1" in arp_data["duplicate_macs"]["aa:bb:cc:dd:ee:ff"]
        assert "192.168.1.45" in arp_data["duplicate_macs"]["aa:bb:cc:dd:ee:ff"]


def test_evil_twin_rogue_bssid_detection(tmp_path):
    """Validates that connecting to an unauthorized BSSID for a known SSID triggers EVIL_TWIN_ROGUE_ACCESS_POINT."""
    test_store_path = tmp_path / "test_trusted_wifi.json"
    with patch("backend.app.services.wifi_guard_service.TRUSTED_WIFI_STORE", test_store_path):
        # 1. Pin legitimate network
        WiFiTrustedStore.trust_wifi_network(
            ssid="Office-Secure-5G",
            bssid="11:22:33:44:55:66",
            cipher="CCMP",
            authentication="WPA2-Personal",
        )

        # 2. Simulate connecting to an Evil Twin with rogue BSSID
        mock_current_wifi = {
            "connected": True,
            "interface_name": "Wi-Fi",
            "ssid": "Office-Secure-5G",
            "bssid": "de:ad:be:ef:00:01",  # ROGUE BSSID!
            "authentication": "WPA2-Personal",
            "cipher": "CCMP",
            "signal_percent": "98%",
        }

        with patch.object(WiFiNetworkAuditor, "get_current_wifi_details", return_value=mock_current_wifi), \
             patch.object(WiFiNetworkAuditor, "get_visible_wifi_networks", return_value=[]), \
             patch.object(WiFiNetworkAuditor, "get_arp_cache", return_value={"has_duplicate_macs": False, "entries": []}), \
             patch.object(WiFiNetworkAuditor, "get_default_gateway", return_value={"ip": "192.168.1.1", "mac": "11:22:33:44:55:66"}), \
             patch.object(WiFiNetworkAuditor, "get_configured_dns_servers", return_value=[]):

            report = WiFiThreatDetector.audit_wifi_and_network_security()

            assert report["status"] == "THREATS_DETECTED"
            categories = [t["category"] for t in report["threats"]]
            assert "EVIL_TWIN_ROGUE_ACCESS_POINT" in categories
            evil_twin_threat = next(t for t in report["threats"] if t["category"] == "EVIL_TWIN_ROGUE_ACCESS_POINT")
            assert evil_twin_threat["severity"] == "CRITICAL"
            assert evil_twin_threat["risk_score"] >= 90
            assert evil_twin_threat["evidence"]["rogue_bssid"] == "de:ad:be:ef:00:01"


def test_wifi_cipher_downgrade_detection(tmp_path):
    """Validates that a cipher downgrade from WPA2 to Open triggers WIFI_CIPHER_DOWNGRADE_ATTACK."""
    test_store_path = tmp_path / "test_trusted_wifi.json"
    with patch("backend.app.services.wifi_guard_service.TRUSTED_WIFI_STORE", test_store_path):
        WiFiTrustedStore.trust_wifi_network(
            ssid="HomeNet",
            bssid="aa:bb:cc:11:22:33",
            cipher="CCMP",
            authentication="WPA2-Personal",
        )

        mock_current_wifi = {
            "connected": True,
            "interface_name": "Wi-Fi",
            "ssid": "HomeNet",
            "bssid": "aa:bb:cc:11:22:33",
            "authentication": "Open",  # DOWNGRADED!
            "cipher": "None",
            "signal_percent": "90%",
        }

        with patch.object(WiFiNetworkAuditor, "get_current_wifi_details", return_value=mock_current_wifi), \
             patch.object(WiFiNetworkAuditor, "get_visible_wifi_networks", return_value=[]), \
             patch.object(WiFiNetworkAuditor, "get_arp_cache", return_value={"has_duplicate_macs": False, "entries": []}), \
             patch.object(WiFiNetworkAuditor, "get_default_gateway", return_value={"ip": "192.168.1.1", "mac": "aa:bb:cc:11:22:33"}), \
             patch.object(WiFiNetworkAuditor, "get_configured_dns_servers", return_value=[]):

            report = WiFiThreatDetector.audit_wifi_and_network_security()

            categories = [t["category"] for t in report["threats"]]
            assert "WIFI_CIPHER_DOWNGRADE_ATTACK" in categories
            assert "INSECURE_OPEN_WIFI_HAZARD" in categories


def test_arp_poisoning_gateway_hijack_detection():
    """Validates detection of active ARP Poisoning when Default Gateway shares MAC with a local peer."""
    mock_arp_data = {
        "has_duplicate_macs": True,
        "mac_to_ips": {
            "00:11:22:33:44:55": ["192.168.1.1", "192.168.1.66"]  # Gateway + Hostile Attacker!
        },
        "duplicate_macs": {
            "00:11:22:33:44:55": ["192.168.1.1", "192.168.1.66"]
        },
        "entries": [],
    }

    mock_gateway = {
        "ip": "192.168.1.1",
        "mac": "00:11:22:33:44:55",
        "interface": "Wi-Fi"
    }

    with patch.object(WiFiNetworkAuditor, "get_current_wifi_details", return_value={"connected": True, "ssid": "NormalNet", "authentication": "WPA2"}), \
         patch.object(WiFiNetworkAuditor, "get_visible_wifi_networks", return_value=[]), \
         patch.object(WiFiNetworkAuditor, "get_arp_cache", return_value=mock_arp_data), \
         patch.object(WiFiNetworkAuditor, "get_default_gateway", return_value=mock_gateway), \
         patch.object(WiFiNetworkAuditor, "get_configured_dns_servers", return_value=[]):

        report = WiFiThreatDetector.audit_wifi_and_network_security()

        assert report["status"] == "THREATS_DETECTED"
        categories = [t["category"] for t in report["threats"]]
        assert "ARP_SPOOFING_MITM_ATTACK" in categories
        arp_threat = next(t for t in report["threats"] if t["category"] == "ARP_SPOOFING_MITM_ATTACK")
        assert arp_threat["severity"] == "CRITICAL"
        assert arp_threat["risk_score"] >= 95
        assert "192.168.1.66" in arp_threat["evidence"]["conflicting_local_ips"]


@pytest.mark.asyncio
async def test_wifi_forensic_vault_freeze_and_certificate(db_session):
    """Validates that WiFiForensicVault seals volatile evidence (0400) and produces signed certificate."""
    mock_audit = {
        "status": "THREATS_DETECTED",
        "overall_risk_score": 95,
        "threats_count": 1,
        "threats": [{
            "category": "EVIL_TWIN_ROGUE_ACCESS_POINT",
            "severity": "CRITICAL",
            "risk_score": 95,
            "title": "Evil Twin Detected",
            "description": "Unauthorized BSSID broadcasting target SSID.",
            "recommended_action": "EMERGENCY_DISCONNECT",
        }],
        "current_wifi": {
            "connected": True,
            "ssid": "Hostile-EvilTwin-AP",
            "bssid": "66:77:88:99:00:11",
            "authentication": "Open",
            "cipher": "None",
        },
        "default_gateway": {"ip": "10.0.0.1", "mac": "66:77:88:99:00:11"},
        "dns_servers": [{"ip": "10.0.0.1", "is_public_secure": False}],
        "arp_summary": {"has_duplicate_macs": False, "total_entries": 3},
    }

    with patch.object(WiFiNetworkHardener, "emergency_disconnect_wifi", return_value={"success": True, "details": "Disconnected"}), \
         patch.object(WiFiNetworkHardener, "purge_wifi_profile", return_value={"success": True}), \
         patch.object(WiFiNetworkHardener, "flush_arp_and_dns", return_value={"actions": ["Flushed"]}):

        res = await WiFiForensicVault.freeze_network_crime_scene_and_rectify(
            audit_report=mock_audit,
            auto_disconnect=True,
            db=db_session,
        )

        assert res["status"] == "WIFI_INCIDENT_RECTIFIED_AND_SEALED"
        assert "incident_id" in res
        assert "evidence" in res
        vault_path = Path(res["evidence"]["vault_path"])
        cert_path = Path(res["remediation"]["certificate_path"])

        # Check disk existence
        assert vault_path.exists()
        assert cert_path.exists()
        assert res["evidence"]["sha256"] is not None
        assert len(res["evidence"]["sha256"]) == 64

        # Verify certificate content
        cert_text = cert_path.read_text(encoding="utf-8")
        assert "SENTINEL-X WI-FI & NETWORK INCIDENT RECTIFICATION CERTIFICATE" in cert_text
        assert "Hostile-EvilTwin-AP" in cert_text
        assert "EVIL_TWIN_ROGUE_ACCESS_POINT" in cert_text


@pytest.mark.asyncio
async def test_wifi_guard_api_endpoints(client: AsyncClient, admin_token: str):
    """Tests the REST API routes for /api/v1/wifi-guard/status, /audit, /trust, and /harden."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Status
    res_status = await client.get("/api/v1/wifi-guard/status", headers=headers)
    assert res_status.status_code == 200
    data_status = res_status.json()
    assert data_status["status"] == "OPERATIONAL"
    assert "guardian_daemon" in data_status
    assert "active_wifi" in data_status

    # 2. Audit
    res_audit = await client.get("/api/v1/wifi-guard/audit", headers=headers)
    assert res_audit.status_code == 200
    data_audit = res_audit.json()
    assert "overall_risk_score" in data_audit
    assert "threats" in data_audit
    assert "arp_summary" in data_audit

    # 3. Trust Pinning
    res_trust = await client.post(
        "/api/v1/wifi-guard/trust",
        headers=headers,
        json={"ssid": "Lab-Secure-SSID", "bssid": "fa:ce:b0:0c:12:34"}
    )
    assert res_trust.status_code == 200
    assert res_trust.json()["status"] == "WIFI_SIGNATURE_PINNED_AND_TRUSTED"

    # 4. Network Hardening
    res_harden = await client.post("/api/v1/wifi-guard/harden", headers=headers)
    assert res_harden.status_code == 200
    assert res_harden.json()["status"] == "NETWORK_DEFENSES_HARDENED"
