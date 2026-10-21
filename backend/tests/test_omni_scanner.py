import pytest
import io
from PIL import Image
import cv2
import numpy as np

from backend.app.services.omni_scanner_service import omni_threat_scanner


@pytest.mark.asyncio
async def test_scan_link_heuristics():
    # Test suspicious TLD and raw IP
    res = await omni_threat_scanner.scan_link("http://2130706433/login.php")
    assert res["risk_score"] > 0
    assert any("Heuristic evasion" in ind or "numeric" in ind for ind in res["threat_indicators"])

    # Test clean link
    res_clean = await omni_threat_scanner.scan_link("https://example.com")
    assert "threat_verdict" in res_clean


def test_scan_file_double_extension():
    fake_exe = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 100
    res = omni_threat_scanner.scan_file(fake_exe, filename="urgent_invoice.pdf.exe")
    assert res["risk_score"] >= 70
    assert res["threat_verdict"] == "MALICIOUS_VIRUS"
    assert any("double extension" in ind.lower() for ind in res["threat_indicators"])


def test_scan_file_pdf_malicious_actions():
    pdf_content = b"%PDF-1.4\n1 0 obj\n<< /Type /Action /S /Launch /F (cmd.exe) >>\nendobj"
    res = omni_threat_scanner.scan_file(pdf_content, filename="statement.pdf")
    assert any("/Launch" in ind for ind in res["threat_indicators"])
    assert res["risk_score"] >= 60


def test_scan_picture_polyglot_and_trailing_data():
    # Standard JPEG SOI (FF D8) + some bytes + EOI (FF D9) + appended executable (MZ)
    jpeg_head = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    jpeg_tail = b"\xFF\xD9"
    hidden_payload = b"MZ" + (b"\x90" * 100) + b"echo 'hacked'"

    stego_image = jpeg_head + (b"\xAA" * 50) + jpeg_tail + hidden_payload
    res = omni_threat_scanner.scan_picture(stego_image, filename="vacation.jpg")

    assert res["is_polyglot"] is True
    assert res["hidden_payload_type"] == "Embedded Windows PE32 Executable Polyglot"
    assert res["risk_score"] >= 70
    assert res["threat_verdict"] == "MALICIOUS_STEGO_OR_POLYGLOT"


def test_scan_picture_svg_script_injection():
    svg_data = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert("XSS")</script></svg>'
    res = omni_threat_scanner.scan_picture(svg_data, filename="avatar.svg")
    assert any("script" in ind.lower() for ind in res["threat_indicators"])
    assert res["risk_score"] >= 70


@pytest.mark.asyncio
async def test_scan_qr_code_decoding():
    # Create a synthetic QR code in memory using OpenCV or PIL
    # We can encode a test string with OpenCV
    # Note: cv2.QRCodeEncoder is available in OpenCV
    qr_encoder = cv2.QRCodeEncoder.create()
    img = qr_encoder.encode("https://sentinel-x.security/verify")
    # Convert numpy array to PNG bytes
    success, encoded_img = cv2.imencode(".png", img)
    assert success
    qr_bytes = encoded_img.tobytes()

    res = await omni_threat_scanner.scan_qr_code(qr_bytes, filename="test_qr.png")
    assert res["success"] is True
    assert "https://sentinel-x.security/verify" in res["decoded_payload"]
    assert res["is_url"] is True


@pytest.mark.asyncio
async def test_scan_deep_link_and_software():
    # Test deep path audit on a URL
    res = await omni_threat_scanner.scan_deep_link_and_software("http://2130706433/setup.exe")
    assert "audit_trail" in res
    assert "software_payloads_analyzed" in res
    assert "threat_verdict" in res
    assert len(res["audit_trail"]) > 0


@pytest.mark.asyncio
async def test_autonomous_sentinel_lifecycle():
    from backend.app.services.autonomous_sentinel_service import autonomous_sentinel_service
    # Start autonomous sentinel
    start_res = await autonomous_sentinel_service.start()
    assert start_res["success"] is True
    assert autonomous_sentinel_service.is_active is True

    # Check status
    status = autonomous_sentinel_service.get_status()
    assert status["is_active"] is True
    assert "stats" in status

    # Stop autonomous sentinel
    stop_res = await autonomous_sentinel_service.stop()
    assert stop_res["success"] is True
    assert autonomous_sentinel_service.is_active is False

