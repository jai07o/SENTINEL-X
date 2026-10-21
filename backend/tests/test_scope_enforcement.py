from datetime import datetime, timedelta
from backend.app.services.assessment_service import AssessmentService


class DummyScope:
    def __init__(self, target, expires_at, is_active=True, allowed_methods="HTTP_HEADERS, TLS_CIPHERS"):
        self.target = target
        self.expires_at = expires_at
        self.is_active = is_active
        self.allowed_methods = allowed_methods


def test_scope_gate_allows_valid_target():
    service = AssessmentService()
    valid_scope = DummyScope(
        target="example.com",
        expires_at=datetime.utcnow() + timedelta(days=7),
    )
    is_auth, err = service.validate_target_scope("example.com", [valid_scope], method="HTTP_HEADERS")
    assert is_auth is True
    assert err is None


def test_scope_gate_blocks_unauthorized_target():
    service = AssessmentService()
    valid_scope = DummyScope(
        target="authorized.org",
        expires_at=datetime.utcnow() + timedelta(days=7),
    )
    is_auth, err = service.validate_target_scope("unauthorized.com", [valid_scope])
    assert is_auth is False
    assert "not authorized" in err


def test_scope_gate_blocks_expired_authorization():
    service = AssessmentService()
    expired_scope = DummyScope(
        target="example.com",
        expires_at=datetime.utcnow() - timedelta(days=1),  # Expired yesterday
    )
    is_auth, err = service.validate_target_scope("example.com", [expired_scope])
    assert is_auth is False
    assert "expired" in err


def test_scope_gate_blocks_disallowed_method():
    service = AssessmentService()
    scope = DummyScope(
        target="example.com",
        expires_at=datetime.utcnow() + timedelta(days=7),
        allowed_methods="TLS_CIPHERS",  # HTTP_HEADERS NOT allowed
    )
    is_auth, err = service.validate_target_scope("example.com", [scope], method="HTTP_HEADERS")
    assert is_auth is False
    assert "not permitted" in err


def test_private_ip_ssrf_detection():
    service = AssessmentService()
    assert service.is_private_ip("127.0.0.1") is True
    assert service.is_private_ip("10.10.10.1") is True
    assert service.is_private_ip("192.168.1.1") is True
    assert service.is_private_ip("8.8.8.8") is False
