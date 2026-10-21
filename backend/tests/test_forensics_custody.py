import tempfile
from pathlib import Path
from backend.app.services.forensics_service import ForensicsService


def test_evidence_intake_and_hashing():
    with tempfile.TemporaryDirectory() as tmpdir:
        service = ForensicsService(base_storage_dir=Path(tmpdir))
        content = b"CRITICAL FORENSIC MEMORY DUMP TELEMETRY ARTIFACT"
        
        stored = service.store_evidence_file(
            file_bytes=content,
            original_filename="mem_dump.raw",
            evidence_number="EV-2026-TEST",
        )
        assert len(stored["sha256_hash"]) == 64
        assert stored["file_size_bytes"] == len(content)
        assert Path(stored["storage_path"]).exists()

        # Verify integrity
        is_valid, current_hash = service.verify_evidence_integrity(
            stored["storage_path"], stored["sha256_hash"]
        )
        assert is_valid is True
        assert current_hash == stored["sha256_hash"]


def test_tamper_detection():
    with tempfile.TemporaryDirectory() as tmpdir:
        service = ForensicsService(base_storage_dir=Path(tmpdir))
        content = b"ORIGINAL PRISTINE LOGS"
        stored = service.store_evidence_file(
            file_bytes=content,
            original_filename="audit.log",
            evidence_number="EV-2026-TAMPER",
        )
        original_hash = stored["sha256_hash"]

        # Simulate deliberate tampering on disk
        target_path = Path(stored["storage_path"])
        # Remove read-only attribute if on windows to simulate rogue actor
        import os, stat
        os.chmod(target_path, stat.S_IWRITE)
        with open(target_path, "wb") as f:
            f.write(b"ROGUE ACTOR TAMPERED LOGS")

        is_valid, tampered_hash = service.verify_evidence_integrity(
            str(target_path), original_hash
        )
        assert is_valid is False  # Tampering detected!
        assert tampered_hash != original_hash
