import os
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Tuple, Optional
from backend.app.config import EVIDENCE_DIR


class ForensicsService:
    """
    Digital Forensics & Chain of Custody Service.
    Enforces cryptographic integrity, immutable evidence records, and tamper detection.
    """

    def __init__(self, base_storage_dir: Optional[Path] = None):
        self.storage_dir = base_storage_dir or EVIDENCE_DIR
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def calculate_file_hashes(filepath: Path) -> Tuple[str, str, int]:
        """Calculates SHA-256, MD5, and file size in bytes."""
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        size = 0
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                md5.update(chunk)
                size += len(chunk)
        return sha256.hexdigest(), md5.hexdigest(), size

    def store_evidence_file(
        self, file_bytes: bytes, original_filename: str, evidence_number: str
    ) -> Dict[str, Any]:
        """
        Stores evidence with read-only permissions and calculates cryptographic hashes.
        """
        safe_filename = f"{evidence_number}_{original_filename.replace(' ', '_')}"
        target_path = self.storage_dir / safe_filename
        
        with open(target_path, "wb") as f:
            f.write(file_bytes)

        # Make file read-only to prevent accidental modification
        try:
            os.chmod(target_path, 0o400)
        except Exception:
            pass

        sha256_hash, md5_hash, size = self.calculate_file_hashes(target_path)

        return {
            "evidence_number": evidence_number,
            "original_filename": original_filename,
            "storage_path": str(target_path),
            "sha256_hash": sha256_hash,
            "md5_hash": md5_hash,
            "file_size_bytes": size,
            "acquired_at": datetime.utcnow(),
        }

    def verify_evidence_integrity(
        self, storage_path: str, expected_sha256: str
    ) -> Tuple[bool, str]:
        """
        Calculates cryptographic hash on disk and compares against recorded intake hash.
        Detects tampering or bit rot.
        """
        path = Path(storage_path)
        if not path.exists():
            return False, "Evidence file missing from disk vault."

        current_sha256, _, _ = self.calculate_file_hashes(path)
        is_valid = current_sha256.lower() == expected_sha256.lower()
        return is_valid, current_sha256


forensics_service = ForensicsService()
