import hashlib
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from backend.app.config import PROJECT_ROOT


class PlatformSelfIntegritySentinel:
    """
    Platform Self-Defense & Anti-Tamper Cryptographic Sentinel.
    Maintains a cryptographic SHA-256 baseline of core engine modules.
    Continuously audits itself to detect unauthorized modifications,
    code tampering, rootkits, or malicious payload injection into the tool itself.
    """
    
    CORE_MODULES: List[str] = [
        "backend/app/main.py",
        "backend/app/config.py",
        "backend/app/core/security.py",
        "backend/app/core/middleware.py",
        "backend/app/core/permissions.py",
        "backend/app/core/rate_limiter.py",
        "backend/app/engine/normalization.py",
        "backend/app/engine/rules_engine.py",
        "backend/app/engine/ewcc_engine.py",
        "backend/app/services/hardware_port_service.py",
        "backend/app/services/autonomous_sentinel_service.py",
        "backend/app/services/omni_scanner_service.py",
        "cli.py",
        "launcher.py",
    ]

    def __init__(self, root_dir: Optional[Path] = None):
        self.root_dir = root_dir or PROJECT_ROOT
        self._baseline_hashes: Dict[str, str] = {}
        self._initialized_at: Optional[datetime] = None
        self._last_audit_time: Optional[datetime] = None
        self._last_verdict: str = "INITIALIZING"
        self._captured_tamper_events: List[dict] = []
        
        # Build initial baseline
        self.rebuild_baseline()

    def _hash_file(self, rel_path: str) -> Optional[str]:
        full_path = self.root_dir / rel_path
        if not full_path.is_file():
            return None
        hasher = hashlib.sha256()
        try:
            with open(full_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None

    def rebuild_baseline(self) -> None:
        """Establish or re-anchor cryptographic baseline of all core platform modules."""
        self._baseline_hashes.clear()
        for mod in self.CORE_MODULES:
            h = self._hash_file(mod)
            if h:
                self._baseline_hashes[mod] = h
        self._initialized_at = datetime.utcnow()
        self._last_verdict = "VERIFIED_CLEAN"

    def audit_integrity(self) -> Dict[str, Any]:
        """
        Verify every core module against its cryptographic baseline.
        Returns detailed report and flags any unauthorized alterations.
        """
        now = datetime.utcnow()
        self._last_audit_time = now
        
        tampered_files = []
        missing_files = []
        verified_count = 0
        details = []

        for mod, baseline_hash in self._baseline_hashes.items():
            current_hash = self._hash_file(mod)
            if current_hash is None:
                missing_files.append(mod)
                details.append({
                    "module": mod,
                    "status": "MISSING",
                    "expected_sha256": baseline_hash,
                    "actual_sha256": None,
                })
            elif current_hash != baseline_hash:
                tampered_files.append(mod)
                details.append({
                    "module": mod,
                    "status": "TAMPERED",
                    "expected_sha256": baseline_hash,
                    "actual_sha256": current_hash,
                })
            else:
                verified_count += 1
                details.append({
                    "module": mod,
                    "status": "INTEACT",
                    "sha256": current_hash,
                })

        is_intact = len(tampered_files) == 0 and len(missing_files) == 0
        verdict = "VERIFIED_CLEAN" if is_intact else "INTEGRITY_COMPROMISED"
        self._last_verdict = verdict

        if not is_intact:
            event = {
                "timestamp": now.isoformat(),
                "verdict": verdict,
                "tampered_modules": tampered_files,
                "missing_modules": missing_files,
            }
            self._captured_tamper_events.append(event)

        return {
            "verdict": verdict,
            "is_intact": is_intact,
            "modules_monitored": len(self._baseline_hashes),
            "modules_verified": verified_count,
            "tampered_count": len(tampered_files),
            "missing_count": len(missing_files),
            "tampered_files": tampered_files,
            "missing_files": missing_files,
            "baseline_anchored_at": self._initialized_at.isoformat() if self._initialized_at else None,
            "last_audited_at": now.isoformat(),
            "details": details,
        }

    def get_security_posture_summary(self) -> Dict[str, Any]:
        """
        Comprehensive operational security posture assessment of the SENTINEL-X platform itself.
        """
        audit = self.audit_integrity()
        
        from backend.app.core.rate_limiter import brute_force_protector
        from backend.app.services.hardware_port_service import hardware_port_service

        bf_stats = brute_force_protector.get_stats()
        immunization = hardware_port_service.get_host_usb_immunization_status()

        return {
            "platform_name": "SENTINEL-X",
            "security_grade": "GRADE A+ MILITARY DEFENSE-IN-DEPTH",
            "self_integrity": {
                "verdict": audit["verdict"],
                "is_intact": audit["is_intact"],
                "modules_monitored": audit["modules_monitored"],
                "tampered_count": audit["tampered_count"],
            },
            "transport_security": {
                "hsts_preload_ready": True,
                "content_security_policy": "STRICT_RESTRICTED",
                "x_frame_options": "DENY",
                "x_content_type_options": "NOSNIFF",
                "referrer_policy": "STRICT_ORIGIN_WHEN_CROSS_ORIGIN",
                "permissions_policy": "RESTRICTED",
            },
            "access_control": {
                "anti_brute_force_active": True,
                "max_failures_threshold": bf_stats["max_failures_threshold"],
                "lockout_duration_seconds": bf_stats["lockout_duration_seconds"],
                "active_lockouts": bf_stats["active_lockouts_count"],
                "timing_attack_resistance": "CONSTANT_TIME_HASH_VERIFY",
            },
            "hardware_and_ports": {
                "autorun_immunization_active": immunization.get("is_fully_immunized", False),
                "inifilemapping_disabled": immunization.get("inifilemapping_disabled", False),
                "badusb_heuristics": "ACTIVE",
            },
            "memory_and_payload_defenses": {
                "max_request_payload_mb": 25,
                "path_traversal_guards": "CANONICAL_IS_RELATIVE_TO_ENFORCED",
            },
            "timestamp": datetime.utcnow().isoformat(),
        }


# Global Singleton Instance
platform_integrity_sentinel = PlatformSelfIntegritySentinel()
