import os
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional


class FileIntegrityCollector:
    """
    File Integrity Monitor (FIM).
    Maintains cryptographic baseline of high-security system binaries and configurations.
    Detects unauthorized tampering with /etc/passwd, /etc/shadow, /etc/sudoers, PAM, etc.
    """

    DEFAULT_WATCHLIST = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/crontab",
        "/bin/login",
        "/bin/su",
    ]

    def __init__(self, watchlist: List[str] = None):
        self.watchlist = watchlist or self.DEFAULT_WATCHLIST
        # In-memory baseline: filepath -> {"sha256": str, "mtime": float, "size": int}
        self.baseline: Dict[str, Dict[str, Any]] = {}
        self.initialize_baseline()

    @staticmethod
    def compute_sha256(filepath: str) -> Optional[str]:
        """Computes SHA-256 for a file."""
        p = Path(filepath)
        if not p.exists() or not p.is_file():
            return None
        try:
            h = hashlib.sha256()
            with open(p, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except (PermissionError, OSError):
            return None

    def initialize_baseline(self) -> None:
        """Takes initial snapshot of watched files."""
        for path_str in self.watchlist:
            p = Path(path_str)
            if p.exists() and p.is_file():
                h = self.compute_sha256(path_str)
                if h:
                    stat = p.stat()
                    self.baseline[path_str] = {
                        "sha256": h,
                        "mtime": stat.st_mtime,
                        "size": stat.st_size,
                    }

    def check_for_changes(self, hostname: str) -> List[Dict[str, Any]]:
        """
        Scans watched files against baseline and emits events on modifications.
        """
        events = []
        now = datetime.utcnow()

        for path_str in self.watchlist:
            p = Path(path_str)
            current_hash = self.compute_sha256(path_str)

            if path_str in self.baseline:
                old_info = self.baseline[path_str]
                if current_hash is None:
                    # File was deleted!
                    events.append({
                        "event_id": f"fim_del_{int(now.timestamp())}_{os.path.basename(path_str)}",
                        "timestamp": now.isoformat(),
                        "hostname": hostname,
                        "source": "fim",
                        "event_category": "FILE_MODIFICATION",
                        "severity": "CRITICAL",
                        "file_path": path_str,
                        "file_sha256": old_info["sha256"],
                        "raw_payload": {
                            "action": "FILE_DELETED",
                            "file_path": path_str,
                            "previous_hash": old_info["sha256"],
                        },
                    })
                    del self.baseline[path_str]
                elif current_hash != old_info["sha256"]:
                    # File was modified!
                    events.append({
                        "event_id": f"fim_mod_{int(now.timestamp())}_{os.path.basename(path_str)}",
                        "timestamp": now.isoformat(),
                        "hostname": hostname,
                        "source": "fim",
                        "event_category": "FILE_MODIFICATION",
                        "severity": "CRITICAL",
                        "file_path": path_str,
                        "file_sha256": current_hash,
                        "raw_payload": {
                            "action": "FILE_MODIFIED",
                            "file_path": path_str,
                            "old_sha256": old_info["sha256"],
                            "new_sha256": current_hash,
                        },
                    })
                    # Update baseline
                    stat = p.stat()
                    self.baseline[path_str] = {
                        "sha256": current_hash,
                        "mtime": stat.st_mtime,
                        "size": stat.st_size,
                    }
            else:
                # Newly created file in watch path
                if current_hash:
                    stat = p.stat()
                    self.baseline[path_str] = {
                        "sha256": current_hash,
                        "mtime": stat.st_mtime,
                        "size": stat.st_size,
                    }
                    events.append({
                        "event_id": f"fim_new_{int(now.timestamp())}_{os.path.basename(path_str)}",
                        "timestamp": now.isoformat(),
                        "hostname": hostname,
                        "source": "fim",
                        "event_category": "FILE_MODIFICATION",
                        "severity": "HIGH",
                        "file_path": path_str,
                        "file_sha256": current_hash,
                        "raw_payload": {
                            "action": "FILE_CREATED",
                            "file_path": path_str,
                            "sha256": current_hash,
                        },
                    })

        return events
