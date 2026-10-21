import os
import platform
from pathlib import Path
from typing import Dict, Any


class LinuxDistroDetector:
    """
    Cross-Distribution Linux Environment & Capability Detector.
    Identifies distribution identity (Ubuntu, Debian, Kali, Parrot, Fedora),
    kernel version, architecture, and available telemetry subsystems (journald, auditd, auth.log).
    """

    @staticmethod
    def detect_distribution() -> Dict[str, Any]:
        """
        Parses /etc/os-release or platform information.
        """
        distro_id = "linux_generic"
        version_id = "unknown"
        pretty_name = "Linux"

        os_release = Path("/etc/os-release")
        if os_release.exists():
            try:
                with open(os_release, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("ID="):
                            distro_id = line.split("=", 1)[1].strip('"').lower()
                        elif line.startswith("VERSION_ID="):
                            version_id = line.split("=", 1)[1].strip('"')
                        elif line.startswith("PRETTY_NAME="):
                            pretty_name = line.split("=", 1)[1].strip('"')
            except Exception:
                pass
        else:
            # Fallback for non-Linux or Windows development test environments
            sys_name = platform.system().lower()
            if sys_name == "windows":
                distro_id = "windows_dev"
                pretty_name = f"Windows {platform.release()}"
            elif sys_name == "darwin":
                distro_id = "macos_dev"
                pretty_name = f"macOS {platform.mac_ver()[0]}"
            else:
                distro_id = "linux_generic"
                pretty_name = "Linux Generic"

        # Check telemetry capabilities
        has_journald = Path("/run/systemd/journal").exists() or Path("/var/log/journal").exists()
        has_auth_log = Path("/var/log/auth.log").exists()
        has_secure_log = Path("/var/log/secure").exists()  # Fedora/RHEL
        has_auditd = Path("/var/log/audit/audit.log").exists()
        has_proc = Path("/proc").exists()

        auth_source = "journald"
        if has_auth_log:
            auth_source = "/var/log/auth.log"
        elif has_secure_log:
            auth_source = "/var/log/secure"
        elif has_journald:
            auth_source = "journalctl"

        return {
            "distro_id": distro_id,
            "version_id": version_id,
            "pretty_name": pretty_name,
            "kernel_version": platform.release(),
            "architecture": platform.machine(),
            "capabilities": {
                "journald": has_journald,
                "auth_log": has_auth_log,
                "secure_log": has_secure_log,
                "auditd": has_auditd,
                "procfs": has_proc,
                "primary_auth_source": auth_source,
            },
        }


distro_detector = LinuxDistroDetector()
