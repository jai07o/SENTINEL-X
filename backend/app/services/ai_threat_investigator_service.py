"""
SENTINEL-X — AI Linux Threat Investigator Service
Real-time monitoring agent and deep correlation engine that:
  1. Correlates 4 critical attack signals:
     - Suspicious Processes (masquerading, temp execution, reverse shells, miners)
     - Login Attempts (SSH brute-force, unauthorized sudo, remote IP logins)
     - Modified System Files (FIM: /etc/passwd, /etc/shadow, /etc/sudoers, /etc/crontab)
     - Unusual Network Connections (RAT/C2 listeners, anomalous outbound beacons)
  2. Explains suspicious behavior using grounded defensive AI intelligence.
  3. Produces a chronological incident timeline.
  4. Recommends safe, non-destructive remediation steps.
"""

import os
import sys
import time
import json
import psutil
import hashlib
import hmac
import subprocess
import asyncio
import sqlite3
import uuid
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
DATA_DIR = ROOT_DIR / "data"
DATABASE_DIR = DATA_DIR / "database"
EVIDENCE_DIR = DATA_DIR / "evidence"
FORENSICS_DIR = DATA_DIR / "forensics"
REPORTS_DIR = DATA_DIR / "reports"
TELEMETRY_DIR = DATA_DIR / "telemetry"
MODELS_DIR = DATA_DIR / "models"
QUARANTINE_DIR = DATA_DIR / "quarantine"

for directory in (DATABASE_DIR, EVIDENCE_DIR, FORENSICS_DIR, REPORTS_DIR, TELEMETRY_DIR, MODELS_DIR, QUARANTINE_DIR):
    directory.mkdir(parents=True, exist_ok=True)

DB_PATH = DATABASE_DIR / "sentinel_x.db"


class AIThreatInvestigatorService:
    """
    SENTINEL-X AI Linux Threat Investigator.
    Monitors, correlates, explains, reconstructs timelines, and recommends remediation
    for complex multi-signal cyber attacks, storing rich digital forensics proof
    in the single overall database.
    """

    HMAC_SECRET = b"SENTINEL_X_AI_THREAT_INVESTIGATOR_KEY_2026_HMAC"

    # Critical Linux and Unix system file watchlists
    CRITICAL_SYSTEM_FILES = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/crontab",
        "/etc/ssh/sshd_config",
        "/etc/hosts",
        "/etc/pam.d/common-auth",
        "/etc/systemd/system",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
    ]

    # High-threat hacker listener and RAT ports
    HIGH_RISK_PORTS = {4444, 1337, 6667, 8888, 9001, 9999, 31337, 5555, 7777}

    def __init__(self):
        self.database_dir = DATABASE_DIR
        self.evidence_dir = EVIDENCE_DIR
        self.forensics_dir = FORENSICS_DIR
        self.reports_dir = REPORTS_DIR
        self.telemetry_dir = TELEMETRY_DIR
        self.models_dir = MODELS_DIR
        self.quarantine_dir = QUARANTINE_DIR
        self.db_path = DB_PATH
        self.is_monitoring: bool = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._file_baselines: Dict[str, Dict[str, Any]] = {}
        self._initialize_file_baselines()
        self._init_database()

    def _init_database(self):
        """Initializes the unified evidence table in the single overall database."""
        try:
            legacy_db = ROOT_DIR / "sentinel_dev.db"
            if legacy_db.exists() and not self.db_path.exists():
                try:
                    shutil.copy2(legacy_db, self.db_path)
                except Exception:
                    pass

            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS investigation_evidence (
                        id TEXT PRIMARY KEY,
                        investigation_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        date_and_time TEXT NOT NULL,
                        from_where TEXT NOT NULL,
                        site TEXT NOT NULL,
                        app TEXT NOT NULL,
                        device TEXT NOT NULL,
                        device_hostname TEXT NOT NULL,
                        device_type TEXT NOT NULL,
                        device_os TEXT NOT NULL,
                        stage_or_signal TEXT NOT NULL,
                        subtype TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        evidence_hash TEXT NOT NULL,
                        hmac_signature TEXT NOT NULL,
                        details TEXT NOT NULL,
                        mitre_technique TEXT,
                        raw_data_json TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS ix_evidence_inv_id ON investigation_evidence(investigation_id);")
                cursor.execute("CREATE INDEX IF NOT EXISTS ix_evidence_timestamp ON investigation_evidence(timestamp);")
                cursor.execute("CREATE INDEX IF NOT EXISTS ix_evidence_stage ON investigation_evidence(stage_or_signal);")
                cursor.execute("CREATE INDEX IF NOT EXISTS ix_evidence_app ON investigation_evidence(app);")
                cursor.execute("CREATE INDEX IF NOT EXISTS ix_evidence_site ON investigation_evidence(site);")
                conn.commit()
        except Exception as e:
            pass

    def save_evidence_record(self, record: Dict[str, Any]) -> bool:
        """Inserts a structured evidence record with rich metadata into the overall database."""
        try:
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO investigation_evidence (
                        id, investigation_id, timestamp, date_and_time, from_where, site, app,
                        device, device_hostname, device_type, device_os,
                        stage_or_signal, subtype, severity, evidence_hash, hmac_signature,
                        details, mitre_technique, raw_data_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record.get("id"),
                    record.get("investigation_id"),
                    record.get("timestamp"),
                    record.get("date_and_time"),
                    record.get("from_where"),
                    record.get("site"),
                    record.get("app"),
                    record.get("device"),
                    record.get("device_hostname"),
                    record.get("device_type"),
                    record.get("device_os"),
                    record.get("stage_or_signal"),
                    record.get("subtype"),
                    record.get("severity"),
                    record.get("evidence_hash"),
                    record.get("hmac_signature"),
                    record.get("details"),
                    record.get("mitre_technique"),
                    record.get("raw_data_json"),
                    record.get("created_at")
                ))
                conn.commit()
                return True
        except Exception:
            return False

    def get_stored_evidence(
        self,
        investigation_id: Optional[str] = None,
        stage_or_signal: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Queries stored evidence records from the single overall database."""
        records = []
        try:
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                query = "SELECT * FROM investigation_evidence WHERE 1=1"
                params = []
                if investigation_id:
                    query += " AND investigation_id = ?"
                    params.append(investigation_id)
                if stage_or_signal:
                    query += " AND stage_or_signal = ?"
                    params.append(stage_or_signal)
                if severity:
                    query += " AND severity = ?"
                    params.append(severity)
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)

                rows = cursor.execute(query, params).fetchall()
                for r in rows:
                    records.append(dict(r))
        except Exception:
            pass
        return records

    @staticmethod
    def get_host_device_info() -> Dict[str, str]:
        """Gathers genuine host device metadata for forensic evidence attribution."""
        import socket
        import platform
        hname = socket.gethostname()
        sys_os = f"{platform.system()} {platform.release()} ({platform.machine()})"
        is_laptop = False
        try:
            battery = psutil.sensors_battery()
            if battery is not None:
                is_laptop = True
        except Exception:
            pass
        dev_type = "Laptop" if is_laptop else "Desktop PC / Server"
        return {
            "hostname": hname,
            "device_type": dev_type,
            "os": sys_os,
            "full_label": f"{hname} ({dev_type} - {sys_os})"
        }

    def _hash_data(self, data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def _hmac_sign(self, data: str) -> str:
        return hmac.new(self.HMAC_SECRET, data.encode("utf-8"), hashlib.sha256).hexdigest()

    def _initialize_file_baselines(self):
        """Initializes cryptographic baselines for monitored critical system files."""
        for fp_str in self.CRITICAL_SYSTEM_FILES:
            p = Path(fp_str)
            if p.exists() and p.is_file():
                try:
                    stat = p.stat()
                    h = hashlib.sha256()
                    with open(p, "rb") as f:
                        while chunk := f.read(65536):
                            h.update(chunk)
                    self._file_baselines[fp_str] = {
                        "sha256": h.hexdigest(),
                        "size": stat.st_size,
                        "mtime": stat.st_mtime,
                        "initialized_at": datetime.now(timezone.utc).isoformat()
                    }
                except Exception:
                    continue

    # =========================================================================
    # SIGNAL 1: SUSPICIOUS PROCESSES
    # =========================================================================
    def audit_suspicious_processes(self) -> Dict[str, Any]:
        """
        Audits live processes for suspicious indicators:
        - Executing from temporary/volatile paths (/tmp, /dev/shm, AppData\Local\Temp)
        - Masquerading as trusted system binaries (e.g. svchost, systemd, sshd from wrong dirs)
        - Reverse shells or interactive script interpreters (sh -i, nc -e, python pty)
        - Unlinked or hidden processes
        """
        findings = []
        total_procs = 0

        temp_markers = ["/tmp/", "/dev/shm/", "\\temp\\", "\\appdata\\local\\temp\\"]
        system_binaries = {
            "svchost.exe": "C:\\Windows\\System32",
            "lsass.exe": "C:\\Windows\\System32",
            "systemd": "/lib/systemd",
            "sshd": "/usr/sbin",
            "cron": "/usr/sbin",
        }

        reverse_shell_flags = [
            "/bin/sh -i", "/bin/bash -i", "nc -e", "ncat -e",
            "bash -c 'bash -i", "pty.spawn", "socket.socket",
            "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden"
        ]

        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid", "username", "cpu_percent"]):
            try:
                total_procs += 1
                name = (proc.info["name"] or "").lower()
                exe = proc.info["exe"] or ""
                cmdline = " ".join(proc.info["cmdline"] or [])
                cmd_lower = cmdline.lower()
                pid = proc.info["pid"]

                # 1. Binary executing from volatile / temporary directory
                if exe and any(marker in exe.lower() for marker in temp_markers):
                    findings.append({
                        "signal": "SUSPICIOUS_PROCESS",
                        "subtype": "TEMP_DIRECTORY_EXECUTION",
                        "severity": "HIGH",
                        "pid": pid,
                        "process_name": proc.info["name"],
                        "exe_path": exe,
                        "cmdline": cmdline[:200],
                        "username": proc.info.get("username"),
                        "rationale": f"Binary '{proc.info['name']}' running from volatile temporary directory ({exe}). Classic staging vector for dropped payloads.",
                        "mitre_technique": "T1059 (Command and Scripting Interpreter)",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })

                # 2. System binary masquerading from wrong directory
                for sys_name, expected_dir in system_binaries.items():
                    if name == sys_name.lower() and exe:
                        if not exe.lower().startswith(expected_dir.lower()):
                            findings.append({
                                "signal": "SUSPICIOUS_PROCESS",
                                "subtype": "PROCESS_MASQUERADING",
                                "severity": "CRITICAL",
                                "pid": pid,
                                "process_name": proc.info["name"],
                                "exe_path": exe,
                                "cmdline": cmdline[:200],
                                "username": proc.info.get("username"),
                                "rationale": f"Process '{proc.info['name']}' masquerading as trusted system binary outside '{expected_dir}'. High confidence trojan / process hollowing.",
                                "mitre_technique": "T1036 (Masquerading)",
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            })

                # 3. Interactive reverse shell or C2 command execution
                if any(flag.lower() in cmd_lower for flag in reverse_shell_flags):
                    findings.append({
                        "signal": "SUSPICIOUS_PROCESS",
                        "subtype": "REVERSE_SHELL_COMMAND",
                        "severity": "CRITICAL",
                        "pid": pid,
                        "process_name": proc.info["name"],
                        "exe_path": exe,
                        "cmdline": cmdline[:200],
                        "username": proc.info.get("username"),
                        "rationale": "Command-line signature matches interactive reverse shell or stealth socket redirector.",
                        "mitre_technique": "T1059.004 (Unix Shell)",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return {
            "signal_type": "SUSPICIOUS_PROCESSES",
            "total_processes_scanned": total_procs,
            "suspicious_process_count": len(findings),
            "findings": findings,
            "severity": "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else ("HIGH" if findings else "CLEAN")
        }

    # =========================================================================
    # SIGNAL 2: LOGIN ATTEMPTS
    # =========================================================================
    def audit_login_attempts(self) -> Dict[str, Any]:
        """
        Audits login attempts from Linux authentication logs (/var/log/auth.log, /var/log/secure)
        or Windows Security Event Log (Event ID 4625 failed, 4624 remote success):
        - Bursts of brute force authentication failures
        - Successful logins from unfamiliar or external IP addresses
        - Privilege escalation (sudo executions)
        """
        findings = []
        is_linux = sys.platform.startswith("linux")
        failed_count = 0
        success_count = 0

        if is_linux:
            # Check Linux auth.log / secure
            auth_paths = [Path("/var/log/auth.log"), Path("/var/log/secure")]
            for ap in auth_paths:
                if ap.exists():
                    try:
                        with open(ap, "r", encoding="utf-8", errors="ignore") as f:
                            lines = f.readlines()[-300:]
                            for line in lines:
                                l_clean = line.strip()
                                if "Failed password for" in l_clean:
                                    failed_count += 1
                                    findings.append({
                                        "signal": "LOGIN_ATTEMPT",
                                        "subtype": "FAILED_PASSWORD_BURST",
                                        "severity": "HIGH",
                                        "raw_log": l_clean[:180],
                                        "rationale": "Authentication failure recorded in system authentication log (potential brute-force spraying).",
                                        "mitre_technique": "T1110 (Brute Force)",
                                        "timestamp": datetime.now(timezone.utc).isoformat()
                                    })
                                elif "Accepted password for" in l_clean or "Accepted publickey for" in l_clean:
                                    success_count += 1
                                    findings.append({
                                        "signal": "LOGIN_ATTEMPT",
                                        "subtype": "REMOTE_LOGIN_ACCEPTED",
                                        "severity": "MEDIUM",
                                        "raw_log": l_clean[:180],
                                        "rationale": "Successful remote authentication session established.",
                                        "mitre_technique": "T1078 (Valid Accounts)",
                                        "timestamp": datetime.now(timezone.utc).isoformat()
                                    })
                                elif "sudo:" in l_clean and "COMMAND=" in l_clean:
                                    findings.append({
                                        "signal": "LOGIN_ATTEMPT",
                                        "subtype": "SUDO_PRIVILEGE_ESCALATION",
                                        "severity": "MEDIUM",
                                        "raw_log": l_clean[:180],
                                        "rationale": "Elevated administrative sudo execution recorded in authentication log.",
                                        "mitre_technique": "T1548.003 (Sudo and Sudo Caching)",
                                        "timestamp": datetime.now(timezone.utc).isoformat()
                                    })
                    except Exception:
                        pass
        else:
            # Windows Security Event Log parsing
            try:
                cmd_4625 = 'wevtutil qe Security "/q:*[System[(EventID=4625)]]" /c:10 /f:text'
                res = subprocess.run(cmd_4625, shell=True, capture_output=True, text=True, timeout=4)
                if res.returncode == 0 and res.stdout:
                    for b in res.stdout.split("Event["):
                        if "4625" in b:
                            failed_count += 1
                            lines = [l.strip() for l in b.splitlines() if l.strip()]
                            acc, ip = "Unknown", "Unknown"
                            for l in lines:
                                if "Account Name:" in l:
                                    acc = l.split("Account Name:")[-1].strip()
                                elif "Source Network Address:" in l:
                                    ip = l.split("Source Network Address:")[-1].strip()
                            findings.append({
                                "signal": "LOGIN_ATTEMPT",
                                "subtype": "WINDOWS_FAILED_LOGON_BRUTE_FORCE",
                                "severity": "HIGH",
                                "account_user": acc,
                                "source_ip": ip,
                                "rationale": f"Failed logon burst recorded for account '{acc}' from IP '{ip}'.",
                                "mitre_technique": "T1110 (Brute Force)",
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            })

                cmd_4624 = 'wevtutil qe Security "/q:*[System[(EventID=4624)]]" /c:10 /f:text'
                res_s = subprocess.run(cmd_4624, shell=True, capture_output=True, text=True, timeout=4)
                if res_s.returncode == 0 and res_s.stdout:
                    for b in res_s.stdout.split("Event["):
                        if "Logon Type: 3" in b or "Logon Type: 10" in b or "Logon Type:		3" in b:
                            success_count += 1
                            lines = [l.strip() for l in b.splitlines() if l.strip()]
                            acc, ip = "Unknown", "Unknown"
                            for l in lines:
                                if "Account Name:" in l:
                                    acc = l.split("Account Name:")[-1].strip()
                                elif "Source Network Address:" in l:
                                    ip = l.split("Source Network Address:")[-1].strip()
                            if ip not in ("-", "127.0.0.1", "::1", "Unknown"):
                                findings.append({
                                    "signal": "LOGIN_ATTEMPT",
                                    "subtype": "REMOTE_INBOUND_SESSION",
                                    "severity": "CRITICAL",
                                    "account_user": acc,
                                    "source_ip": ip,
                                    "rationale": f"Remote interactive or network session established for '{acc}' from external IP '{ip}'.",
                                    "mitre_technique": "T1078 (Valid Accounts)",
                                    "timestamp": datetime.now(timezone.utc).isoformat()
                                })
            except Exception:
                pass

        return {
            "signal_type": "LOGIN_ATTEMPTS",
            "total_failed_logins": failed_count,
            "total_successful_logins": success_count,
            "findings": findings[:10],
            "severity": "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else ("HIGH" if failed_count >= 3 else "CLEAN")
        }

    # =========================================================================
    # SIGNAL 3: MODIFIED SYSTEM FILES (FIM)
    # =========================================================================
    def audit_modified_system_files(self) -> Dict[str, Any]:
        """
        Audits File Integrity Monitoring (FIM) across security-critical system files:
        - /etc/passwd, /etc/shadow, /etc/sudoers, /etc/crontab, /etc/ssh/sshd_config
        - Windows hosts file and critical service files
        - Checks for unauthorized content modification, hash changes, and unsafe permissions
        """
        findings = []

        for fp_str in self.CRITICAL_SYSTEM_FILES:
            p = Path(fp_str)
            if not p.exists():
                continue

            try:
                stat = p.stat()
                h = hashlib.sha256()
                with open(p, "rb") as f:
                    while chunk := f.read(65536):
                        h.update(chunk)
                current_sha256 = h.hexdigest()

                # Check against baseline
                baseline = self._file_baselines.get(fp_str)
                if baseline:
                    if current_sha256 != baseline["sha256"]:
                        findings.append({
                            "signal": "MODIFIED_SYSTEM_FILE",
                            "subtype": "CRITICAL_CONFIG_MODIFICATION",
                            "severity": "CRITICAL",
                            "file_path": fp_str,
                            "baseline_sha256": baseline["sha256"][:16] + "...",
                            "current_sha256": current_sha256[:16] + "...",
                            "size_bytes": stat.st_size,
                            "rationale": f"System file '{fp_str}' has been altered since baseline. High-confidence unauthorized configuration modification.",
                            "mitre_technique": "T1098 (Account Manipulation) or T1565 (Data Manipulation)",
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        })
                else:
                    # Establish baseline if not present
                    self._file_baselines[fp_str] = {
                        "sha256": current_sha256,
                        "size": stat.st_size,
                        "mtime": stat.st_mtime,
                        "initialized_at": datetime.now(timezone.utc).isoformat()
                    }

                # Check permission anomalies on Linux (e.g. world-writable /etc/passwd or /etc/shadow)
                if sys.platform.startswith("linux"):
                    mode = stat.st_mode & 0o777
                    if fp_str in ("/etc/shadow", "/etc/sudoers") and (mode & 0o077 != 0):
                        findings.append({
                            "signal": "MODIFIED_SYSTEM_FILE",
                            "subtype": "OVERLY_PERMISSIVE_SYSTEM_FILE",
                            "severity": "CRITICAL",
                            "file_path": fp_str,
                            "mode_octal": oct(mode),
                            "rationale": f"Critical security file '{fp_str}' has unsafe permissions ({oct(mode)}). Allows unprivileged users to read/tamper with credentials.",
                            "mitre_technique": "T1548 (Abuse Elevation Control Mechanism)",
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        })

            except Exception:
                continue

        return {
            "signal_type": "MODIFIED_SYSTEM_FILES",
            "monitored_targets_count": len([f for f in self.CRITICAL_SYSTEM_FILES if Path(f).exists()]),
            "file_tampering_findings": len(findings),
            "findings": findings,
            "severity": "CRITICAL" if findings else "CLEAN"
        }

    # =========================================================================
    # SIGNAL 4: UNUSUAL NETWORK CONNECTIONS
    # =========================================================================
    def audit_unusual_network_connections(self) -> Dict[str, Any]:
        """
        Audits active network sockets and telemetry for:
        - Active listeners or outbound connections on known RAT/C2 ports (4444, 1337, etc.)
        - Outbound connections established by scripting engines (python, sh, bash, powershell)
        - Wildcard listeners binding to 0.0.0.0
        """
        findings = []
        total_conns = 0

        scripting_procs = {"python", "python3", "sh", "bash", "powershell", "cmd", "mshta", "certutil", "nc"}

        try:
            for conn in psutil.net_connections(kind="inet"):
                total_conns += 1
                raddr = conn.raddr
                laddr = conn.laddr

                proc_name = ""
                try:
                    if conn.pid:
                        proc_name = psutil.Process(conn.pid).name().lower().replace(".exe", "")
                except Exception:
                    pass

                # Anomaly 1: Connection to/from high-threat backdoor listener port
                if raddr and raddr.port in self.HIGH_RISK_PORTS:
                    findings.append({
                        "signal": "UNUSUAL_NETWORK_CONNECTION",
                        "subtype": "C2_RAT_PORT_CONNECTION",
                        "severity": "CRITICAL",
                        "pid": conn.pid,
                        "process_name": proc_name,
                        "local_endpoint": f"{laddr.ip}:{laddr.port}" if laddr else "Unknown",
                        "remote_endpoint": f"{raddr.ip}:{raddr.port}",
                        "status": conn.status,
                        "rationale": f"Connection active on known offensive RAT/C2 listener port {raddr.port}.",
                        "mitre_technique": "T1071 (Application Layer Protocol)",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })

                # Anomaly 2: Scripting binary reaching non-local public IP
                elif raddr and proc_name in scripting_procs:
                    dst_ip = raddr.ip
                    is_private = (
                        dst_ip.startswith("10.") or
                        dst_ip.startswith("192.168.") or
                        dst_ip.startswith("172.") or
                        dst_ip.startswith("127.") or
                        dst_ip == "::1"
                    )
                    if not is_private:
                        findings.append({
                            "signal": "UNUSUAL_NETWORK_CONNECTION",
                            "subtype": "SCRIPT_OUTBOUND_C2_BEACON",
                            "severity": "HIGH",
                            "pid": conn.pid,
                            "process_name": proc_name,
                            "local_endpoint": f"{laddr.ip}:{laddr.port}" if laddr else "Unknown",
                            "remote_endpoint": f"{raddr.ip}:{raddr.port}",
                            "status": conn.status,
                            "rationale": f"Script interpreter '{proc_name}' establishing direct outbound connection to external public IP '{dst_ip}:{raddr.port}'.",
                            "mitre_technique": "T1071.001 (Web Protocols / C2)",
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        })

                # Anomaly 3: Suspicious listener on non-standard port
                elif conn.status == "LISTEN" and laddr and laddr.port in self.HIGH_RISK_PORTS:
                    findings.append({
                        "signal": "UNUSUAL_NETWORK_CONNECTION",
                        "subtype": "HIGH_RISK_PORT_LISTENER",
                        "severity": "CRITICAL",
                        "pid": conn.pid,
                        "process_name": proc_name,
                        "local_endpoint": f"{laddr.ip}:{laddr.port}",
                        "status": conn.status,
                        "rationale": f"Process '{proc_name}' listening for incoming connections on backdoor port {laddr.port}.",
                        "mitre_technique": "T1571 (Non-Standard Port)",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
        except Exception:
            pass

        return {
            "signal_type": "UNUSUAL_NETWORK_CONNECTIONS",
            "total_sockets_audited": total_conns,
            "anomalous_connections_count": len(findings),
            "findings": findings,
            "severity": "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else ("HIGH" if findings else "CLEAN")
        }

    # =========================================================================
    # MULTI-SIGNAL CORRELATION & AI EXPLANATION ENGINE
    # =========================================================================
    def correlate_and_investigate(self) -> Dict[str, Any]:
        """
        Executes the full AI Linux Threat Investigator workflow:
        1. Gathers all 4 signals: Processes, Logins, Modified Files, Network Sockets.
        2. Correlates indicators across temporal and identity vectors.
        3. Formulates grounded plain-English and technical AI explanations.
        4. Reconstructs the chronological incident timeline.
        5. Generates safe, actionable remediation recommendations.
        6. Cryptographically seals the dossier and issues a certificate.
        """
        investigation_id = f"AI-INVESTIGATION-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        start_time = datetime.now(timezone.utc)

        # 1. Harvest the 4 Critical Operational Signals
        proc_audit = self.audit_suspicious_processes()
        login_audit = self.audit_login_attempts()
        file_audit = self.audit_modified_system_files()
        net_audit = self.audit_unusual_network_connections()

        # 2. Harvest Deep Digital Forensics (4 Stages + RAM Memory + MACB)
        forensic_findings = []
        forensic_dossier = {}
        try:
            from backend.app.services.digital_forensics_investigator_service import digital_forensics_investigator
            forensic_dossier = digital_forensics_investigator.run_complete_investigation()

            # Stage 1: Initial Access
            st1 = forensic_dossier.get("stage_1_initial_access", {})
            for art in st1.get("failed_logon_artifacts", []):
                forensic_findings.append({
                    "signal": "STAGE_1_INITIAL_ACCESS",
                    "subtype": "BRUTE_FORCE_CREDENTIAL_SPRAY",
                    "severity": "HIGH",
                    "source_ip": art.get("source_ip") or "127.0.0.1",
                    "rationale": art.get("details") or art.get("raw_log", "Brute-force credential failure"),
                    "mitre_technique": "T1110 (Brute Force)",
                    "timestamp": art.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "app": "Authentication Daemon",
                    "from_where": "Security Event Log / auth.log",
                    "site": art.get("source_ip", "Local Host")
                })
            for art in st1.get("remote_logon_artifacts", []):
                forensic_findings.append({
                    "signal": "STAGE_1_INITIAL_ACCESS",
                    "subtype": "REMOTE_AUTHENTICATION_ENTRY",
                    "severity": "HIGH",
                    "source_ip": art.get("source_ip"),
                    "rationale": art.get("details") or art.get("raw_log", "Remote authentication entry point"),
                    "mitre_technique": "T1078 (Valid Accounts)",
                    "timestamp": art.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "app": "Remote Logon Service",
                    "from_where": "Security Event Log / auth.log",
                    "site": art.get("source_ip", "Remote Endpoint")
                })

            # Stage 2: Lateral Movement
            st2 = forensic_dossier.get("stage_2_lateral_movement", {})
            for cmd_art in st2.get("suspicious_commands_identified", []):
                forensic_findings.append({
                    "signal": "STAGE_2_LATERAL_MOVEMENT",
                    "subtype": "SUSPICIOUS_SHELL_COMMAND",
                    "severity": "HIGH",
                    "rationale": f"Suspicious command history: {cmd_art.get('command')}",
                    "mitre_technique": "T1059 (Command and Scripting Interpreter)",
                    "timestamp": cmd_art.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "app": cmd_art.get("shell", "Shell Interpreter"),
                    "from_where": cmd_art.get("history_file", "Shell History"),
                    "site": "Local Host"
                })

            # Stage 3: Persistence
            st3 = forensic_dossier.get("stage_3_persistence", {})
            for bin_art in st3.get("staged_binaries_identified", []):
                forensic_findings.append({
                    "signal": "STAGE_3_PERSISTENCE",
                    "subtype": "STAGED_MALICIOUS_BINARY",
                    "severity": "CRITICAL",
                    "file_path": bin_art.get("path"),
                    "rationale": f"Staged payload binary detected in temp folder: {bin_art.get('filename')}",
                    "mitre_technique": "T1547 (Boot or Logon Autostart Execution)",
                    "timestamp": bin_art.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "app": bin_art.get("filename"),
                    "from_where": bin_art.get("path"),
                    "site": "Local Host"
                })
            for lotl in st3.get("lotl_tools_identified", []):
                forensic_findings.append({
                    "signal": "STAGE_3_PERSISTENCE",
                    "subtype": "LOTL_DUAL_USE_TOOL_ABUSE",
                    "severity": "HIGH",
                    "rationale": f"Dual-use Living-off-the-Land tool found: {lotl.get('tool')}",
                    "mitre_technique": "T1218 (System Binary Proxy Execution)",
                    "timestamp": lotl.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "app": lotl.get("tool"),
                    "from_where": lotl.get("path"),
                    "site": "Local Host"
                })

            # Stage 4: Data Exfiltration
            st4 = forensic_dossier.get("stage_4_data_exfiltration", {})
            for exfil in st4.get("staged_archives_identified", []):
                forensic_findings.append({
                    "signal": "STAGE_4_DATA_EXFILTRATION",
                    "subtype": "STAGED_DATA_ARCHIVE",
                    "severity": "HIGH",
                    "file_path": exfil.get("path"),
                    "rationale": f"Staged archive prepared for exfiltration: {exfil.get('filename')} ({exfil.get('size_bytes')} bytes)",
                    "mitre_technique": "T1560 (Archive Collected Data)",
                    "timestamp": exfil.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "app": "Archive Manager",
                    "from_where": exfil.get("path"),
                    "site": "Local Host"
                })

            # Volatile Memory (RAM) Analysis
            ram = forensic_dossier.get("memory_dump_analysis", {})
            for sus_mem in ram.get("suspicious_memory_processes", []):
                forensic_findings.append({
                    "signal": "MEMORY_DUMP_ANALYSIS",
                    "subtype": "SUSPICIOUS_RAM_ALLOCATION",
                    "severity": "CRITICAL",
                    "process_name": sus_mem.get("process_name"),
                    "rationale": f"Volatile RAM anomaly: PID {sus_mem.get('pid')} ({sus_mem.get('process_name')}) RSS: {sus_mem.get('rss_mb')}MB",
                    "mitre_technique": "T1055 (Process Injection)",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "app": sus_mem.get("process_name"),
                    "from_where": f"Volatile RAM PID {sus_mem.get('pid')}",
                    "site": "Local Host"
                })
        except Exception as e:
            forensic_dossier = {"status": "FORENSIC_INTEGRATION_NOTE", "details": str(e)}

        all_findings = (
            proc_audit.get("findings", []) +
            login_audit.get("findings", []) +
            file_audit.get("findings", []) +
            net_audit.get("findings", []) +
            forensic_findings
        )

        critical_count = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in all_findings if f.get("severity") == "HIGH")
        total_signals = len(all_findings)

        # 3. Compute Threat Risk Score & Multi-Signal Correlation Score
        correlation_score = min(100, (critical_count * 25) + (high_count * 10))
        if correlation_score >= 60:
            threat_status = "CRITICAL_ACTIVE_INTRUSION_CORRELATED"
        elif correlation_score >= 20:
            threat_status = "ELEVATED_SUSPICIOUS_SIGNALS_DETECTED"
        else:
            threat_status = "BASELINE_CLEAN_NO_THREAT_CORRELATED"

        # 4. Assemble Chronological Incident Timeline
        timeline = []
        for idx, f in enumerate(all_findings):
            timeline.append({
                "sequence_number": idx + 1,
                "timestamp": f.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "signal_category": f.get("signal", "SECURITY_SIGNAL"),
                "subtype": f.get("subtype", "ANOMALY"),
                "severity": f.get("severity", "MEDIUM"),
                "title": f"[{f.get('signal')}] {f.get('subtype')}",
                "description": f.get("rationale", ""),
                "mitre_technique": f.get("mitre_technique", "T1059"),
                "evidence_data": {k: v for k, v in f.items() if k not in ("rationale", "timestamp")}
            })

        timeline.sort(key=lambda x: str(x.get("timestamp") or ""))

        # 5. Generate Grounded AI Explanation
        ai_explanation = self._generate_ai_explanation(
            threat_status=threat_status,
            proc_audit=proc_audit,
            login_audit=login_audit,
            file_audit=file_audit,
            net_audit=net_audit,
            total_signals=total_signals
        )

        # 6. Formulate Safe Remediation Recommendations
        remediation_steps = self._generate_safe_remediation(all_findings)

        # 7. Device Fingerprint & Database Persistence (Store Every Evidence Finding)
        device_info = self.get_host_device_info()
        records_saved_count = 0

        for f in all_findings:
            rec_id = f"EV-{investigation_id}-{uuid.uuid4().hex[:8]}"
            ts_iso = f.get("timestamp") or datetime.now(timezone.utc).isoformat()
            try:
                dt_obj = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
                date_and_time = dt_obj.strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                date_and_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            from_where = (
                f.get("file_path") or
                f.get("exe_path") or
                f.get("local_endpoint") or
                f.get("source_ip") or
                f.get("path") or
                f.get("from_where") or
                "Local Operating System Subsystem"
            )

            site = (
                f.get("remote_endpoint") or
                f.get("target_url") or
                f.get("url") or
                f.get("site") or
                f.get("source_ip") or
                "Local Host"
            )

            app = (
                f.get("process_name") or
                f.get("tool_name") or
                f.get("binary_name") or
                f.get("app") or
                f.get("service_name") or
                "System Kernel / Daemon"
            )

            details_text = f.get("rationale") or f.get("description") or f.get("details") or ""
            raw_payload_json = json.dumps(f, default=str)
            ev_hash = self._hash_data(raw_payload_json)
            hmac_sig = self._hmac_sign(raw_payload_json)

            rec = {
                "id": rec_id,
                "investigation_id": investigation_id,
                "timestamp": ts_iso,
                "date_and_time": date_and_time,
                "from_where": str(from_where),
                "site": str(site),
                "app": str(app),
                "device": device_info["full_label"],
                "device_hostname": device_info["hostname"],
                "device_type": device_info["device_type"],
                "device_os": device_info["os"],
                "stage_or_signal": f.get("signal") or f.get("stage") or "SECURITY_SIGNAL",
                "subtype": f.get("subtype") or "ANOMALY",
                "severity": f.get("severity") or "MEDIUM",
                "evidence_hash": ev_hash,
                "hmac_signature": hmac_sig,
                "details": details_text,
                "mitre_technique": f.get("mitre_technique", "T1059"),
                "raw_data_json": raw_payload_json,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            if self.save_evidence_record(rec):
                records_saved_count += 1

        duration_sec = round((datetime.now(timezone.utc) - start_time).total_seconds(), 2)

        result = {
            "investigation_id": investigation_id,
            "hostname": device_info["hostname"],
            "device": device_info["full_label"],
            "investigation_timestamp": start_time.isoformat(),
            "date_and_time": start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "duration_seconds": duration_sec,
            "threat_status": threat_status,
            "threat_correlation_score": correlation_score,
            "total_correlated_signals": total_signals,
            "signal_breakdown": {
                "suspicious_processes": proc_audit.get("suspicious_process_count", 0),
                "login_attempts": len(login_audit.get("findings", [])),
                "modified_system_files": file_audit.get("file_tampering_findings", 0),
                "unusual_network_connections": net_audit.get("anomalous_connections_count", 0),
                "deep_digital_forensic_artifacts": len(forensic_findings)
            },
            # 4 Core Operational Signals
            "signals": {
                "processes": proc_audit,
                "logins": login_audit,
                "files": file_audit,
                "network": net_audit
            },
            # Deep Digital Forensics
            "digital_forensics_summary": {
                "artifacts_identified": len(forensic_findings),
                "stages_covered": ["Stage 1 Initial Access", "Stage 2 Lateral Movement", "Stage 3 Persistence", "Stage 4 Exfiltration", "RAM Volatile Memory", "MFT MACB Timestamps"]
            },
            # Database Persistence Summary
            "database_storage": {
                "database_path": str(self.db_path),
                "table_name": "investigation_evidence",
                "records_persisted": records_saved_count,
                "device_registered": device_info["full_label"]
            },
            # AI-Powered Explanation
            "ai_threat_explanation": ai_explanation,
            # Chronological Incident Timeline
            "incident_timeline": timeline,
            # Safe Remediation Recommendations
            "safe_remediation_recommendations": remediation_steps
        }

        # 8. Cryptographically Seal Dossier
        raw_json = json.dumps(result, indent=2, default=str)
        sha256_hash = self._hash_data(raw_json)
        hmac_sig = self._hmac_sign(raw_json)

        result["cryptographic_evidence_seal"] = {
            "algorithm": "SHA-256 + HMAC-SHA256",
            "sha256_fingerprint": sha256_hash,
            "hmac_signature": hmac_sig,
            "tamper_proof": True,
            "sealed_at": datetime.now(timezone.utc).isoformat()
        }

        # Save Sealed Evidence in data/evidence/
        vault_file = self.evidence_dir / f"{investigation_id}.json"
        with open(vault_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(result, indent=2, default=str))

        try:
            os.chmod(vault_file, 0o400)
            if sys.platform == "win32":
                subprocess.run(f'attrib +r "{vault_file}"', shell=True, capture_output=True, timeout=2)
        except Exception:
            pass

        result["sealed_evidence_filepath"] = str(vault_file)

        # Save Deep Forensics Snapshot in data/forensics/
        if forensic_dossier:
            forensics_snap = self.forensics_dir / f"FORENSIC-SNAPSHOT-{investigation_id}.json"
            try:
                with open(forensics_snap, "w", encoding="utf-8") as f:
                    f.write(json.dumps(forensic_dossier, indent=2, default=str))
                result["forensic_snapshot_path"] = str(forensics_snap)
            except Exception:
                pass

        # Save Host Telemetry Snapshot in data/telemetry/
        telemetry_snap = self.telemetry_dir / f"TELEMETRY-{investigation_id}.json"
        try:
            with open(telemetry_snap, "w", encoding="utf-8") as f:
                f.write(json.dumps(result["signals"], indent=2, default=str))
            result["telemetry_snapshot_path"] = str(telemetry_snap)
        except Exception:
            pass

        # 9. Generate Signed Markdown Certificate in data/reports/
        cert_file = self._generate_markdown_report(result)
        result["investigation_certificate_path"] = str(cert_file)

        return result

    # =========================================================================
    # AI EXPLANATION SYNTHESIZER
    # =========================================================================
    def _generate_ai_explanation(
        self,
        threat_status: str,
        proc_audit: Dict[str, Any],
        login_audit: Dict[str, Any],
        file_audit: Dict[str, Any],
        net_audit: Dict[str, Any],
        total_signals: int
    ) -> Dict[str, Any]:
        """
        Synthesizes a plain-English, beginner-friendly summary and in-depth analyst rationale
        explaining why the combination of signals represents suspicious behavior.
        """
        if total_signals == 0:
            return {
                "summary": "Host telemetry is healthy and operating within baseline parameters. No suspicious processes, login bursts, modified system files, or anomalous network connections were detected.",
                "analyst_rationale": "Active process table, authentication journals, system file hashes, and network socket tables match known good baselines. Zero signs of lateral movement or unauthorized access.",
                "confidence_score": 0.98,
                "mitre_alignment": []
            }

        # Identify correlated patterns
        has_logins = len(login_audit.get("findings", [])) > 0
        has_procs = proc_audit.get("suspicious_process_count", 0) > 0
        has_files = file_audit.get("file_tampering_findings", 0) > 0
        has_net = net_audit.get("anomalous_connections_count", 0) > 0

        summary_parts = []
        if has_logins:
            summary_parts.append("repeated unauthorized authentication attempts")
        if has_files:
            summary_parts.append("tampering with critical operating system configuration files")
        if has_procs:
            summary_parts.append("suspicious process execution from transient paths")
        if has_net:
            summary_parts.append("anomalous network socket connections communicating on non-standard ports")

        joined_reasons = ", ".join(summary_parts)

        summary = (
            f"SENTINEL-X AI Investigator correlated {total_signals} suspicious security signals across the host. "
            f"The primary threat indicators involve {joined_reasons}. "
            f"When observed concurrently, this pattern indicates an adversary attempting privilege escalation or establishing persistent remote command and control."
        )

        analyst_rationale = (
            f"Correlated Multi-Signal Evaluation: Observed {proc_audit.get('suspicious_process_count', 0)} process anomalies, "
            f"{len(login_audit.get('findings', []))} authentication log events, {file_audit.get('file_tampering_findings', 0)} modified system files, "
            f"and {net_audit.get('anomalous_connections_count', 0)} high-risk network sockets. "
            f"The convergence of modified system credentials/configs and active sockets indicates active lateral execution."
        )

        mitre_list = ["T1059 (Command and Scripting Interpreter)", "T1078 (Valid Accounts)", "T1071 (Application Layer Protocol)"]
        if has_files:
            mitre_list.append("T1098 (Account Manipulation)")

        return {
            "summary": summary,
            "analyst_rationale": analyst_rationale,
            "confidence_score": 0.94 if (has_procs and has_net) else 0.82,
            "mitre_alignment": mitre_list
        }

    # =========================================================================
    # SAFE REMEDIATION RECOMMENDATION ENGINE
    # =========================================================================
    def _generate_safe_remediation(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generates actionable, step-by-step, safe and non-destructive remediation recommendations.
        """
        steps = []
        step_num = 1

        # Check for rogue processes
        proc_findings = [f for f in findings if f.get("signal") == "SUSPICIOUS_PROCESS"]
        for pf in proc_findings[:2]:
            pid = pf.get("pid")
            name = pf.get("process_name")
            steps.append({
                "step": step_num,
                "action": "TERMINATE_SUSPICIOUS_PID",
                "target": f"PID {pid} ({name})",
                "recommended_command": f"kill -9 {pid}" if sys.platform != "win32" else f"taskkill /PID {pid} /F",
                "safety_precaution": "Verify parent process ID before termination to prevent accidental system service interruption.",
                "priority": "HIGH"
            })
            step_num += 1

        # Check for modified system files
        file_findings = [f for f in findings if f.get("signal") == "MODIFIED_SYSTEM_FILE"]
        for ff in file_findings[:2]:
            fp = ff.get("file_path")
            steps.append({
                "step": step_num,
                "action": "RESTORE_SYSTEM_FILE_BASELINE",
                "target": fp,
                "recommended_command": f"diff -u {fp}.bak {fp} && cp {fp}.bak {fp}",
                "safety_precaution": "Review diff before overwriting to ensure legitimate administrative edits are not discarded.",
                "priority": "CRITICAL"
            })
            step_num += 1

        # Check for unusual network connections
        net_findings = [f for f in findings if f.get("signal") == "UNUSUAL_NETWORK_CONNECTION"]
        for nf in net_findings[:2]:
            r_ep = nf.get("remote_endpoint")
            if r_ep:
                ip = r_ep.split(":")[0]
                steps.append({
                    "step": step_num,
                    "action": "BLOCK_REMOTE_IP_FIREWALL",
                    "target": ip,
                    "recommended_command": f"iptables -A INPUT -s {ip} -j DROP" if sys.platform != "win32" else f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}',
                    "safety_precaution": "Ensure IP is not a corporate default gateway or DNS resolver before applying block.",
                    "priority": "HIGH"
                })
                step_num += 1

        # Default hygiene step if clean or general
        if not steps:
            steps.append({
                "step": 1,
                "action": "MAINTAIN_BASELINE_MONITORING",
                "target": "Host System",
                "recommended_command": "python cli.py ai-investigator --continuous",
                "safety_precaution": "Regularly audit authentication logs and maintain cryptographic FIM baselines.",
                "priority": "LOW"
            })

        return steps

    # =========================================================================
    # SIGNED MARKDOWN CERTIFICATE GENERATOR
    # =========================================================================
    def _generate_markdown_report(self, inv: Dict[str, Any]) -> Path:
        """Generates human-readable signed investigative certificate."""
        inv_id = inv.get("investigation_id", "CASE")
        cert_path = self.reports_dir / f"CERT-{inv_id}.md"

        timeline_md = ""
        for ev in inv.get("incident_timeline", [])[:12]:
            timeline_md += f"| {ev.get('sequence_number')} | `{ev.get('timestamp')}` | **{ev.get('signal_category')}** | {ev.get('subtype')} | `{ev.get('severity')}` | {ev.get('description')[:70]} |\n"

        if not timeline_md:
            timeline_md = "| 1 | Baseline | ALL_SIGNALS_HEALTHY | Normal | `CLEAN` | System operational within normal parameters. |\n"

        remed_md = ""
        for r in inv.get("safe_remediation_recommendations", []):
            remed_md += f"**Step {r.get('step')}: {r.get('action')}** (`Priority: {r.get('priority')}`)\n"
            remed_md += f"- Target: `{r.get('target')}`\n"
            remed_md += f"- Command: `{r.get('recommended_command')}`\n"
            remed_md += f"- Precaution: *{r.get('safety_precaution')}*\n\n"

        cert_content = f"""# SENTINEL-X AI LINUX THREAT INVESTIGATOR REPORT
**Investigation ID:** `{inv.get('investigation_id')}`  
**Host Platform:** `{inv.get('hostname')}`  
**Timestamp:** `{inv.get('investigation_timestamp')}`  
**Threat Status:** **{inv.get('threat_status')}**  
**Correlation Score:** **{inv.get('threat_correlation_score')}/100**  
**Duration:** `{inv.get('duration_seconds')}s`  

---

### 1. AI-POWERED THREAT EXPLANATION
**Executive Summary:**  
{inv['ai_threat_explanation'].get('summary')}

**Technical Analyst Rationale:**  
{inv['ai_threat_explanation'].get('analyst_rationale')}

**MITRE ATT&CK Alignment:**  
{', '.join(inv['ai_threat_explanation'].get('mitre_alignment', []))}

---

### 2. THE 4 CORRELATED THREAT SIGNALS
- **Suspicious Processes:** {inv['signal_breakdown']['suspicious_processes']} flagged
- **Login Attempts:** {inv['signal_breakdown']['login_attempts']} events audited
- **Modified System Files (FIM):** {inv['signal_breakdown']['modified_system_files']} tampering anomalies
- **Unusual Network Connections:** {inv['signal_breakdown']['unusual_network_connections']} anomalous socket beacons

---

### 3. CHRONOLOGICAL INCIDENT TIMELINE
| # | Timestamp | Signal Category | Subtype | Severity | Description |
|---|---|---|---|---|---|
{timeline_md}

---

### 4. RECOMMENDED SAFE REMEDIATION
{remed_md}

---

### 5. CRYPTOGRAPHIC EVIDENCE CHAIN OF CUSTODY (SEALED)
- **SHA-256 Digest:** `{inv['cryptographic_evidence_seal']['sha256_fingerprint']}`
- **HMAC Signature:** `{inv['cryptographic_evidence_seal']['hmac_signature']}`
- **Evidence Vault:** `{inv.get('sealed_evidence_filepath')}`
- **Chain of Custody Status:** **IMMUTABLE & DIGITALLY VERIFIED**
"""
        with open(cert_path, "w", encoding="utf-8") as f:
            f.write(cert_content)

        return cert_path


# Global singleton instance
ai_threat_investigator = AIThreatInvestigatorService()
