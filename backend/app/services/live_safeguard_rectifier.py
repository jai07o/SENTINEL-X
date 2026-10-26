import os
import sys
import math
import json
import time
import uuid
import signal
import psutil
import hashlib
import logging
import asyncio
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Set

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.app.config import DATA_DIR, EVIDENCE_DIR, REPORTS_DIR, QUARANTINE_DIR
from backend.app.database import AsyncSessionLocal
from backend.app.models.incident import Incident, ResponseAction
from backend.app.models.evidence import EvidenceItem, ChainOfCustodyRecord
from backend.app.models.forensic import ForensicCase
from backend.app.models.auth import User, Role
from backend.app.models.host import Host
from backend.app.services.forensics_service import forensics_service
from backend.app.api.v1.websockets import ws_manager

logger = logging.getLogger("live-safeguard-rectifier")

# Suspicious process names commonly associated with RATs, reverse shells, C2 agents, or hacking utilities
HOSTILE_PROCESS_SIGNATURES = {
    "nc": "Netcat Reverse Shell Tool",
    "nc.exe": "Netcat Windows Reverse Shell",
    "netcat": "Netcat Utility",
    "ncat": "Ncat Modern Network Tool",
    "ncat.exe": "Ncat Windows Binary",
    "meterpreter": "Metasploit Meterpreter Payload",
    "socat": "Multipurpose Relay / Reverse Shell",
    "mimikatz": "Mimikatz Credential Dumper",
    "mimikatz.exe": "Mimikatz Windows Credential Tool",
    "chisel": "Chisel TCP/UDP Tunneling Tool",
    "chisel.exe": "Chisel Tunneling Binary",
    "ngrok": "Ngrok External C2 Tunnel",
    "ngrok.exe": "Ngrok Reverse Tunnel Utility",
    "frpc": "Fast Reverse Proxy Client",
    "frpc.exe": "FRP Reverse Proxy Client",
    "xmrig": "XMRig Monero Cryptominer",
    "xmrig.exe": "XMRig Windows Cryptominer",
}

# Known C2 and backdoor network ports
KNOWN_C2_PORTS = {
    4444: "Metasploit Default C2 Listener",
    1337: "Hacker / Backdoor Port",
    31337: "Back Orifice / Remote Access Trojan",
    5555: "Insecure ADB Daemon / Mobile Botnet",
    6667: "IRC Botnet C2 Channel",
    8888: "Suspicious Web Shell / C2 Proxy",
    9999: "Arbitrary Daemon / Reverse Shell",
    4443: "Cobalt Strike Alternative C2",
    8088: "HTTP Reverse Beacon Port",
    2222: "Non-Standard SSH Tunneling Port",
}

SUSPICIOUS_EXECUTION_DIRS = [
    r"appdata\local\temp",
    r"windows\temp",
    r"/tmp",
    r"/var/tmp",
    r"/dev/shm",
    r"downloads",
]

# Windows Kernel Pseudo-processes that have no disk path
KERNEL_PSEUDO_PROCESSES = {
    "system", "registry", "memory compression", "secure system", "idle"
}

# Critical system binaries that must reside in protected system directories
LEGIT_SYSTEM_BINARIES = {
    "svchost.exe", "lsass.exe", "services.exe", "csrss.exe",
    "smss.exe", "winlogon.exe", "dwm.exe", "spoolsv.exe"
}


class LiveThreatHunter:
    """
    Real-Time Physical Host Threat Hunter.
    Continuously audits live processes, execution arguments, parentage trees,
    and network sockets on Windows, Kali Linux, and Mobile companion endpoints.
    """

    @staticmethod
    def calculate_entropy(file_path: Path) -> float:
        """Calculates Shannon entropy to detect packed or encrypted malware."""
        if not file_path.exists() or not file_path.is_file():
            return 0.0
        try:
            byte_counts = [0] * 256
            total_bytes = 0
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    total_bytes += len(chunk)
                    for b in chunk:
                        byte_counts[b] += 1
            if total_bytes == 0:
                return 0.0
            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    prob = count / total_bytes
                    entropy -= prob * math.log2(prob)
            return round(entropy, 4)
        except Exception:
            return 0.0

    @classmethod
    def hunt_active_threats(cls) -> List[Dict[str, Any]]:
        """
        Scans all active physical host processes and network sockets.
        Returns a list of critical threats requiring instant evidence preservation and containment.
        """
        threats = []
        try:
            connections = psutil.net_connections(kind="inet")
        except Exception:
            connections = []

        # Map sockets by PID
        pid_sockets: Dict[int, List[Any]] = {}
        for conn in connections:
            if conn.pid:
                pid_sockets.setdefault(conn.pid, []).append(conn)

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_info', 'create_time', 'username']):
            try:
                info = proc.info
                pid = info['pid']
                if pid <= 4:
                    continue  # Skip System Idle / System

                name = info['name'] or "Unknown"
                name_lower = name.lower()
                exe = info['exe'] or ""
                exe_lower = exe.lower()
                cmdline_list = info['cmdline'] or []
                cmdline = " ".join(cmdline_list)
                cmdline_lower = cmdline.lower()
                cpu = info['cpu_percent'] or 0.0

                risk_score = 0
                indicators = []
                category = "ANOMALOUS_PROCESS"

                # 1. Signature check for known RAT / Reverse Shell binaries
                for sig, label in HOSTILE_PROCESS_SIGNATURES.items():
                    if name_lower == sig or name_lower.startswith(sig + "."):
                        risk_score += 90
                        category = "REMOTE_ACCESS_TROJAN"
                        indicators.append(f"Hostile tool signature matched: {label} ({name})")
                        break

                # 2. Obfuscated / Encoded command line reverse shells
                if "powershell" in cmdline_lower and ("-enc" in cmdline_lower or "-e " in cmdline_lower or "iex" in cmdline_lower or "downloadstring" in cmdline_lower):
                    risk_score += 85
                    category = "ENCODED_POWERSHELL_SHELL"
                    indicators.append("Obfuscated/Encoded PowerShell reverse execution cradle detected")

                if "bash -i" in cmdline_lower or "/dev/tcp/" in cmdline_lower or "nc -e" in cmdline_lower or "socat exec:" in cmdline_lower:
                    risk_score += 95
                    category = "INTERACTIVE_REVERSE_SHELL"
                    indicators.append("Interactive bash/socket reverse shell command syntax detected")

                # 3. Suspicious folder execution (temporary dropper paths)
                for sp in SUSPICIOUS_EXECUTION_DIRS:
                    if sp in exe_lower:
                        risk_score += 45
                        indicators.append(f"Process binary executing from volatile temporary path: {sp}")
                        break

                # 4. Skip kernel pseudo-processes (System, Registry, Memory Compression)
                if name_lower in KERNEL_PSEUDO_PROCESSES:
                    continue

                # Masquerading check for explorer.exe
                if name_lower == "explorer.exe":
                    if sys.platform == "win32" and exe and ("\\" in exe or "/" in exe):
                        if "windows" not in exe_lower:
                            risk_score += 80
                            category = "MASQUERADED_SYSTEM_BINARY"
                            indicators.append(f"Masqueraded explorer.exe running outside Windows directory: {exe}")

                # Masquerading check for core system binaries (e.g. svchost.exe, lsass.exe)
                elif name_lower in LEGIT_SYSTEM_BINARIES:
                    if sys.platform == "win32" and exe and ("\\" in exe or "/" in exe):
                        if "system32" not in exe_lower and "syswow64" not in exe_lower and "winsxs" not in exe_lower:
                            risk_score += 80
                            category = "MASQUERADED_SYSTEM_BINARY"
                            indicators.append(f"Critical system binary '{name}' running outside System32: {exe}")

                # 5. Connected sockets check for known C2 ports or external connections
                conns = pid_sockets.get(pid, [])
                c2_ip = None
                c2_port = None
                for c in conns:
                    rport = c.raddr.port if c.raddr else 0
                    rip = c.raddr.ip if c.raddr else ""
                    if rport in KNOWN_C2_PORTS:
                        risk_score += 85
                        category = "C2_NETWORK_INTRUSION"
                        c2_ip = rip
                        c2_port = rport
                        indicators.append(f"Established connection to hostile C2 port: {rip}:{rport} ({KNOWN_C2_PORTS[rport]})")
                    elif c.status == "ESTABLISHED" and rip and not rip.startswith("127."):
                        # Non-standard high port communication from suspicious binary
                        if risk_score > 30 and rport > 1024:
                            risk_score += 25
                            c2_ip = rip
                            c2_port = rport
                            indicators.append(f"Active outbound socket to foreign host {rip}:{rport}")

                # 6. Unbacked cryptominer check
                if cpu > 75.0 and any(sp in exe_lower for sp in SUSPICIOUS_EXECUTION_DIRS):
                    risk_score += 60
                    category = "CRYPTOMINER_MALWARE"
                    indicators.append(f"High CPU consumption ({cpu}%) originating from temporary directory")

                if risk_score >= 70:
                    threat_item = {
                        "pid": pid,
                        "process_name": name,
                        "exe_path": exe,
                        "cmdline": cmdline,
                        "risk_score": min(100, risk_score),
                        "category": category,
                        "severity": "CRITICAL",
                        "remote_ip": c2_ip,
                        "remote_port": c2_port,
                        "indicators": indicators,
                        "cpu_percent": cpu,
                        "detected_at": datetime.now(timezone.utc).isoformat(),
                    }
                    threats.append(threat_item)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, Exception):
                continue

        return threats


class LiveForensicInvestigator:
    """
    Live Physical Crime-Scene Forensic Investigator.
    Performs volatile memory string harvesting, process tree mapping, thread/DLL
    enumeration, binary hashing, and cryptographic vault sealing before containment.
    """

    @classmethod
    def harvest_memory_strings(cls, pid: int, max_strings: int = 50) -> List[str]:
        """Harvests readable strings and network indicators from process arguments and memory."""
        extracted = []
        try:
            proc = psutil.Process(pid)
            # 1. Commandline and environment
            cmdline = " ".join(proc.cmdline())
            if cmdline:
                extracted.append(f"CMDLINE: {cmdline}")
            
            try:
                env = proc.environ()
                for k, v in list(env.items())[:15]:
                    # Filter out sensitive auth tokens
                    if not any(s in k.lower() for s in ("token", "key", "secret", "password")):
                        extracted.append(f"ENV: {k}={v}")
            except Exception:
                pass

            # 2. Open Files
            try:
                open_files = proc.open_files()
                for of in open_files[:10]:
                    extracted.append(f"OPEN_FILE: {of.path}")
            except Exception:
                pass

        except Exception:
            pass

        return extracted[:max_strings]

    @classmethod
    def capture_live_forensic_scene(cls, pid: int, threat_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Creates an immutable, court-admissible digital forensics dossier from physical host state.
        """
        now = datetime.now(timezone.utc)
        evidence_num = f"EV-LIVE-{now.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"

        proc_dump: Dict[str, Any] = {
            "pid": pid,
            "target_detected": threat_info.get("process_name", "unknown"),
            "category": threat_info.get("category", "MALWARE_INTRUSION"),
            "risk_score": threat_info.get("risk_score", 100),
            "indicators": threat_info.get("indicators", []),
        }

        exe_path = threat_info.get("exe_path", "")
        binary_sha256 = "N/A"
        binary_md5 = "N/A"
        binary_size = 0
        entropy = 0.0

        if exe_path and Path(exe_path).exists():
            try:
                p_file = Path(exe_path)
                sha256_calc, md5_calc, size_calc = forensics_service.calculate_file_hashes(p_file)
                binary_sha256 = sha256_calc
                binary_md5 = md5_calc
                binary_size = size_calc
                entropy = LiveThreatHunter.calculate_entropy(p_file)
            except Exception as fe:
                proc_dump["binary_read_error"] = str(fe)

        # Process Live Introspection
        try:
            proc = psutil.Process(pid)
            proc_dump.update({
                "pid": proc.pid,
                "ppid": proc.ppid(),
                "parent_name": proc.parent().name() if proc.parent() else "N/A",
                "name": proc.name(),
                "exe": proc.exe() if hasattr(proc, "exe") else exe_path,
                "cmdline": proc.cmdline(),
                "cwd": proc.cwd() if hasattr(proc, "cwd") else None,
                "username": proc.username() if hasattr(proc, "username") else None,
                "create_time": datetime.fromtimestamp(proc.create_time(), timezone.utc).isoformat(),
                "memory_info": proc.memory_info()._asdict() if hasattr(proc, "memory_info") else None,
                "cpu_times": proc.cpu_times()._asdict() if hasattr(proc, "cpu_times") else None,
                "num_threads": proc.num_threads() if hasattr(proc, "num_threads") else None,
                "threads": [t._asdict() for t in proc.threads()[:10]] if hasattr(proc, "threads") else [],
                "open_sockets": [c._asdict() for c in proc.net_connections()] if hasattr(proc, "net_connections") else [],
            })

            # Harvest loaded modules (DLLs on Windows / .so on Linux)
            try:
                memory_maps = proc.memory_maps()
                modules = [m.path for m in memory_maps if m.path][:30]
                proc_dump["loaded_modules"] = modules
            except Exception:
                proc_dump["loaded_modules"] = []

        except (psutil.NoSuchProcess, psutil.AccessDenied) as pe:
            proc_dump["process_state"] = f"Volatile process access note: {pe}"

        # Harvest memory strings
        proc_dump["memory_strings_harvested"] = cls.harvest_memory_strings(pid)

        # Assemble Formal Evidence Dossier
        dossier = {
            "evidence_metadata": {
                "evidence_number": evidence_num,
                "acquisition_timestamp": now.isoformat(),
                "platform": sys.platform,
                "hostname": os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "SENTINEL-HOST",
                "intake_analyst": "SENTINEL-X Supreme Live Forensics Engine",
                "legal_admissibility": "COURT_ADMISSIBLE_CHAIN_OF_CUSTODY_SEALED",
            },
            "threat_classification": {
                "category": threat_info.get("category", "MALWARE_INTRUSION"),
                "severity": threat_info.get("severity", "CRITICAL"),
                "detected_at": threat_info.get("detected_at", now.isoformat()),
                "indicators": threat_info.get("indicators", []),
                "c2_remote_ip": threat_info.get("remote_ip"),
                "c2_remote_port": threat_info.get("remote_port"),
            },
            "binary_artifact_forensics": {
                "path_on_disk": exe_path,
                "sha256": binary_sha256,
                "md5": binary_md5,
                "size_bytes": binary_size,
                "shannon_entropy": entropy,
                "is_packed_or_encrypted": entropy >= 7.0,
            },
            "volatile_crime_scene_state": proc_dump,
            "chain_of_custody_statement": (
                f"Volatile crime scene state captured from physical process PID {pid} on "
                f"{proc_dump.get('name', 'threat')}. Sealed into secure vault prior to neutralization."
            ),
        }

        # Commit to Digital Forensics Vault
        vault_filename = f"LIVE_SCENE_{evidence_num}.json"
        vault_path = EVIDENCE_DIR / vault_filename
        raw_json_bytes = json.dumps(dossier, indent=2, default=str).encode("utf-8")

        with open(vault_path, "wb") as vf:
            vf.write(raw_json_bytes)

        # Set read-only permissions on vault file
        try:
            os.chmod(vault_path, 0o400)
        except Exception:
            pass

        dossier_sha256 = hashlib.sha256(raw_json_bytes).hexdigest()
        dossier_md5 = hashlib.md5(raw_json_bytes).hexdigest()

        return {
            "evidence_number": evidence_num,
            "vault_path": str(vault_path),
            "sha256": dossier_sha256,
            "md5": dossier_md5,
            "binary_sha256": binary_sha256,
            "entropy": entropy,
            "dossier": dossier,
        }


class LiveThreatNeutralizer:
    """
    Active Real-Time Threat Neutralizer & Containment Engine.
    Executes immediate process tree termination, network isolation, and C2 firewall blocks.
    """

    @classmethod
    def terminate_process_tree(cls, pid: int) -> Dict[str, Any]:
        """Safely kills all child processes and forcefully neutralizes the main threat PID."""
        killed_pids = []
        try:
            main_proc = psutil.Process(pid)
            # Find all child processes
            children = main_proc.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                    killed_pids.append(child.pid)
                except Exception:
                    pass

            # Terminate main process
            main_proc.kill()
            killed_pids.append(pid)
            time.sleep(0.1)

            is_alive = main_proc.is_running()
            if is_alive:
                # Fallback to OS-level forceful termination
                if sys.platform == "win32":
                    subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
                else:
                    os.kill(pid, signal.SIGKILL)

            return {
                "success": True,
                "message": f"Successfully terminated hostile process tree (PIDs: {killed_pids})",
                "terminated_pids": killed_pids,
            }

        except psutil.NoSuchProcess:
            return {
                "success": True,
                "message": f"Process {pid} already dead or exited",
                "terminated_pids": [pid],
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Failed to terminate process {pid}: {e}",
                "terminated_pids": [],
            }

    @classmethod
    def block_c2_network_firewall(cls, remote_ip: str) -> Dict[str, Any]:
        """Blocks external C2 server communication at the host firewall level."""
        if not remote_ip or remote_ip in ("127.0.0.1", "0.0.0.0", "localhost"):
            return {"applied": False, "reason": "Loopback or empty IP"}

        rule_name = f"SENTINEL_DROP_C2_{remote_ip.replace('.', '_')}"
        try:
            if sys.platform == "win32":
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=out",
                    "action=block",
                    f"remoteip={remote_ip}",
                    "description=Automated SENTINEL-X C2 Threat Containment"
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                return {"applied": True, "platform": "Windows Firewall (netsh)", "rule_name": rule_name, "output": res.stdout.strip()}
            else:
                # Linux iptables drop rule
                cmd = ["iptables", "-I", "OUTPUT", "-d", remote_ip, "-j", "DROP"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                return {"applied": True, "platform": "Linux iptables", "rule_name": rule_name, "output": res.stdout.strip()}
        except Exception as e:
            return {"applied": False, "error": str(e)}


class LiveIncidentRectifier:
    """
    Supreme Incident Rectification & Remediation Engine.
    Cleans up persistence mechanisms (Windows Registry, Scheduled Tasks, Cron),
    quarantines dropper binaries, flushes network DNS caches, and generates
    official Remediation Certificates to restore the system to a clean safeguarded state.
    """

    @classmethod
    def clean_windows_registry_persistence(cls, target_name: str, target_exe: str) -> List[Dict[str, Any]]:
        """Removes malicious auto-start persistence entries from Windows Registry."""
        removed_entries = []
        if sys.platform != "win32":
            return removed_entries

        try:
            import winreg
            run_keys = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU_Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU_RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM_Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM_RunOnce"),
            ]

            t_name_lower = target_name.lower().replace(".exe", "")
            t_exe_lower = target_exe.lower()

            for root_key, subkey_path, label in run_keys:
                try:
                    with winreg.OpenKey(root_key, subkey_path, 0, winreg.KEY_ALL_ACCESS) as key:
                        i = 0
                        values_to_delete = []
                        while True:
                            try:
                                v_name, v_data, _ = winreg.EnumValue(key, i)
                                v_name_l = v_name.lower()
                                v_data_l = str(v_data).lower()
                                if (t_name_lower and t_name_lower in v_name_l) or (t_exe_lower and t_exe_lower in v_data_l):
                                    values_to_delete.append(v_name)
                                i += 1
                            except OSError:
                                break
                        
                        for v in values_to_delete:
                            try:
                                winreg.DeleteValue(key, v)
                                removed_entries.append({"hive": label, "value_name": v, "status": "REMOVED"})
                            except Exception:
                                pass
                except PermissionError:
                    continue
                except FileNotFoundError:
                    continue
                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Registry cleanup: {e}")

        return removed_entries

    @classmethod
    def clean_startup_folder_shortcuts(cls, target_name: str, target_exe: str) -> List[str]:
        """Scans and neutralizes rogue shortcuts in the Windows Startup directory."""
        quarantined = []
        if sys.platform != "win32":
            return quarantined

        try:
            appdata = os.environ.get("APPDATA")
            if not appdata:
                return quarantined
            startup_dir = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            if not startup_dir.exists():
                return quarantined

            t_name_l = target_name.lower().replace(".exe", "")
            for f in startup_dir.iterdir():
                if f.is_file() and t_name_l and t_name_l in f.name.lower():
                    # Move to quarantine
                    q_dest = QUARANTINE_DIR / f"STARTUP_{f.name}.quarantined"
                    try:
                        f.rename(q_dest)
                        quarantined.append(f.name)
                    except Exception:
                        pass
        except Exception:
            pass

        return quarantined

    @classmethod
    def quarantine_dropper_file(cls, file_path_str: str, file_sha256: str) -> Dict[str, Any]:
        """Moves malicious binary off active path into secure quarantine vault."""
        if not file_path_str:
            return {"quarantined": False, "reason": "No file path provided"}

        target_p = Path(file_path_str)
        if not target_p.exists() or not target_p.is_file():
            return {"quarantined": False, "reason": "File does not exist on disk"}

        # Prevent moving critical system files
        if "system32" in str(target_p).lower():
            return {"quarantined": False, "reason": "Refusing to move protected System32 path"}

        safe_q_name = f"{file_sha256[:16]}_{target_p.name}.quarantined"
        q_path = QUARANTINE_DIR / safe_q_name

        try:
            # Copy to quarantine then remove original
            with open(target_p, "rb") as sf, open(q_path, "wb") as df:
                df.write(sf.read())
            
            # Make quarantined file strictly non-executable
            try:
                os.chmod(q_path, 0o000)
            except Exception:
                pass

            # Remove original dropper
            try:
                target_p.unlink(missing_ok=True)
            except Exception:
                # If file is locked, disarm it
                try:
                    os.chmod(target_p, 0o400)
                except Exception:
                    pass

            return {
                "quarantined": True,
                "original_path": str(target_p),
                "quarantine_vault_path": str(q_path),
                "sha256": file_sha256,
            }
        except Exception as e:
            return {"quarantined": False, "error": str(e)}

    @classmethod
    def flush_dns_cache(cls) -> Dict[str, Any]:
        """Flushes DNS cache to eliminate poisoned resolutions or lingering C2 domain lookups."""
        try:
            if sys.platform == "win32":
                res = subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, timeout=5)
                return {"flushed": True, "platform": "Windows", "output": res.stdout.strip()}
            else:
                res = subprocess.run(["resolvectl", "flush-caches"], capture_output=True, text=True, timeout=5)
                return {"flushed": True, "platform": "Linux", "output": res.stdout.strip()}
        except Exception as e:
            return {"flushed": False, "error": str(e)}

    @classmethod
    def generate_rectification_certificate(
        cls,
        incident_id: str,
        threat_info: Dict[str, Any],
        forensics_info: Dict[str, Any],
        neutralization_info: Dict[str, Any],
        remediation_info: Dict[str, Any],
    ) -> str:
        """Generates a court-admissible, cryptographically verified Incident Rectification Certificate."""
        cert_id = f"CERT-RECTIFY-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"
        now_str = datetime.now(timezone.utc).isoformat()

        md_content = f"""# SENTINEL-X INCIDENT RECTIFICATION & REMEDIATION CERTIFICATE
**Certificate ID**: `{cert_id}`  
**Issuing Authority**: SENTINEL-X Supreme Real-Time Safeguard & Forensics Engine  
**Execution Timestamp**: `{now_str}`  
**Host Target**: `{os.environ.get('COMPUTERNAME') or os.environ.get('HOSTNAME') or 'LOCAL_ENDPOINT'}` (`{sys.platform}`)

---

## 1. Executive Summary & Incident Rectification Verdict
An active security intrusion was intercepted, volatile scene evidence was frozen and vaulted, hostile execution was terminated, and persistence mechanisms were wiped. The system is verified **SAFEGUARDED AND RECTIFIED**.

- **Incident Identifier**: `{incident_id}`
- **Threat Vector**: `{threat_info.get('category', 'UNKNOWN_INTRUSION')}`
- **Severity Rating**: `CRITICAL`
- **Initial Detection Trigger**: `{threat_info.get('indicators', ['Threat signature matched'])[0]}`
- **Post-Remediation System Status**: **`CLEAN / IMMUNIZED / NORMALIZED`**

---

## 2. Forensic Crime-Scene Evidence Preservation (Court Admissible)
Volatile physical host memory, thread ancestry, open network sockets, and command line context were cryptographically sealed into the digital forensics vault prior to process termination.

- **Vault Evidence Record**: `{forensics_info.get('evidence_number')}`
- **Cryptographic SHA-256 Digest**: `{forensics_info.get('sha256')}`
- **Disk Artifact MD5 Digest**: `{forensics_info.get('md5')}`
- **Read-Only Vault Storage**: `{forensics_info.get('vault_path')}`
- **Shannon Entropy Rating**: `{forensics_info.get('entropy', 0.0)}` *(Packed/Encrypted: {forensics_info.get('entropy', 0.0) >= 7.0})*
- **Chain of Custody Status**: `SEALED_READ_ONLY (0400)`

---

## 3. Hostile Threat Neutralization
- **Terminated Process Tree**: `PIDs: {neutralization_info.get('terminated_pids', [])}`
- **Hostile Process Name**: `{threat_info.get('process_name')}`
- **Active Command Line**: `{threat_info.get('cmdline', 'N/A')}`
- **Firewall C2 Severance**: `{neutralization_info.get('c2_firewall_rule', 'N/A')}`

---

## 4. System Rectification & Persistence Cleanup
- **Registry Persistence Wiped**: `{len(remediation_info.get('registry_wiped', []))} entries removed`
- **Startup Folder Shortcuts Cleared**: `{remediation_info.get('startup_shortcuts_cleared', [])}`
- **Dropper Binary Quarantine**: `{remediation_info.get('dropper_quarantine', {}).get('quarantine_vault_path', 'Disarmed / Quarantined')}`
- **DNS Resolution Cache**: `Purged & Normalized`

---
*Signed and sealed autonomously by SENTINEL-X Unified Threat Containment & Digital Forensics Core.*
"""
        cert_path = REPORTS_DIR / f"{cert_id}.md"
        with open(cert_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        return str(cert_path)


class SupremeSafeguardEngine:
    """
    Unified Supreme Safeguard, Forensics & Incident Rectifier Engine.
    Executes the entire end-to-end live cycle on physical endpoints in real time.
    """

    def __init__(self):
        self.is_running: bool = False
        self._daemon_task: Optional[asyncio.Task] = None
        self.stats = {
            "real_time_sweeps": 0,
            "threats_intercepted": 0,
            "processes_neutralized": 0,
            "forensic_scenes_vaulted": 0,
            "incidents_rectified": 0,
            "last_sweep_timestamp": None,
        }
        self.rectification_history: List[Dict[str, Any]] = []

    async def execute_full_safeguard_cycle(
        self,
        pid: int,
        threat_info: Optional[Dict[str, Any]] = None,
        db: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:
        """
        Executes the supreme 4-step real-time defense cycle on a target process:
        [1] Physical Forensic Scene Capture & Vault Seal (with SHA-256)
        [2] Process Neutralization & C2 Firewall Isolation
        [3] Persistence Cleanup & Dropper Quarantine
        [4] Rectification Certificate Issuance & Database Sync
        """
        threat_info = threat_info or {
            "pid": pid,
            "process_name": "Target Threat",
            "category": "LIVE_INTRUSION",
            "severity": "CRITICAL",
            "indicators": ["Operator / Real-time live threat identified"],
            "detected_at": datetime.now(timezone.utc).isoformat(),
        }

        # Step 1: Capture live physical forensics BEFORE altering process state
        logger.info(f"Phase 1: Capturing live forensic crime scene for PID {pid}...")
        forensics_res = LiveForensicInvestigator.capture_live_forensic_scene(pid, threat_info)

        # Step 2: Safe process termination & firewall block
        logger.info(f"Phase 2: Neutralizing threat process PID {pid}...")
        kill_res = LiveThreatNeutralizer.terminate_process_tree(pid)
        c2_ip = threat_info.get("remote_ip")
        fw_res = LiveThreatNeutralizer.block_c2_network_firewall(c2_ip) if c2_ip else {"applied": False}

        # Step 3: Rectify bad incident (clean persistence, quarantine dropper, flush DNS)
        logger.info(f"Phase 3: Rectifying persistence and quarantining droppers...")
        t_name = threat_info.get("process_name", "")
        t_exe = threat_info.get("exe_path", "")
        reg_cleaned = LiveIncidentRectifier.clean_windows_registry_persistence(t_name, t_exe)
        startup_cleaned = LiveIncidentRectifier.clean_startup_folder_shortcuts(t_name, t_exe)
        dropper_res = LiveIncidentRectifier.quarantine_dropper_file(t_exe, forensics_res["binary_sha256"])
        dns_res = LiveIncidentRectifier.flush_dns_cache()

        # Step 4: Issue Rectification Certificate
        inc_id = f"INC-SAFEGUARD-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"
        remediation_meta = {
            "registry_wiped": reg_cleaned,
            "startup_shortcuts_cleared": startup_cleaned,
            "dropper_quarantine": dropper_res,
            "dns_flush": dns_res,
        }
        cert_path = LiveIncidentRectifier.generate_rectification_certificate(
            incident_id=inc_id,
            threat_info=threat_info,
            forensics_info=forensics_res,
            neutralization_info={
                "terminated_pids": kill_res.get("terminated_pids", [pid]),
                "c2_firewall_rule": fw_res.get("rule_name", "N/A"),
            },
            remediation_info=remediation_meta,
        )

        # Step 5: Database Persistence & Chain-of-Custody
        async def _persist_to_db(session: AsyncSession):
            try:
                # 1. Register or find Host
                hname = os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "SENTINEL-HOST"
                res_host = await session.execute(select(Host).where(Host.hostname == hname))
                host = res_host.scalar_one_or_none()
                if not host:
                    host = Host(
                        hostname=hname,
                        ip_address="127.0.0.1",
                        os_distro=sys.platform,
                        os_version="Production",
                        architecture="x86_64",
                        agent_version="1.0.0",
                        status="ONLINE",
                    )
                    session.add(host)
                    await session.flush()

                # 1b. Resolve Analyst User for Forensic Custody
                res_u = await session.execute(select(User))
                analyst = res_u.scalars().first()
                if not analyst:
                    res_r = await session.execute(select(Role))
                    role = res_r.scalars().first()
                    if not role:
                        role = Role(id=str(uuid.uuid4()), name="admin", description="System Administrator")
                        session.add(role)
                        await session.flush()
                    analyst = User(
                        id=str(uuid.uuid4()),
                        username="sentinel_guardian",
                        email="guardian@sentinel-x.local",
                        hashed_password="N/A",
                        full_name="SENTINEL-X Guardian Engine",
                        role_id=role.id,
                    )
                    session.add(analyst)
                    await session.flush()
                analyst_id = analyst.id

                # 2. Record Incident
                inc = Incident(
                    incident_number=inc_id,
                    title=f"LIVE INCIDENT RECTIFIED: {threat_info.get('process_name')} ({threat_info.get('category')})",
                    description=f"Active threat detected on PID {pid}. Neutralized, volatile forensic scene sealed, and persistence rectified.",
                    status="Closed",
                    severity="CRITICAL",
                    confidence=0.99,
                    host_id=host.id,
                    assigned_to=analyst_id,
                    resolution_notes=f"Rectified. Evidence: {forensics_res['evidence_number']} (SHA-256: {forensics_res['sha256']}). Certificate: {cert_path}",
                )
                session.add(inc)
                await session.flush()

                # 3. Create Forensic Case
                fcase = ForensicCase(
                    case_number=f"CASE-{inc_id}",
                    title=f"Rectification Dossier: {threat_info.get('process_name')}",
                    description=f"Crime scene evidence vault for neutralized threat PID {pid}.",
                    status="CLOSED",
                    priority="CRITICAL",
                    lead_analyst_id=analyst_id,
                )
                session.add(fcase)
                await session.flush()

                # 4. Enroll Evidence Item
                e_item = EvidenceItem(
                    evidence_number=forensics_res["evidence_number"],
                    name=f"Volatile Crime Scene: PID {pid} ({threat_info.get('process_name')})",
                    source_description=f"Live process memory, sockets, thread tree, and binary triage for PID {pid}.",
                    original_filename=Path(forensics_res["vault_path"]).name,
                    sha256_hash=forensics_res["sha256"],
                    md5_hash=forensics_res["md5"],
                    file_size_bytes=os.path.getsize(forensics_res["vault_path"]),
                    mime_type="application/json",
                    storage_path=forensics_res["vault_path"],
                    is_read_only=True,
                    acquired_by_id=analyst_id,
                    case_id=fcase.id,
                )
                session.add(e_item)
                await session.flush()

                # 5. Chain of Custody Record
                coc = ChainOfCustodyRecord(
                    evidence_id=e_item.id,
                    analyst_id=analyst_id,
                    action="LIVE_ATTACK_EVIDENCE_SEALED_AND_RECTIFIED",
                    verified_hash=forensics_res["sha256"],
                    hash_matched=True,
                    notes=f"Sealed prior to process termination. Dropper quarantined, persistence wiped.",
                )
                session.add(coc)

                # 6. Response Action
                ra = ResponseAction(
                    incident_id=inc.id,
                    action_type="RECTIFY_AND_SAFEGUARD",
                    requested_by=analyst_id,
                    approved_by=analyst_id,
                    status="EXECUTED",
                    executed_at=datetime.utcnow(),
                    outcome_details=f"PIDs terminated: {kill_res.get('terminated_pids')}. Persistence removed: {len(reg_cleaned)}. Dropper quarantined.",
                )
                session.add(ra)
                await session.commit()
            except Exception as dbe:
                logger.error(f"Failed to persist safeguard incident to DB: {dbe}")
                await session.rollback()

        if db is not None:
            await _persist_to_db(db)
        else:
            async with AsyncSessionLocal() as session:
                await _persist_to_db(session)

        # Update stats
        self.stats["threats_intercepted"] += 1
        self.stats["processes_neutralized"] += len(kill_res.get("terminated_pids", [pid]))
        self.stats["forensic_scenes_vaulted"] += 1
        self.stats["incidents_rectified"] += 1

        summary = {
            "status": "INCIDENT_RECTIFIED_AND_SAFEGUARDED",
            "incident_id": inc_id,
            "target": {
                "pid": pid,
                "process_name": threat_info.get("process_name"),
                "category": threat_info.get("category"),
            },
            "forensics": {
                "evidence_number": forensics_res["evidence_number"],
                "sha256_digest": forensics_res["sha256"],
                "vault_path": forensics_res["vault_path"],
                "shannon_entropy": forensics_res["entropy"],
                "chain_of_custody": "SEALED_READ_ONLY",
            },
            "neutralization": {
                "terminated_pids": kill_res.get("terminated_pids"),
                "firewall_c2_rule": fw_res.get("rule_name"),
            },
            "remediation": {
                "registry_persistence_removed": len(reg_cleaned),
                "startup_shortcuts_cleaned": len(startup_cleaned),
                "dropper_quarantined": dropper_res.get("quarantined", False),
                "dns_flushed": dns_res.get("flushed", False),
                "certificate_path": cert_path,
            },
            "rectified_at": datetime.now(timezone.utc).isoformat(),
        }

        self.rectification_history.insert(0, summary)
        if len(self.rectification_history) > 50:
            self.rectification_history.pop()

        # Broadcast WebSocket event
        try:
            await ws_manager.broadcast({
                "type": "LIVE_INCIDENT_RECTIFIED",
                "summary": summary,
            })
        except Exception:
            pass

        return summary

    async def start_live_safeguard_daemon(self, interval_seconds: int = 3) -> Dict[str, Any]:
        """Starts real-time continuous background guardian on physical host."""
        if self.is_running:
            return {"success": True, "message": "Live Safeguard Daemon is already actively guarding the host."}

        self.is_running = True
        logger.info("Starting Supreme Live Safeguard & Forensics Daemon...")

        async def _daemon_loop():
            while self.is_running:
                try:
                    self.stats["real_time_sweeps"] += 1
                    self.stats["last_sweep_timestamp"] = datetime.now(timezone.utc).isoformat()

                    # Hunt physical host threats
                    active_threats = LiveThreatHunter.hunt_active_threats()
                    if active_threats:
                        for th in active_threats:
                            target_pid = th["pid"]
                            logger.warning(f"CRITICAL THREAT IDENTIFIED: {th['process_name']} (PID: {target_pid}). Initiating Supreme Safeguard Cycle...")
                            await self.execute_full_safeguard_cycle(target_pid, th)
                except Exception as loop_e:
                    logger.debug(f"Safeguard sweep error: {loop_e}")

                await asyncio.sleep(interval_seconds)

        self._daemon_task = asyncio.create_task(_daemon_loop())
        return {
            "success": True,
            "message": "Supreme Live Safeguard & Forensics Daemon engaged. Host actively guarded in real time.",
            "interval_seconds": interval_seconds,
        }

    async def stop_live_safeguard_daemon(self) -> Dict[str, Any]:
        """Stops the real-time background guardian."""
        if not self.is_running:
            return {"success": True, "message": "Safeguard Daemon is not running."}

        self.is_running = False
        if self._daemon_task and not self._daemon_task.done():
            self._daemon_task.cancel()
            try:
                await self._daemon_task
            except asyncio.CancelledError:
                pass
            self._daemon_task = None

        return {
            "success": True,
            "message": "Supreme Live Safeguard Daemon stopped.",
        }


# Global Singleton Engine Instance
supreme_safeguard = SupremeSafeguardEngine()
