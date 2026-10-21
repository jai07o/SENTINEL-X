import os
import socket
import psutil
from typing import List, Dict, Any, Optional
from datetime import datetime

# Known ports frequently abused by malware C2, reverse shells, botnets, and backdoors
SUSPICIOUS_C2_PORTS = {
    4444: ("Metasploit / Default Reverse Shell", 95),
    1337: ("Elite / Hacker Backdoor", 90),
    31337: ("Back Orifice / Trojan C2", 95),
    5555: ("ADB Insecure Remote Debugging / Botnet", 85),
    6667: ("IRC Botnet Control Channel", 80),
    8888: ("Generic Web Shell / Insecure Proxy", 60),
    9999: ("Reverse Shell / Unauthorized Daemon", 75),
    4443: ("Alternative HTTPS C2 Listener (Cobalt Strike)", 85),
    1080: ("SOCKS4/5 Proxy Pivoting / Tor", 70),
    8088: ("Alternative HTTP C2 Beaconing", 65),
    2222: ("Non-standard SSH Gateway / Honeypot Probe", 65),
    445: ("SMB Remote Exploitation (EternalBlue)", 80),
    135: ("RPC Endpoint Mapper (Lateral Movement)", 70),
}

# Suspicious directories where legitimate applications should rarely run network sockets from
SUSPICIOUS_EXEC_PATHS = [
    r"appdata\local\temp",
    r"windows\temp",
    r"/tmp",
    r"/var/tmp",
    r"/dev/shm",
    r"downloads",
]


class SocketMonitorService:
    """
    Real-Time Socket & Network Connection Inspector.
    Monitors live TCP/UDP sockets, foreign inbound/outbound addresses, and evaluates
    C2 virus, reverse shell, and backdoor risks for every connected process.
    """

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        if not ip or ip in ("0.0.0.0", "127.0.0.1", "::", "::1"):
            return True
        parts = ip.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            first, second = int(parts[0]), int(parts[1])
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 169 and second == 254:
                return True
        return False

    @classmethod
    def get_active_sockets(cls) -> List[Dict[str, Any]]:
        results = []
        try:
            connections = psutil.net_connections(kind="inet")
        except Exception:
            return results

        # Cache process information by pid to avoid redundant lookups
        proc_cache: Dict[int, Dict[str, Any]] = {}

        for conn in connections:
            pid = conn.pid
            proc_info = {"name": "System/Unknown", "exe": "", "username": "", "cmdline": ""}
            if pid and pid > 0:
                if pid not in proc_cache:
                    try:
                        p = psutil.Process(pid)
                        proc_cache[pid] = {
                            "name": p.name(),
                            "exe": p.exe() if hasattr(p, "exe") else "",
                            "username": p.username() if hasattr(p, "username") else "",
                            "cmdline": " ".join(p.cmdline()[:4]) if hasattr(p, "cmdline") else "",
                        }
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        proc_cache[pid] = proc_info
                proc_info = proc_cache[pid]

            laddr_ip = conn.laddr.ip if conn.laddr else ""
            laddr_port = conn.laddr.port if conn.laddr else 0
            raddr_ip = conn.raddr.ip if conn.raddr else ""
            raddr_port = conn.raddr.port if conn.raddr else 0
            status = conn.status

            # Skip unestablished sockets without remote address unless they are listening on public interfaces
            is_external_remote = bool(raddr_ip and not cls.is_private_ip(raddr_ip))
            is_external_listen = bool(status == "LISTEN" and laddr_ip in ("0.0.0.0", "::"))

            # Calculate Threat & C2 Risk
            risk_score = 0
            threat_reasons = []

            # 1. Suspicious C2 Port Check
            if raddr_port in SUSPICIOUS_C2_PORTS:
                desc, p_risk = SUSPICIOUS_C2_PORTS[raddr_port]
                risk_score += p_risk
                threat_reasons.append(f"Remote port {raddr_port} matches known {desc}")
            elif laddr_port in SUSPICIOUS_C2_PORTS and status == "LISTEN":
                desc, p_risk = SUSPICIOUS_C2_PORTS[laddr_port]
                risk_score += p_risk
                threat_reasons.append(f"Listening on high-risk backdoor port {laddr_port} ({desc})")

            # 2. Suspicious Process Executable Location Check
            exe_lower = proc_info["exe"].lower()
            for susp_path in SUSPICIOUS_EXEC_PATHS:
                if susp_path in exe_lower:
                    risk_score += 45
                    threat_reasons.append(f"Process running from suspicious directory ({susp_path})")
                    break

            # 3. Known Reverse Shell / Masquerading Process Names
            proc_name_lower = proc_info["name"].lower()
            if proc_name_lower in ("nc.exe", "netcat", "ncat", "mimikatz.exe", "psexec.exe"):
                risk_score += 60
                threat_reasons.append(f"Known dual-use/offensive utility detected: {proc_info['name']}")

            # 4. Outbound external connection with high port
            if is_external_remote and status in ("ESTABLISHED", "SYN_SENT"):
                risk_score += 15
                threat_reasons.append(f"Active external WAN socket established to {raddr_ip}:{raddr_port}")

            # Cap risk score
            risk_score = min(100, risk_score)

            # Determine Threat Level
            if risk_score >= 80:
                threat_level = "CRITICAL"
            elif risk_score >= 50:
                threat_level = "HIGH"
            elif risk_score >= 25:
                threat_level = "SUSPICIOUS"
            else:
                threat_level = "SAFE"

            results.append({
                "socket_id": f"sock_{pid}_{laddr_port}_{raddr_port}_{status}",
                "pid": pid,
                "process_name": proc_info["name"],
                "process_path": proc_info["exe"],
                "username": proc_info["username"],
                "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                "local_ip": laddr_ip,
                "local_port": laddr_port,
                "remote_ip": raddr_ip,
                "remote_port": raddr_port,
                "status": status,
                "is_external": is_external_remote,
                "risk_score": risk_score,
                "threat_level": threat_level,
                "threat_reasons": threat_reasons,
                "timestamp": datetime.utcnow().isoformat(),
            })

        # Sort with highest risk first, then external established connections
        results.sort(key=lambda s: (s["risk_score"], s["is_external"], s["status"] == "ESTABLISHED"), reverse=True)
        return results

    @staticmethod
    def terminate_socket_process(pid: int) -> Dict[str, Any]:
        """Terminates process associated with suspicious connected socket."""
        if not pid or pid <= 4:
            return {"success": False, "message": "Cannot terminate protected system process (PID <= 4)"}
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc.terminate()
            proc.wait(timeout=2.0)
            return {"success": True, "message": f"Successfully terminated process '{proc_name}' (PID: {pid})"}
        except psutil.TimeoutExpired:
            proc.kill()
            return {"success": True, "message": f"Force-killed process '{proc_name}' (PID: {pid})"}
        except Exception as e:
            return {"success": False, "message": f"Failed to terminate process PID {pid}: {str(e)}"}


socket_monitor_service = SocketMonitorService()
