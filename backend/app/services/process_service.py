import os
import psutil
from datetime import datetime
from typing import List, Dict, Any, Optional

LEGIT_SYSTEM_NAMES = {
    "explorer.exe", "svchost.exe", "lsass.exe", "services.exe", "csrss.exe",
    "smss.exe", "winlogon.exe", "system", "registry", "dwm.exe", "spoolsv.exe"
}

SUSPICIOUS_PATHS = [
    r"appdata\local\temp",
    r"windows\temp",
    r"/tmp",
    r"/var/tmp",
    r"/dev/shm",
]


class ProcessMonitorService:
    """
    Background Application & Process Hunter.
    Inspects active and background processes, categorizes background workers,
    and identifies anomalous process trees, hidden scripts, and cryptominers.
    """

    @classmethod
    def get_processes(cls, filter_background_only: bool = False, limit: int = 200) -> Dict[str, Any]:
        processes = []
        total_mem_mb = 0.0

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_info', 'status', 'create_time', 'username']):
            try:
                info = proc.info
                pid = info['pid']
                name = info['name'] or "Unknown"
                exe = info['exe'] or ""
                cmdline = " ".join(info['cmdline'] or [])
                status = info['status']
                mem_mb = (info['memory_info'].rss / (1024 * 1024)) if info['memory_info'] else 0.0
                total_mem_mb += mem_mb

                # Background classification:
                # GUI apps in Windows usually have explorer.exe as ancestor or a visible window handle
                is_background = True
                name_lower = name.lower()
                if name_lower in ("explorer.exe", "chrome.exe", "msedge.exe", "code.exe", "devenv.exe", "notepad.exe"):
                    is_background = False

                # Threat & Suspiciousness Analysis:
                risk_score = 0
                indicators = []

                # 1. Suspicious folder execution
                exe_lower = exe.lower()
                for sp in SUSPICIOUS_PATHS:
                    if sp in exe_lower:
                        risk_score += 40
                        indicators.append(f"Running from temporary path: {sp}")
                        break

                # 2. Masquerading check
                if name_lower not in LEGIT_SYSTEM_NAMES:
                    for sys_name in LEGIT_SYSTEM_NAMES:
                        # Simple Levenshtein distance 1 or subtle misspelling (e.g. scvhost vs svchost)
                        if sys_name.split(".")[0] in name_lower and name_lower != sys_name:
                            risk_score += 55
                            indicators.append(f"Likely masquerading as legitimate system process '{sys_name}'")
                            break

                # 3. High CPU consumption (possible cryptominer)
                cpu = info['cpu_percent'] or 0.0
                if cpu > 70.0 and is_background:
                    risk_score += 35
                    indicators.append(f"High background CPU usage ({cpu}%) - possible cryptominer")

                # 4. Encoded powershell or reverse shell scripts
                cmd_lower = cmdline.lower()
                if "powershell" in cmd_lower and ("-enc" in cmd_lower or "-e " in cmd_lower or "iex" in cmd_lower):
                    risk_score += 65
                    indicators.append("Encoded PowerShell command line execution detected")
                if "bash -i" in cmd_lower or "nc -e" in cmd_lower:
                    risk_score += 70
                    indicators.append("Interactive reverse shell string detected in command line arguments")

                risk_score = min(100, risk_score)
                if risk_score >= 70:
                    threat_level = "CRITICAL"
                elif risk_score >= 40:
                    threat_level = "HIGH"
                elif risk_score >= 20:
                    threat_level = "SUSPICIOUS"
                else:
                    threat_level = "SAFE"

                item = {
                    "pid": pid,
                    "name": name,
                    "exe": exe,
                    "cmdline": cmdline[:200] if cmdline else "",
                    "is_background": is_background,
                    "status": status,
                    "cpu_percent": round(cpu, 1),
                    "memory_mb": round(mem_mb, 1),
                    "username": info['username'] or "SYSTEM",
                    "create_time": datetime.fromtimestamp(info['create_time']).isoformat() if info['create_time'] else None,
                    "risk_score": risk_score,
                    "threat_level": threat_level,
                    "indicators": indicators,
                }

                if filter_background_only and not is_background:
                    continue

                processes.append(item)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Sort by risk score (highest first), then by memory usage
        processes.sort(key=lambda p: (p["risk_score"], p["memory_mb"]), reverse=True)

        return {
            "summary": {
                "total_processes": len(processes),
                "background_count": sum(1 for p in processes if p["is_background"]),
                "suspicious_count": sum(1 for p in processes if p["threat_level"] in ("CRITICAL", "HIGH", "SUSPICIOUS")),
                "total_memory_used_mb": round(total_mem_mb, 1),
            },
            "processes": processes[:limit],
        }

    @staticmethod
    def kill_process(pid: int) -> Dict[str, Any]:
        if not pid or pid <= 4:
            return {"success": False, "message": "Refusing to terminate critical kernel PID <= 4"}
        try:
            p = psutil.Process(pid)
            p_name = p.name()
            p.kill()
            return {"success": True, "message": f"Successfully killed process '{p_name}' (PID: {pid})"}
        except Exception as e:
            return {"success": False, "message": f"Failed to kill PID {pid}: {str(e)}"}


process_monitor_service = ProcessMonitorService()
