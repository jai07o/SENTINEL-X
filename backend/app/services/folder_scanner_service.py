import os
import math
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

from backend.app.config import PROJECT_ROOT

SUSPICIOUS_SIGNATURES = [
    (b"bash -i >& /dev/tcp", "Linux Bash Interactive Reverse Shell", 90),
    (b"nc -e /bin/sh", "Netcat Insecure Shell Spawner", 95),
    (b"nc -e /bin/bash", "Netcat Insecure Shell Spawner", 95),
    (b"eval($_POST", "PHP One-Line Web Shell", 95),
    (b"eval($_GET", "PHP One-Line Web Shell", 95),
    (b"powershell -enc", "Base64 Encoded PowerShell Execution", 80),
    (b"powershell.exe -enc", "Base64 Encoded PowerShell Execution", 80),
    (b"Invoke-Expression", "PowerShell Memory Execution (IEX)", 70),
    (b"IEX (New-Object", "PowerShell Remote Download Cradle", 85),
    (b"mimikatz", "Mimikatz Credential Dumping Signature", 90),
    (b"WScript.Shell", "Windows Script Host Shell Execution", 60),
    (b"cmd.exe /c powershell", "Process Chaining Defense Evasion", 65),
    (b"/dev/shm/", "Linux Shared Memory Drop Location", 60),
]


class FolderScannerService:
    """
    Workspace & Local Folder Threat Scanner.
    Recursively audits 'everything in this folder', computes cryptographic hashes,
    evaluates Shannon entropy for packed code, and checks for embedded malware signatures.
    """

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq: Dict[int, int] = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        for count in freq.values():
            p_x = count / length
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return round(entropy, 3)

    @classmethod
    def scan_directory(cls, target_dir: Optional[str] = None, max_files: int = 500) -> Dict[str, Any]:
        root_path = Path(target_dir) if target_dir else PROJECT_ROOT
        if not root_path.exists():
            root_path = PROJECT_ROOT

        files_scanned = []
        total_bytes = 0
        high_entropy_count = 0
        threat_count = 0

        # Skip noisy dependency and cache folders to keep scan snappy
        IGNORE_DIRS = {".git", ".venv", "node_modules", ".pytest_cache", "__pycache__", ".idea"}

        for dirpath, dirnames, filenames in os.walk(str(root_path)):
            # Filter in-place to prevent traversing ignored dirs
            dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]

            for fname in filenames:
                if len(files_scanned) >= max_files:
                    break

                full_path = Path(dirpath) / fname
                try:
                    rel_path = full_path.relative_to(root_path).as_posix()
                except Exception:
                    rel_path = full_path.name

                try:
                    stat = full_path.stat()
                    file_size = stat.st_size
                    total_bytes += file_size
                    mtime = datetime.fromtimestamp(stat.st_mtime).isoformat()

                    # Read up to 2MB for hashing & entropy analysis
                    h_sha256 = hashlib.sha256()
                    h_md5 = hashlib.md5()
                    content_sample = bytearray()

                    with open(full_path, "rb") as f:
                        while chunk := f.read(65536):
                            h_sha256.update(chunk)
                            h_md5.update(chunk)
                            if len(content_sample) < 2000000:
                                content_sample.extend(chunk[:2000000 - len(content_sample)])

                    sha256_hex = h_sha256.hexdigest()
                    md5_hex = h_md5.hexdigest()
                    entropy = cls.calculate_entropy(bytes(content_sample))

                    # Threats Analysis
                    risk_score = 0
                    threat_indicators = []

                    # 1. High Entropy check (packed, obfuscated, or encrypted payload)
                    is_high_entropy = entropy >= 7.0 and file_size > 1024
                    if is_high_entropy:
                        high_entropy_count += 1
                        risk_score += 40
                        threat_indicators.append(f"High Shannon Entropy ({entropy}/8.0) - possible packed or encrypted binary")

                    # 2. Signature match
                    for sig, desc, sig_risk in SUSPICIOUS_SIGNATURES:
                        if sig in content_sample:
                            risk_score += sig_risk
                            threat_indicators.append(desc)

                    # 3. Suspicious script extension checks
                    ext = full_path.suffix.lower()
                    if ext in (".vbs", ".scr", ".pif", ".hta"):
                        risk_score += 35
                        threat_indicators.append(f"High-risk legacy script extension ({ext})")

                    risk_score = min(100, risk_score)
                    if risk_score >= 80:
                        threat_level = "CRITICAL"
                        threat_count += 1
                    elif risk_score >= 50:
                        threat_level = "HIGH"
                        threat_count += 1
                    elif risk_score >= 25:
                        threat_level = "SUSPICIOUS"
                        threat_count += 1
                    else:
                        threat_level = "CLEAN"

                    files_scanned.append({
                        "file_name": fname,
                        "relative_path": rel_path,
                        "extension": ext or "none",
                        "size_bytes": file_size,
                        "size_formatted": f"{file_size / 1024:.1f} KB" if file_size < 1048576 else f"{file_size / (1024*1024):.2f} MB",
                        "last_modified": mtime,
                        "sha256": sha256_hex,
                        "md5": md5_hex,
                        "entropy": entropy,
                        "is_high_entropy": is_high_entropy,
                        "risk_score": risk_score,
                        "threat_level": threat_level,
                        "threat_indicators": threat_indicators,
                    })
                except Exception:
                    continue

        # Sort: highest risk first, then by size
        files_scanned.sort(key=lambda x: (x["risk_score"], x["entropy"]), reverse=True)

        return {
            "summary": {
                "scanned_directory": str(root_path),
                "total_files": len(files_scanned),
                "total_size_mb": round(total_bytes / (1024 * 1024), 2),
                "clean_files": len(files_scanned) - threat_count,
                "flagged_threats": threat_count,
                "high_entropy_files": high_entropy_count,
                "scan_completed_at": datetime.utcnow().isoformat(),
            },
            "files": files_scanned,
        }


folder_scanner_service = FolderScannerService()
