import re
from datetime import datetime
from typing import Dict, Any, Optional


class AuthLogCollector:
    """
    Linux Authentication Log & PAM Parser.
    Extracts failed/successful logins, sudo commands, and invalid user brute force.
    """

    FAILED_PASSWORD_RE = re.compile(
        r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+) ssh2"
    )
    ACCEPTED_PASSWORD_RE = re.compile(
        r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+) ssh2"
    )
    SUDO_EXEC_RE = re.compile(
        r"(\S+) : TTY=\S+ ; PWD=\S+ ; USER=(\S+) ; COMMAND=(.*)"
    )

    def parse_auth_line(self, line: str, hostname: str) -> Optional[Dict[str, Any]]:
        """
        Parses a single line from /var/log/auth.log, /var/log/secure, or journalctl _COMM=sshd.
        """
        clean = line.strip()
        if not clean:
            return None

        now = datetime.utcnow()

        # Check Failed SSH Password
        fail_match = self.FAILED_PASSWORD_RE.search(clean)
        if fail_match:
            user, src_ip, src_port = fail_match.groups()
            return {
                "event_id": f"auth_fail_{int(now.timestamp())}_{src_ip}_{src_port}",
                "timestamp": now.isoformat(),
                "hostname": hostname,
                "source": "auth_log",
                "event_category": "AUTH_FAILURE",
                "severity": "LOW",
                "account_user": user,
                "target_user": user,
                "process_name": "sshd",
                "src_ip": src_ip,
                "src_port": int(src_port),
                "dst_port": 22,
                "raw_payload": {"line": clean, "user": user, "ip": src_ip},
            }

        # Check Accepted SSH Password
        succ_match = self.ACCEPTED_PASSWORD_RE.search(clean)
        if succ_match:
            user, src_ip, src_port = succ_match.groups()
            return {
                "event_id": f"auth_succ_{int(now.timestamp())}_{src_ip}_{src_port}",
                "timestamp": now.isoformat(),
                "hostname": hostname,
                "source": "auth_log",
                "event_category": "AUTH_SUCCESS",
                "severity": "INFORMATIONAL",
                "account_user": user,
                "process_name": "sshd",
                "src_ip": src_ip,
                "src_port": int(src_port),
                "dst_port": 22,
                "raw_payload": {"line": clean, "user": user, "ip": src_ip},
            }

        # Check Sudo Command Execution
        sudo_match = self.SUDO_EXEC_RE.search(clean)
        if sudo_match:
            invoking_user, target_user, command = sudo_match.groups()
            return {
                "event_id": f"priv_sudo_{int(now.timestamp())}_{invoking_user}",
                "timestamp": now.isoformat(),
                "hostname": hostname,
                "source": "auth_log",
                "event_category": "PRIVILEGE_ESCALATION",
                "severity": "HIGH",
                "account_user": invoking_user,
                "target_user": target_user,
                "account_uid": 0 if target_user == "root" else None,
                "process_name": "sudo",
                "process_cmdline": f"sudo {command}",
                "raw_payload": {"line": clean, "command": command, "target_user": target_user},
            }

        return None
