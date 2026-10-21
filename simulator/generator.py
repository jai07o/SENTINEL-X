import time
from datetime import datetime, timedelta
from typing import List, Dict, Any
from backend.app.schemas.event import RawEventIngest


class LabTelemetrySimulator:
    """
    Synthetic Telemetry Simulator for Safe, Reproducible Security Testing.
    Generates deterministic attack scenarios and benign noise without executing live exploits.
    """

    @staticmethod
    def generate_ssh_brute_force_scenario(
        host_id: str = "host-srv-ubuntu-01",
        num_failures: int = 7,
        target_user: str = "admin",
        attacker_ip: str = "198.51.100.42",
    ) -> List[RawEventIngest]:
        """
        Simulates an automated SSH password guessing attempt:
        Multiple rapid AUTH_FAILURE events followed by an eventual AUTH_SUCCESS or lock.
        """
        events = []
        base_time = datetime.utcnow() - timedelta(seconds=num_failures * 3)

        for i in range(num_failures):
            t = base_time + timedelta(seconds=i * 2)
            events.append(
                RawEventIngest(
                    event_id=f"sim_ssh_fail_{i}",
                    timestamp=t,
                    hostname=host_id,
                    source="auth_log",
                    event_category="AUTH_FAILURE",
                    severity="LOW",
                    account_user=target_user,
                    target_user=target_user,
                    process_name="sshd",
                    process_pid=1024 + i,
                    src_ip=attacker_ip,
                    src_port=40000 + i,
                    dst_ip="10.0.0.5",
                    dst_port=22,
                    raw_payload={
                        "message": f"Failed password for {target_user} from {attacker_ip} port {40000+i} ssh2",
                        "attempt": i + 1,
                    },
                )
            )

        return events

    @staticmethod
    def generate_privilege_escalation_scenario(
        host_id: str = "host-srv-fedora-01",
        user: str = "developer",
    ) -> List[RawEventIngest]:
        """
        Simulates execution of sudo commands leading to root privilege acquisition.
        """
        now = datetime.utcnow()
        return [
            RawEventIngest(
                event_id="sim_sudo_exec_01",
                timestamp=now - timedelta(seconds=5),
                hostname=host_id,
                source="auditd",
                event_category="PRIVILEGE_ESCALATION",
                severity="HIGH",
                account_user=user,
                account_uid=0,  # Effective root
                process_name="sudo",
                process_pid=31415,
                process_cmdline="sudo /bin/bash",
                raw_payload={
                    "comm": "sudo",
                    "euid": 0,
                    "auid": 1001,
                    "tty": "pts/0",
                },
            )
        ]

    @staticmethod
    def generate_fim_tampering_scenario(
        host_id: str = "host-kali-01",
        tampered_file: str = "/etc/shadow",
    ) -> List[RawEventIngest]:
        """
        Simulates File Integrity Monitor (FIM) alert on security-critical file.
        """
        now = datetime.utcnow()
        return [
            RawEventIngest(
                event_id="sim_fim_shadow_01",
                timestamp=now - timedelta(seconds=2),
                hostname=host_id,
                source="fim",
                event_category="FILE_MODIFICATION",
                severity="CRITICAL",
                file_path=tampered_file,
                file_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                process_name="nano",
                process_pid=9988,
                account_user="root",
                account_uid=0,
                raw_payload={
                    "action": "MODIFY",
                    "file": tampered_file,
                    "diff": "user entry modified",
                },
            )
        ]

    @staticmethod
    def generate_benign_administrative_noise(
        host_id: str = "host-srv-ubuntu-01",
        count: int = 20,
    ) -> List[RawEventIngest]:
        """
        Generates normal system operations (routine cron, successful SSH logins, systemd services)
        to measure false-positive rates.
        """
        events = []
        now = datetime.utcnow()

        for i in range(count):
            t = now - timedelta(seconds=(count - i) * 10)
            events.append(
                RawEventIngest(
                    event_id=f"sim_benign_{i}",
                    timestamp=t,
                    hostname=host_id,
                    source="systemd_journal",
                    event_category="AUTH_SUCCESS",
                    severity="INFORMATIONAL",
                    account_user="deploy",
                    process_name="systemd",
                    process_pid=1,
                    raw_payload={
                        "unit": "daily-backup.service",
                        "status": "active",
                    },
                )
            )

        return events


simulator = LabTelemetrySimulator()
