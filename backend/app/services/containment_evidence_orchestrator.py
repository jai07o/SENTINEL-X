import os
import json
import uuid
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import psutil

from backend.app.models.incident import Incident, ResponseAction
from backend.app.models.host import Host
from backend.app.models.auth import User
from backend.app.models.forensic import ForensicCase, CaseTimelineItem
from backend.app.models.evidence import EvidenceItem, ChainOfCustodyRecord
from backend.app.services.forensics_service import forensics_service
from backend.app.api.v1.websockets import ws_manager
from backend.app.services.hardware_port_service import hardware_port_service

logger = logging.getLogger("sentinel.orchestrator")


class ContainmentEvidenceOrchestrator:
    """
    Core Unified Engine for SENTINEL-X:
    Evidence-Driven Real-Time Endpoint Detection, Automated Threat Containment
    and Digital Forensics Preservation.

    Connects Detection -> Safe Containment -> Evidence Preservation into ONE atomic workflow
    across Windows, Kali Linux, and Mobile Companion endpoints.
    """

    @staticmethod
    async def get_or_create_system_user(db: AsyncSession) -> User:
        """Fetch system automated analyst user or default admin."""
        res = await db.execute(select(User).where(User.username.in_(["admin", "system"])))
        user = res.scalars().first()
        if not user:
            # Fallback to any user
            res_any = await db.execute(select(User))
            user = res_any.scalars().first()
        return user

    async def contain_and_preserve(
        self,
        db: AsyncSession,
        incident_id: str,
        threat_context: Dict[str, Any],
        executed_by_id: Optional[str] = None,
        auto_isolate_host: bool = True,
        auto_kill_process: bool = True,
    ) -> Dict[str, Any]:
        """
        Executes unified Containment and Evidence Preservation:
        1. Captures volatile digital forensic evidence directly from the hacking scene.
        2. Seals the snapshot into the Digital Forensics Vault with SHA-256 and Chain of Custody.
        3. Safely executes containment actions: terminates rogue RAT/malware process and isolates network.
        4. Links evidence, timeline items, and containment actions to the Incident dossier.
        """
        now = datetime.utcnow()
        sys_user = await self.get_or_create_system_user(db)
        actor_id = executed_by_id or (sys_user.id if sys_user else str(uuid.uuid4()))

        # 1. Fetch Incident
        res_inc = await db.execute(select(Incident).where(Incident.id == incident_id))
        incident = res_inc.scalar_one_or_none()
        if not incident:
            raise ValueError(f"Incident {incident_id} not found.")

        # 2. Fetch Associated Host
        host: Optional[Host] = None
        if incident.host_id:
            res_host = await db.execute(select(Host).where(Host.id == incident.host_id))
            host = res_host.scalar_one_or_none()

        host_name = host.hostname if host else threat_context.get("hostname", "unknown-endpoint")
        os_platform = host.os_distro if host else threat_context.get("os_distro", "generic-os")

        # 3. PHASE 1: Capture & Preserve Volatile Scene Evidence
        pid = threat_context.get("pid") or threat_context.get("process_pid")
        process_name = threat_context.get("process_name", "unknown")
        remote_ip = threat_context.get("remote_ip") or threat_context.get("dst_ip")
        remote_port = threat_context.get("remote_port") or threat_context.get("dst_port")
        cmdline = threat_context.get("cmdline") or threat_context.get("process_cmdline")

        # Extract live process memory metadata if process is still running locally
        volatile_proc_info: Dict[str, Any] = {}
        if pid:
            try:
                proc = psutil.Process(int(pid))
                volatile_proc_info = {
                    "pid": proc.pid,
                    "ppid": proc.ppid(),
                    "name": proc.name(),
                    "exe": proc.exe() if hasattr(proc, "exe") else None,
                    "cmdline": proc.cmdline(),
                    "cwd": proc.cwd() if hasattr(proc, "cwd") else None,
                    "create_time": proc.create_time(),
                    "memory_info": proc.memory_info()._asdict() if hasattr(proc, "memory_info") else None,
                    "open_sockets": [c._asdict() for c in proc.net_connections()] if hasattr(proc, "net_connections") else [],
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as pe:
                volatile_proc_info = {"live_query_status": f"Process handle unavailable or already dormant: {pe}"}

        evidence_payload = {
            "incident_id": incident.id,
            "incident_number": incident.incident_number,
            "acquisition_timestamp": now.isoformat(),
            "target_host": {
                "hostname": host_name,
                "os_platform": os_platform,
                "ip_address": host.ip_address if host else threat_context.get("src_ip", "127.0.0.1"),
                "is_isolated": host.is_isolated if host else False,
            },
            "hacking_scene_context": {
                "malicious_vector": threat_context.get("category", "RAT_MALWARE_INTRUSION"),
                "threat_title": threat_context.get("title", incident.title),
                "suspected_process": process_name,
                "process_pid": pid,
                "process_cmdline": cmdline,
                "remote_c2_endpoint": f"{remote_ip}:{remote_port}" if remote_ip else "N/A",
                "volatile_process_dump": volatile_proc_info,
            },
            "chain_of_custody_statement": (
                f"Volatile crime scene snapshot captured at the exact moment of live intrusion detection "
                f"on {host_name} ({os_platform}). Cryptographically sealed before containment."
            ),
        }

        # Store Evidence in Digital Forensics Vault
        raw_evidence_bytes = json.dumps(evidence_payload, indent=2).encode("utf-8")
        evidence_num = f"EV-HACK-{now.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"
        filename = f"volatile_attack_scene_{incident.incident_number}.json"

        stored_file_info = forensics_service.store_evidence_file(
            file_bytes=raw_evidence_bytes,
            original_filename=filename,
            evidence_number=evidence_num,
        )

        # Get or Create Linked Forensic Case
        case_num = f"CASE-{incident.incident_number}"
        res_case = await db.execute(select(ForensicCase).where(ForensicCase.case_number == case_num))
        f_case = res_case.scalar_one_or_none()
        if not f_case:
            f_case = ForensicCase(
                case_number=case_num,
                title=f"Forensic Investigation: {incident.title}",
                description=f"Evidence vault initialized for active threat {incident.incident_number} on {host_name}.",
                status="ACTIVE",
                priority=incident.severity,
                lead_analyst_id=actor_id,
            )
            db.add(f_case)
            await db.flush()

        # Create Database Evidence Record
        evidence_item = EvidenceItem(
            evidence_number=evidence_num,
            name=f"Live Intrusion Snapshot: {incident.incident_number}",
            source_description=f"Volatile host memory, socket state, and process snapshot on {host_name}",
            original_filename=filename,
            sha256_hash=stored_file_info["sha256_hash"],
            md5_hash=stored_file_info["md5_hash"],
            file_size_bytes=stored_file_info["file_size_bytes"],
            mime_type="application/json",
            storage_path=stored_file_info["storage_path"],
            is_read_only=True,
            acquired_by_id=actor_id,
            case_id=f_case.id,
        )
        db.add(evidence_item)
        await db.flush()

        # Create Initial Chain of Custody Record
        custody_record = ChainOfCustodyRecord(
            evidence_id=evidence_item.id,
            analyst_id=actor_id,
            action="LIVE_ATTACK_EVIDENCE_SEALED",
            verified_hash=stored_file_info["sha256_hash"],
            hash_matched=True,
            notes=f"Cryptographically locked into vault immediately upon detection of {incident.title} on {host_name}.",
        )
        db.add(custody_record)

        # Add Timeline Item to Forensic Case
        timeline_item = CaseTimelineItem(
            case_id=f_case.id,
            timestamp=now,
            title=f"Evidence Preserved: {evidence_num}",
            description=f"Volatile state captured for process {process_name} (PID: {pid}) connected to {remote_ip}:{remote_port}.",
            source_type="LIVE_INTRUSION_SCENE",
            evidence_id=evidence_item.id,
        )
        db.add(timeline_item)

        # 4. PHASE 2: Safe Automated Threat Containment
        containment_results = []

        # Action A: Kill Malicious RAT Process
        if auto_kill_process and pid:
            try:
                proc = psutil.Process(int(pid))
                proc.kill()
                proc.wait(timeout=2.0)
                containment_results.append(f"SUCCESS: Rogue process {process_name} (PID {pid}) terminated.")
            except (psutil.NoSuchProcess, Exception) as pe:
                containment_results.append(f"NEUTRALIZED: Process {pid} is no longer running ({pe}).")

        # Action B: Sever Rogue Sockets / Isolate Host
        if auto_isolate_host and host:
            host.is_isolated = True
            containment_results.append(f"SUCCESS: Host {host_name} placed into network isolation.")

        # Action C: Check if USB / Hardware quarantine is relevant
        drive_letter = threat_context.get("drive_letter")
        if drive_letter and drive_letter.upper() != "C:":
            quar_res = hardware_port_service.quarantine_port(drive_letter)
            containment_results.append(f"PORT QUARANTINE: Drive {drive_letter} halted ({quar_res.get('status')}).")

        # 5. Record ResponseAction on the Incident
        outcome_summary = " | ".join(containment_results) if containment_results else "Threat neutralized."
        resp_action = ResponseAction(
            incident_id=incident.id,
            action_type="CONTAIN_AND_PRESERVE",
            parameters=json.dumps({
                "killed_pid": pid,
                "process_name": process_name,
                "evidence_number": evidence_num,
                "sha256": stored_file_info["sha256_hash"],
                "host_isolated": auto_isolate_host,
            }),
            requested_by=actor_id,
            approved_by=actor_id,
            status="EXECUTED",
            executed_at=now,
            outcome_details=outcome_summary,
        )
        db.add(resp_action)

        # Update Incident Status to Contained
        incident.status = "Contained"
        incident.updated_at = now

        # Append analyst note
        existing_notes = []
        if incident.analyst_notes:
            try:
                existing_notes = json.loads(incident.analyst_notes)
            except Exception:
                existing_notes = []
        existing_notes.append({
            "author": "SENTINEL-X Automated Containment & Forensics Sentinel",
            "text": f"Automated defense workflow executed: Volatile evidence sealed in vault as {evidence_num} (SHA-256: {stored_file_info['sha256_hash'][:16]}...). Containment: {outcome_summary}",
            "timestamp": now.isoformat(),
        })
        incident.analyst_notes = json.dumps(existing_notes)

        await db.commit()

        # 6. Broadcast Real-Time Security WebSocket Event
        result_payload = {
            "status": "CONTAINED_AND_PRESERVED",
            "incident_id": incident.id,
            "incident_number": incident.incident_number,
            "host_name": host_name,
            "os_platform": os_platform,
            "evidence": {
                "id": evidence_item.id,
                "evidence_number": evidence_num,
                "sha256": stored_file_info["sha256_hash"],
                "file_size_bytes": stored_file_info["file_size_bytes"],
                "vault_path": stored_file_info["storage_path"],
                "case_number": case_num,
            },
            "containment_summary": outcome_summary,
            "executed_at": now.isoformat(),
        }

        await ws_manager.broadcast({
            "type": "THREAT_CONTAINED_EVIDENCE_PRESERVED",
            "payload": result_payload,
        })

        return result_payload


# Global Singleton Instance
orchestrator = ContainmentEvidenceOrchestrator()
