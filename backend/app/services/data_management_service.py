"""
SENTINEL-X Data Management & Universal Storage Purge Service
Provides database row statistics, granular record deletion, and domain-specific
or system-wide operational data purging with cascading foreign key cleanup.
"""
from typing import Dict, Any, List
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, func

from backend.app.models.event import NormalizedEvent
from backend.app.models.incident import Incident, IncidentEventLink, ResponseAction
from backend.app.models.host import Host, CollectorHealth
from backend.app.models.evidence import EvidenceItem, ChainOfCustodyRecord
from backend.app.models.forensic import ForensicCase, CaseTimelineItem, ForensicNote
from backend.app.models.malware import MalwareSample, StaticAnalysisResult
from backend.app.models.network import NetworkObservation
from backend.app.models.assessment import AssessmentProject, TargetScope, VulnerabilityFinding
from backend.app.models.report import SecurityReport, AuditLog

logger = logging.getLogger(__name__)


class DataManagementService:
    """Manages table metrics, individual deletions, and complete category purges."""

    async def get_storage_statistics(self, db: AsyncSession) -> Dict[str, Any]:
        """Returns row counts for all core operational data tables."""
        stats = {}
        tables = [
            ("events", NormalizedEvent),
            ("incidents", Incident),
            ("incident_links", IncidentEventLink),
            ("hosts", Host),
            ("collector_health", CollectorHealth),
            ("evidence_items", EvidenceItem),
            ("chain_of_custody", ChainOfCustodyRecord),
            ("forensic_cases", ForensicCase),
            ("malware_samples", MalwareSample),
            ("network_observations", NetworkObservation),
            ("assessment_projects", AssessmentProject),
            ("target_scopes", TargetScope),
            ("vulnerabilities", VulnerabilityFinding),
            ("security_reports", SecurityReport),
            ("audit_logs", AuditLog),
        ]

        total_records = 0
        for name, model in tables:
            stmt = select(func.count()).select_from(model)
            count = (await db.execute(stmt)).scalar() or 0
            stats[name] = count
            total_records += count

        stats["total_records"] = total_records
        return stats

    async def delete_event(self, db: AsyncSession, event_id: str) -> bool:
        """Deletes a specific normalized event and any incident links."""
        res_ev = await db.execute(select(NormalizedEvent).where(
            (NormalizedEvent.id == event_id) | (NormalizedEvent.event_id == event_id)
        ))
        ev = res_ev.scalar_one_or_none()
        if not ev:
            return False
        await db.execute(delete(IncidentEventLink).where(IncidentEventLink.event_id == ev.id))
        await db.delete(ev)
        await db.commit()
        return True

    async def delete_incident(self, db: AsyncSession, incident_id: str) -> bool:
        """Deletes an incident, associated event links, and response actions."""
        res_inc = await db.execute(select(Incident).where(
            (Incident.id == incident_id) | (Incident.incident_number == incident_id)
        ))
        inc = res_inc.scalar_one_or_none()
        if not inc:
            return False
        await db.execute(delete(IncidentEventLink).where(IncidentEventLink.incident_id == inc.id))
        await db.execute(delete(ResponseAction).where(ResponseAction.incident_id == inc.id))
        await db.delete(inc)
        await db.commit()
        return True

    async def delete_host(self, db: AsyncSession, host_id: str) -> bool:
        """Deletes a host and its collector health records."""
        res_host = await db.execute(select(Host).where(
            (Host.id == host_id) | (Host.hostname == host_id)
        ))
        host = res_host.scalar_one_or_none()
        if not host:
            return False
        await db.execute(delete(CollectorHealth).where(CollectorHealth.host_id == host.id))
        await db.delete(host)
        await db.commit()
        return True

    async def delete_forensic_case(self, db: AsyncSession, case_id: str) -> bool:
        """Deletes a forensic case, timeline items, and notes."""
        res_case = await db.execute(select(ForensicCase).where(
            (ForensicCase.id == case_id) | (ForensicCase.case_number == case_id)
        ))
        fc = res_case.scalar_one_or_none()
        if not fc:
            return False
        await db.execute(delete(CaseTimelineItem).where(CaseTimelineItem.case_id == fc.id))
        await db.execute(delete(ForensicNote).where(ForensicNote.case_id == fc.id))
        await db.delete(fc)
        await db.commit()
        return True

    async def delete_evidence_item(self, db: AsyncSession, evidence_id: str) -> bool:
        """Deletes an evidence item and its custody records."""
        res_ev = await db.execute(select(EvidenceItem).where(
            (EvidenceItem.id == evidence_id) | (EvidenceItem.evidence_number == evidence_id)
        ))
        item = res_ev.scalar_one_or_none()
        if not item:
            return False
        await db.execute(delete(ChainOfCustodyRecord).where(ChainOfCustodyRecord.evidence_id == item.id))
        await db.delete(item)
        await db.commit()
        return True

    async def delete_malware_sample(self, db: AsyncSession, sample_id: str) -> bool:
        """Deletes a malware sample and static analysis result."""
        res_s = await db.execute(select(MalwareSample).where(
            (MalwareSample.id == sample_id) | (MalwareSample.sha256 == sample_id)
        ))
        sample = res_s.scalar_one_or_none()
        if not sample:
            return False
        await db.execute(delete(StaticAnalysisResult).where(StaticAnalysisResult.sample_id == sample.id))
        await db.delete(sample)
        await db.commit()
        return True

    async def delete_report(self, db: AsyncSession, report_id: str) -> bool:
        """Deletes a security report."""
        res_r = await db.execute(select(SecurityReport).where(
            (SecurityReport.id == report_id) | (SecurityReport.report_id == report_id)
        ))
        rep = res_r.scalar_one_or_none()
        if not rep:
            return False
        await db.delete(rep)
        await db.commit()
        return True

    async def purge_category(self, db: AsyncSession, category: str) -> Dict[str, Any]:
        """
        Purges data by specific category or all operational data.
        Categories: 'events', 'incidents', 'hosts', 'evidence', 'forensics',
                    'malware', 'network', 'assessments', 'reports', 'audit', 'all'
        """
        cat = category.strip().lower()
        deleted_counts = {}

        if cat in ("events", "all"):
            await db.execute(delete(IncidentEventLink))
            res = await db.execute(delete(NormalizedEvent))
            deleted_counts["events"] = res.rowcount

        if cat in ("incidents", "all"):
            await db.execute(delete(IncidentEventLink))
            await db.execute(delete(ResponseAction))
            res = await db.execute(delete(Incident))
            deleted_counts["incidents"] = res.rowcount

        if cat in ("hosts", "all"):
            await db.execute(delete(CollectorHealth))
            res = await db.execute(delete(Host))
            deleted_counts["hosts"] = res.rowcount

        if cat in ("evidence", "all"):
            await db.execute(delete(ChainOfCustodyRecord))
            res = await db.execute(delete(EvidenceItem))
            deleted_counts["evidence"] = res.rowcount

        if cat in ("forensics", "all"):
            await db.execute(delete(CaseTimelineItem))
            await db.execute(delete(ForensicNote))
            res = await db.execute(delete(ForensicCase))
            deleted_counts["forensic_cases"] = res.rowcount

        if cat in ("malware", "all"):
            await db.execute(delete(StaticAnalysisResult))
            res = await db.execute(delete(MalwareSample))
            deleted_counts["malware_samples"] = res.rowcount

        if cat in ("network", "all"):
            res = await db.execute(delete(NetworkObservation))
            deleted_counts["network"] = res.rowcount

        if cat in ("assessments", "all"):
            await db.execute(delete(VulnerabilityFinding))
            await db.execute(delete(TargetScope))
            res = await db.execute(delete(AssessmentProject))
            deleted_counts["assessments"] = res.rowcount

        if cat in ("reports", "all"):
            res = await db.execute(delete(SecurityReport))
            deleted_counts["reports"] = res.rowcount

        if cat in ("audit", "all"):
            res = await db.execute(delete(AuditLog))
            deleted_counts["audit_logs"] = res.rowcount

        await db.commit()
        logger.info(f"Purged category '{cat}': {deleted_counts}")
        return {
            "category": cat,
            "success": True,
            "deleted_records": deleted_counts,
            "total_deleted": sum(deleted_counts.values()),
        }


data_management_service = DataManagementService()
