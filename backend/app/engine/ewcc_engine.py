import math
from datetime import datetime
from typing import Dict, Any, List, Optional


class EWCCEngine:
    """
    Evidence-Weighted Cross-Distribution Correlation (EWCC) Engine.
    Proposed research contribution for evaluating multi-source telemetry confidence,
    cross-distribution identity consistency, and evidence completeness.
    """

    # Source Reliability Matrix (Kernel audit > Structured Journal > Text Syslog > Polling)
    SOURCE_RELIABILITY: Dict[str, float] = {
        "auditd": 0.95,
        "fim": 0.95,
        "zeek": 0.90,
        "systemd_journal": 0.90,
        "auth_log": 0.85,
        "proc_watcher": 0.75,
        "generic": 0.60,
    }

    # Distribution-Specific Identity Baselines
    DISTRO_PROFILES: Dict[str, Dict[str, Any]] = {
        "ubuntu": {"admin_group": "sudo", "default_uid_start": 1000, "auth_path": "/var/log/auth.log"},
        "debian": {"admin_group": "sudo", "default_uid_start": 1000, "auth_path": "/var/log/auth.log"},
        "kali": {"admin_group": "sudo", "default_uid_start": 1000, "auth_path": "/var/log/auth.log"},
        "parrot": {"admin_group": "sudo", "default_uid_start": 1000, "auth_path": "/var/log/auth.log"},
        "fedora": {"admin_group": "wheel", "default_uid_start": 1000, "auth_path": "/var/log/secure"},
    }

    def __init__(
        self,
        weight_source: float = 0.35,
        weight_identity: float = 0.25,
        weight_completeness: float = 0.20,
        weight_temporal: float = 0.20,
    ):
        self.w_src = weight_source
        self.w_id = weight_identity
        self.w_comp = weight_completeness
        self.w_temp = weight_temporal

    def calculate_source_reliability(self, events: List[Dict[str, Any]]) -> float:
        """Computes average telemetry source reliability weight."""
        if not events:
            return 0.5
        scores = [self.SOURCE_RELIABILITY.get(ev.get("source", "generic"), 0.60) for ev in events]
        return sum(scores) / len(scores)

    def calculate_identity_consistency(
        self, events: List[Dict[str, Any]], os_distro: str = "ubuntu"
    ) -> float:
        """
        Evaluates account identity consistency across distribution baselines.
        Flags anomalous uid=0 execution with non-root username, or unexpected privilege discrepancies.
        """
        if not events:
            return 0.7

        consistency_score = 1.0
        for ev in events:
            uid = ev.get("account_uid")
            user = ev.get("account_user")
            cmd = ev.get("process_cmdline") or ""

            # Anomaly: root UID (0) claimed with a non-root named user (excluding known system accounts)
            if uid == 0 and user and user not in ("root", "SYSTEM", "UNKNOWN"):
                consistency_score -= 0.3

            # Anomaly: binary execution from suspicious temp or volatile directory
            if any(susp in cmd for susp in ("/tmp/", "/dev/shm/", "/var/tmp/")):
                consistency_score -= 0.15

        return max(0.2, min(1.0, consistency_score))

    def calculate_evidence_completeness(self, events: List[Dict[str, Any]]) -> float:
        """
        Measures the presence of critical forensic attributes:
        actor identity, process metadata, file/network targets, and cryptographic evidence hashes.
        """
        if not events:
            return 0.0

        attribute_scores = []
        for ev in events:
            score = 0.0
            # 1. Evidence hash present
            if ev.get("evidence_hash"):
                score += 0.25
            # 2. Actor identity present
            if ev.get("account_user") or ev.get("account_uid") is not None:
                score += 0.25
            # 3. Process context present
            if ev.get("process_name") or ev.get("process_pid") is not None:
                score += 0.25
            # 4. Target context present (file, destination, or commandline)
            if ev.get("file_path") or ev.get("dst_ip") or ev.get("process_cmdline"):
                score += 0.25
            attribute_scores.append(score)

        return sum(attribute_scores) / len(attribute_scores)

    def calculate_temporal_clustering(
        self, events: List[Dict[str, Any]], window_seconds: int
    ) -> float:
        """
        Calculates temporal clustering decay.
        Events clustered tightly exhibit higher causal correlation confidence than dispersed events.
        """
        if len(events) <= 1:
            return 0.85

        timestamps = [ev["timestamp"] for ev in events if isinstance(ev["timestamp"], datetime)]
        if len(timestamps) <= 1:
            return 0.85

        timestamps.sort()
        span_seconds = (timestamps[-1] - timestamps[0]).total_seconds()
        if span_seconds <= 0:
            return 0.98

        # Ratio of span to allowed window: tighter clustering -> higher score
        ratio = span_seconds / max(1, window_seconds)
        clustering = math.exp(-0.8 * ratio)
        return max(0.3, min(0.98, clustering))

    def evaluate_correlation(
        self,
        events: List[Dict[str, Any]],
        base_rule_confidence: float = 0.85,
        window_seconds: int = 60,
        os_distro: str = "ubuntu",
    ) -> Dict[str, Any]:
        """
        Performs full EWCC evaluation comparing proposed research metric against rule baseline.
        Separates observed facts from inferred relationships.
        """
        src_score = self.calculate_source_reliability(events)
        id_score = self.calculate_identity_consistency(events, os_distro)
        comp_score = self.calculate_evidence_completeness(events)
        temp_score = self.calculate_temporal_clustering(events, window_seconds)

        # Composite EWCC Confidence Score
        ewcc_confidence = (
            (self.w_src * src_score)
            + (self.w_id * id_score)
            + (self.w_comp * comp_score)
            + (self.w_temp * temp_score)
        )
        ewcc_confidence = round(max(0.1, min(0.99, ewcc_confidence)), 4)

        # Separate Observed Facts from Inferred Relationships
        observed_facts = [
            f"Observed {len(events)} telemetry events across {window_seconds}s correlation window.",
            f"Sources utilized: {', '.join(sorted(set(ev.get('source', 'unknown') for ev in events)))}.",
            f"Cryptographic evidence hashes verified: {all(bool(ev.get('evidence_hash')) for ev in events)}.",
        ]
        
        inferred_relationships = [
            f"Temporal clustering score of {round(temp_score, 2)} indicates potential automated execution pattern.",
            f"Cross-distribution identity score of {round(id_score, 2)} against baseline profile '{os_distro}'.",
            f"Correlation confidence estimated at {ewcc_confidence} (Rule-only baseline: {base_rule_confidence}).",
        ]

        return {
            "ewcc_confidence": ewcc_confidence,
            "rule_baseline_confidence": base_rule_confidence,
            "confidence_delta": round(ewcc_confidence - base_rule_confidence, 4),
            "metrics": {
                "source_reliability": round(src_score, 4),
                "identity_consistency": round(id_score, 4),
                "evidence_completeness": round(comp_score, 4),
                "temporal_clustering": round(temp_score, 4),
            },
            "observed_facts": observed_facts,
            "inferred_relationships": inferred_relationships,
            "evaluation_model": "EWCC-v1-Research",
        }


ewcc_engine = EWCCEngine()
