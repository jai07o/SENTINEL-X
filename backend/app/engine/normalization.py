import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple
from backend.app.schemas.event import RawEventIngest


class EventNormalizer:
    """
    Production Event Normalization & Deduplication Pipeline.
    Harmonizes multi-distribution syslog, journald, auth, and network logs.
    """

    SUPPORTED_CATEGORIES = {
        "AUTH_SUCCESS",
        "AUTH_FAILURE",
        "AUTH_ANOMALY",
        "PROCESS_SPAWN",
        "PRIVILEGE_ESCALATION",
        "FILE_MODIFICATION",
        "SERVICE_CHANGE",
        "SCHEDULED_TASK_CHANGE",
        "NETWORK_OUTBOUND_UNUSUAL",
        "SECURITY_SERVICE_FAILURE",
    }

    SEVERITY_LEVELS = {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def __init__(self, dedup_window_seconds: int = 30):
        self.dedup_window_seconds = dedup_window_seconds
        # In-memory LRU fingerprint cache for fast suppression: hash -> timestamp
        self._seen_fingerprints: Dict[str, float] = {}

    @staticmethod
    def parse_timestamp(ts_input: Any) -> datetime:
        """
        Robustly parses ISO-8601 strings, UNIX epoch timestamps, or datetime objects.
        Always returns a timezone-naive UTC datetime object for database consistency.
        """
        if isinstance(ts_input, datetime):
            if ts_input.tzinfo is not None:
                return ts_input.astimezone(timezone.utc).replace(tzinfo=None)
            return ts_input

        if isinstance(ts_input, (int, float)):
            return datetime.utcfromtimestamp(ts_input)

        if isinstance(ts_input, str):
            ts_cleaned = ts_input.strip()
            # Try ISO formats
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%b %d %H:%M:%S",  # Syslog standard (e.g., Oct 21 14:02:11)
            ):
                try:
                    dt = datetime.strptime(ts_cleaned, fmt)
                    if "%b" in fmt:  # If syslog without year, assume current year
                        dt = dt.replace(year=datetime.utcnow().year)
                    return dt
                except ValueError:
                    continue

        # Fallback to current UTC time if unparseable
        return datetime.utcnow()

    @staticmethod
    def compute_evidence_hash(payload: Dict[str, Any]) -> str:
        """Computes deterministic SHA-256 fingerprint over sorted raw payload."""
        canonical_str = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def is_duplicate(self, fingerprint: str, event_time: datetime) -> bool:
        """
        Suppresses identical duplicate alerts within the sliding dedup window.
        """
        now_ts = event_time.timestamp()
        
        # Housekeeping: prune old entries (> 2x dedup window)
        to_prune = [k for k, v in self._seen_fingerprints.items() if (now_ts - v) > (self.dedup_window_seconds * 2)]
        for k in to_prune:
            del self._seen_fingerprints[k]

        if fingerprint in self._seen_fingerprints:
            last_seen = self._seen_fingerprints[fingerprint]
            if (now_ts - last_seen) <= self.dedup_window_seconds:
                return True

        self._seen_fingerprints[fingerprint] = now_ts
        return False

    def normalize(self, raw: RawEventIngest) -> Tuple[Dict[str, Any], bool]:
        """
        Validates, normalizes, and checks deduplication for an incoming telemetry event.
        Returns: (normalized_dict, is_duplicate_flag)
        """
        event_time = self.parse_timestamp(raw.timestamp) if raw.timestamp else datetime.utcnow()
        raw_payload_dict = raw.raw_payload if raw.raw_payload else {}
        evidence_hash = self.compute_evidence_hash(raw_payload_dict)

        # Generate unique event_id if not supplied by agent
        event_id = raw.event_id or f"evt_{evidence_hash[:16]}_{int(event_time.timestamp())}"

        # Category normalization
        category = raw.event_category.upper().strip()
        if category not in self.SUPPORTED_CATEGORIES:
            category = "AUTH_ANOMALY" if "AUTH" in category else "PROCESS_SPAWN"

        # Severity normalization
        severity = (raw.severity or "INFORMATIONAL").upper().strip()
        if severity not in self.SEVERITY_LEVELS:
            severity = "INFORMATIONAL"

        # Duplicate check
        dup_flag = self.is_duplicate(evidence_hash, event_time)

        normalized = {
            "event_id": event_id,
            "timestamp": event_time,
            "source": raw.source.strip().lower(),
            "event_category": category,
            "severity": severity,
            "account_user": raw.account_user.strip() if raw.account_user else None,
            "account_uid": raw.account_uid,
            "target_user": raw.target_user.strip() if raw.target_user else None,
            "process_name": raw.process_name.strip() if raw.process_name else None,
            "process_pid": raw.process_pid,
            "process_parent_pid": raw.process_parent_pid,
            "process_cmdline": raw.process_cmdline.strip() if raw.process_cmdline else None,
            "file_path": raw.file_path.strip() if raw.file_path else None,
            "file_sha256": raw.file_sha256.strip().lower() if raw.file_sha256 else None,
            "src_ip": raw.src_ip.strip() if raw.src_ip else None,
            "src_port": raw.src_port,
            "dst_ip": raw.dst_ip.strip() if raw.dst_ip else None,
            "dst_port": raw.dst_port,
            "evidence_hash": evidence_hash,
            "raw_payload": json.dumps(raw_payload_dict, default=str),
        }

        return normalized, dup_flag


# Global singleton instance for easy engine/simulator pipeline usage
normalizer = EventNormalizer()
