import json
import yaml
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from backend.app.config import RULES_DIR
from backend.app.engine.mitre_mapper import mitre_mapper


class DetectionRulesEngine:
    """
    Deterministic Sliding-Window Correlation & Detection Engine.
    Evaluates normalized events against YAML detection rules and correlates incidents.
    """

    def __init__(self, rules_file: Optional[Path] = None):
        self.rules_file = rules_file or (RULES_DIR / "default_rules.yaml")
        self.rules: List[Dict[str, Any]] = []
        # Event buffer for sliding window evaluation: (host_id, rule_id) -> list of (event_timestamp, event_dict)
        self._sliding_buffers: Dict[Tuple[str, str], List[Tuple[datetime, Dict[str, Any]]]] = {}
        self.load_rules()

    def load_rules(self) -> None:
        """Loads and parses detection rules from the YAML configuration."""
        if not self.rules_file.exists():
            return
        try:
            with open(self.rules_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                raw_rules = data.get("rules", [])
                self.rules = []
                for r in raw_rules:
                    if r.get("is_active", True):
                        enriched = mitre_mapper.enrich_rule(r)
                        self.rules.append(enriched)
        except Exception as e:
            self.rules = []

    def _event_matches_filter(self, event: Dict[str, Any], filter_criteria: Dict[str, Any]) -> bool:
        """
        Evaluates event attributes against rule filter criteria.
        """
        if not filter_criteria:
            return True

        for key, expected in filter_criteria.items():
            if key == "process_name":
                proc = event.get("process_name")
                if not proc or str(expected).lower() not in proc.lower():
                    return False
            elif key == "account_uid":
                if event.get("account_uid") != expected:
                    return False
            elif key == "account_user":
                if event.get("account_user") != expected:
                    return False
            elif key == "file_path_patterns":
                file_path = event.get("file_path")
                if not file_path:
                    return False
                if not any(pattern in file_path for pattern in expected):
                    return False
            elif key == "is_outbound":
                raw_p = event.get("raw_payload", "{}")
                if isinstance(raw_p, str):
                    try:
                        raw_dict = json.loads(raw_p)
                    except Exception:
                        raw_dict = {}
                else:
                    raw_dict = raw_p
                if raw_dict.get("is_outbound") != expected:
                    return False
            elif key == "status":
                raw_p = event.get("raw_payload", "{}")
                if isinstance(raw_p, str):
                    try:
                        raw_dict = json.loads(raw_p)
                    except Exception:
                        raw_dict = {}
                else:
                    raw_dict = raw_p
                if raw_dict.get("status") != expected:
                    return False

        return True

    def process_event(
        self, host_id: str, event: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Evaluates a normalized event against all active detection rules.
        Returns a list of triggered incident specifications if correlation threshold is met.
        """
        triggered_incidents = []
        event_time = event["timestamp"]
        category = event["event_category"]

        for rule in self.rules:
            # 1. Check category match
            if rule["event_category"] != category:
                continue

            # 2. Check filter criteria
            filter_criteria = rule.get("filter_criteria", {})
            if isinstance(filter_criteria, str):
                try:
                    filter_criteria = json.loads(filter_criteria)
                except Exception:
                    filter_criteria = {}

            if not self._event_matches_filter(event, filter_criteria):
                continue

            # 3. Sliding window correlation buffer
            key = (host_id, rule["rule_id"])
            if key not in self._sliding_buffers:
                self._sliding_buffers[key] = []

            buffer = self._sliding_buffers[key]
            # Add current event
            buffer.append((event_time, event))

            # Prune events older than sliding window
            cutoff = event_time - timedelta(seconds=rule["window_seconds"])
            self._sliding_buffers[key] = [
                (t, ev) for (t, ev) in buffer if t >= cutoff
            ]
            current_count = len(self._sliding_buffers[key])

            # 4. Threshold check
            if current_count >= rule["threshold"]:
                correlated_events = [ev for (_, ev) in self._sliding_buffers[key]]
                
                # Build incident payload
                incident_title = f"{rule['name']} on host {host_id[:8]}"
                if event.get("account_user"):
                    incident_title += f" (user: {event['account_user']})"

                incident_spec = {
                    "rule_id": rule["rule_id"],
                    "rule_name": rule["name"],
                    "rule_version": rule.get("version", "1.0.0"),
                    "title": incident_title,
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "base_confidence": rule.get("base_confidence", 0.85),
                    "mitre_technique_id": rule.get("mitre_technique_id"),
                    "mitre_tactic": rule.get("mitre_tactic"),
                    "host_id": host_id,
                    "affected_account": event.get("account_user") or event.get("target_user"),
                    "event_ids": [ev["event_id"] for ev in correlated_events],
                    "matched_events": correlated_events,
                    "window_seconds": rule["window_seconds"],
                    "threshold": rule["threshold"],
                }
                triggered_incidents.append(incident_spec)

        return triggered_incidents


rules_engine = DetectionRulesEngine()
