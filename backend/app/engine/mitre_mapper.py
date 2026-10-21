import json
from pathlib import Path
from typing import Optional, Dict, Any
from backend.app.config import RULES_DIR


class MitreAttackMapper:
    """
    Verified MITRE ATT&CK Mapping Engine.
    Ensures that only authentic, documented MITRE techniques and tactics are associated with detections.
    """

    def __init__(self, catalog_path: Optional[Path] = None):
        self.catalog_path = catalog_path or (RULES_DIR / "mitre_attack.json")
        self._techniques: Dict[str, Dict[str, Any]] = {}
        self.load_catalog()

    def load_catalog(self) -> None:
        """Loads and indexes the ATT&CK techniques."""
        if not self.catalog_path.exists():
            return
        try:
            with open(self.catalog_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self._techniques = data.get("techniques", {})
        except Exception:
            self._techniques = {}

    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Look up verified technique information by ID (e.g., 'T1110.001')."""
        return self._techniques.get(technique_id)

    def validate_mapping(self, technique_id: str, tactic: Optional[str] = None) -> bool:
        """Validates that a technique exists and matches the tactic."""
        tech = self.get_technique(technique_id)
        if not tech:
            return False
        if tactic and tech.get("tactic", "").lower() != tactic.lower():
            return False
        return True

    def enrich_rule(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enriches rule dictionary with verified ATT&CK technique details."""
        tech_id = rule_data.get("mitre_technique_id")
        if tech_id and tech_id in self._techniques:
            tech = self._techniques[tech_id]
            rule_data["mitre_technique_name"] = tech.get("technique_name")
            rule_data["mitre_tactic"] = tech.get("tactic")
        return rule_data


mitre_mapper = MitreAttackMapper()
