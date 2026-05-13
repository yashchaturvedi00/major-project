"""
Attack analyzer — maps predicted attack types to MITRE ATT&CK techniques
and provides enriched threat intelligence from the knowledge base.
"""
import os
import joblib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Lazy-loaded globals
_attack_to_mitre = None
_mitre_kb = None


def _load_mappings():
    """Lazy-load MITRE mapping files."""
    global _attack_to_mitre, _mitre_kb

    if _attack_to_mitre is None:
        map_path = PROJECT_ROOT / "attack_to_mitre_map.pkl"
        kb_path = PROJECT_ROOT / "mitre_kb.pkl"

        if map_path.exists():
            _attack_to_mitre = joblib.load(str(map_path))
        else:
            _attack_to_mitre = {}

        if kb_path.exists():
            _mitre_kb = joblib.load(str(kb_path))
        else:
            _mitre_kb = {}

    return _attack_to_mitre, _mitre_kb


def analyze_attack(attack_type, detection_time=0.0):
    """
    Analyze a predicted attack type and return enriched MITRE ATT&CK info.

    Args:
        attack_type: String name of the predicted attack type
        detection_time: Time taken for detection in seconds

    Returns:
        dict with technique info, impact, mitigations, etc.
    """
    attack_to_mitre, mitre_kb = _load_mappings()

    # Map attack type to MITRE technique
    technique_id = attack_to_mitre.get(str(attack_type), None)

    if technique_id is None:
        return {
            "Technique ID": "Unknown",
            "Attack Type": str(attack_type),
            "Message": "No MITRE mapping found for this attack type",
            "Detection Time (s)": detection_time,
        }

    # Look up knowledge base
    info = mitre_kb.get(technique_id, None)

    if info is None:
        return {
            "Technique ID": technique_id,
            "Attack Type": str(attack_type),
            "Message": "Technique not documented in knowledge base",
            "Detection Time (s)": detection_time,
        }

    return {
        "Technique ID": technique_id,
        "Technique Name": info.get("name", "Unknown"),
        "Attack Type": str(attack_type),
        "Category": info.get("category", "Unknown"),
        "Description": info.get("description", "No description"),
        "Impact": info.get("impact", "Unknown"),
        "Mitigation": info.get("mitigation", "No mitigation available"),
        "Detection Method": info.get("detection_method", ""),
        "Detection Time (s)": detection_time,
    }
