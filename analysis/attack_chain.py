"""
Attack Chain Reconstruction Engine.

Links individual detections (from document scanner and/or network IDS)
into a MITRE ATT&CK kill chain narrative, showing how an attacker
progresses through tactics.
"""
from datetime import datetime
from collections import defaultdict


# ── MITRE ATT&CK Tactics (Kill Chain Order) ─────────────────
TACTIC_ORDER = [
    ("Reconnaissance",          1, "🔍"),
    ("Resource Development",    2, "🔧"),
    ("Initial Access",          3, "🚪"),
    ("Execution",               4, "⚡"),
    ("Persistence",             5, "📌"),
    ("Privilege Escalation",    6, "⬆️"),
    ("Defense Evasion",         7, "🛡️"),
    ("Credential Access",       8, "🔑"),
    ("Discovery",               9, "🔭"),
    ("Lateral Movement",       10, "↔️"),
    ("Collection",             11, "📦"),
    ("Command and Control",    12, "📡"),
    ("Exfiltration",           13, "📤"),
    ("Impact",                 14, "💥"),
]

TACTIC_NAMES = [t[0] for t in TACTIC_ORDER]
TACTIC_STAGE = {t[0]: t[1] for t in TACTIC_ORDER}
TACTIC_ICON = {t[0]: t[2] for t in TACTIC_ORDER}

# Maps technique ID → tactic name
TECHNIQUE_TO_TACTIC = {
    # Document scanner techniques
    "T1566": "Initial Access",
    "T1059": "Execution",
    "T1036": "Defense Evasion",
    "T1003": "Credential Access",
    "T1110": "Credential Access",
    "T1056": "Collection",
    "T1078": "Persistence",
    "T1499": "Impact",
    # Network IDS techniques
    "T1190": "Initial Access",
    "T1046": "Discovery",
    "T1210": "Lateral Movement",
    "T1071": "Command and Control",
    "T1595": "Reconnaissance",
    "T1570": "Lateral Movement",
}


class AttackChainBuilder:
    """
    Collects detection events and reconstructs them into a
    MITRE ATT&CK kill chain progression.
    """

    def __init__(self):
        self.detections = []

    def add_detection(self, detection):
        """
        Add a detection event.

        Args:
            detection: dict with at minimum:
                - attack_type (str)
                - mitre_id (str)
                - confidence (float)
                - source_type (str): "document" or "network"
                - timestamp (str, optional)
                - file_name or flow info (optional)
        """
        # Determine tactic from MITRE ID
        mitre_id = detection.get("mitre_id", "N/A")
        tactic = TECHNIQUE_TO_TACTIC.get(mitre_id, "Unknown")

        enriched = {
            **detection,
            "tactic": tactic,
            "tactic_stage": TACTIC_STAGE.get(tactic, 99),
            "tactic_icon": TACTIC_ICON.get(tactic, "❓"),
            "timestamp": detection.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        }
        self.detections.append(enriched)

    def add_detections(self, detections):
        """Add multiple detection events at once."""
        for det in detections:
            self.add_detection(det)

    def build_chain(self):
        """
        Return detections sorted by kill chain stage order.

        Returns:
            List of detection dicts, ordered by tactic_stage (ascending).
        """
        return sorted(self.detections, key=lambda d: d["tactic_stage"])

    def get_chain_by_tactic(self):
        """
        Group detections by tactic.

        Returns:
            Dict mapping tactic name → list of detections in that tactic.
            Only includes tactics that have at least one detection.
        """
        groups = defaultdict(list)
        for det in self.detections:
            groups[det["tactic"]].append(det)

        # Return in kill chain order
        ordered = {}
        for tactic_name, _, _ in TACTIC_ORDER:
            if tactic_name in groups:
                ordered[tactic_name] = groups[tactic_name]

        return ordered

    def get_active_tactics(self):
        """Return set of tactic names that have detections."""
        return {d["tactic"] for d in self.detections if d["tactic"] != "Unknown"}

    def get_chain_coverage(self):
        """
        Calculate what percentage of the kill chain has been triggered.

        Returns:
            Float between 0.0 and 100.0
        """
        active = self.get_active_tactics()
        total_tactics = len(TACTIC_NAMES)
        return round(len(active) / total_tactics * 100, 1)

    def get_chain_summary(self):
        """
        Generate a human-readable narrative of the attack chain.

        Returns:
            String like "Attack progressed: Initial Access (Phishing T1566)
            → Execution (Command Interpreter T1059) → Impact (DDoS T1499)"
        """
        if not self.detections:
            return "No detections recorded."

        chain = self.get_chain_by_tactic()
        if not chain:
            return "No detections could be mapped to MITRE tactics."

        parts = []
        for tactic, detections in chain.items():
            icon = TACTIC_ICON.get(tactic, "")
            # Pick the highest confidence detection in this tactic
            best = max(detections, key=lambda d: d.get("confidence", 0))
            technique = f"{best['attack_type']} ({best.get('mitre_id', 'N/A')})"
            parts.append(f"{icon} {tactic}: {technique}")

        summary = " → ".join(parts)
        coverage = self.get_chain_coverage()

        return f"Attack chain ({coverage}% coverage): {summary}"

    def get_timeline(self):
        """
        Return detections as a timeline sorted by timestamp.

        Returns:
            List of dicts with timestamp, tactic, attack_type, source_type, etc.
        """
        return sorted(self.detections, key=lambda d: d.get("timestamp", ""))

    def get_stats(self):
        """
        Return summary statistics about the detection chain.
        """
        if not self.detections:
            return {
                "total_detections": 0,
                "active_tactics": 0,
                "chain_coverage": 0.0,
                "document_detections": 0,
                "network_detections": 0,
                "highest_severity": "None",
            }

        severities = [d.get("severity", "Low") for d in self.detections]
        severity_rank = {"High": 3, "Medium": 2, "Low": 1, "None": 0}
        highest = max(severities, key=lambda s: severity_rank.get(s, 0))

        return {
            "total_detections": len(self.detections),
            "active_tactics": len(self.get_active_tactics()),
            "chain_coverage": self.get_chain_coverage(),
            "document_detections": sum(1 for d in self.detections if d.get("source_type") == "document"),
            "network_detections": sum(1 for d in self.detections if d.get("source_type") == "network"),
            "highest_severity": highest,
        }

    def clear(self):
        """Clear all detections."""
        self.detections = []
