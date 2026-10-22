"""
adaptive_engine.py

PIPELINE STAGE 5: Adaptive Engine

    Threat Score -> [Adaptive Engine] -> Response Engine

This is what makes the firewall "smart": traffic behavior changes the
threat score, and the threat score changes the firewall's posture.

    LOW    -> normal firewall rules apply
    MEDIUM -> increase monitoring + log activity
    HIGH   -> trigger automated response
"""

DECISION_FOR_LEVEL = {
    "LOW": "NORMAL",
    "MEDIUM": "MONITOR",
    "HIGH": "RESPOND",
}


class AdaptiveEngine:
    def decide(self, threat_level: str) -> str:
        """Map a LOW/MEDIUM/HIGH threat level to a posture decision."""
        return DECISION_FOR_LEVEL.get(threat_level, "NORMAL")


