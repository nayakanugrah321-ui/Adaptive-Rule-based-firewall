"""
threat_score.py

PIPELINE STAGE 4: Threat Score Engine

    Firewall + IDS -> [Threat Score Engine] -> Adaptive Engine

Converts IDS detections into a running risk score per source IP
(0-100, capped), bucketed as:

    0-29    LOW
    30-59   MEDIUM
    60-100  HIGH

Weights and bucket boundaries live in config.py so they're easy to
tune without touching this file.
"""

import config

WEIGHTS = {
    "PORT_SCAN": config.SCORE_WEIGHT_PORT_SCAN,
    "HIGH_CONNECTION_RATE": config.SCORE_WEIGHT_HIGH_CONNECTION_RATE,
    "TRAFFIC_ANOMALY": config.SCORE_WEIGHT_TRAFFIC_ANOMALY,
}

class ThreatScoreEngine:
    def __init__(self):
        self._scores: dict[str, int] = {}

    def update(self, source_ip: str, detections: list[str]) -> tuple[int, str]:
        """Add points for each detection, return (score, level) for source_ip."""
        score = self._scores.get(source_ip, 0)
        for detection in detections:
            score += WEIGHTS.get(detection, 0)
        score = min(score, 100)
        self._scores[source_ip] = score
        return score, self._level(score)

    def get(self, source_ip: str) -> tuple[int, str]:
        score = self._scores.get(source_ip, 0)
        return score, self._level(score)

    @staticmethod
    def _level(score: int) -> str:
        if score <= config.SCORE_LOW_MAX:
            return "LOW"
        if score <= config.SCORE_MEDIUM_MAX:
            return "MEDIUM"
        return "HIGH"
