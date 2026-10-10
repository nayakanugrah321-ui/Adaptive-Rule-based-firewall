"""
response_engine.py

PIPELINE STAGE 6: Response Engine

    Adaptive Engine -> [Response Engine] -> ALLOW / BLOCK -> Logging

Carries out the Adaptive Engine's decision:
    NORMAL  -> ALLOW (unless the Firewall Engine itself said BLOCK)
    MONITOR -> MONITOR (allowed through, but flagged)
    RESPOND -> BLOCK the source TEMPORARILY + raise an alert

Blocks are temporary (config.TEMP_BLOCK_DURATION_SECONDS), not
permanent -- once a block expires the source is evaluated again from
a clean slate, exactly like a brand new source.
"""

import time

import config


class ResponseEngine:
    def __init__(self):
        # source_ip -> {"reason", "score", "blocked_at", "expires_at"}
        self._blocked: dict[str, dict] = {}

    def is_blocked(self, source_ip: str) -> bool:
        entry = self._blocked.get(source_ip)
        if not entry:
            return False
        if time.time() >= entry["expires_at"]:
            del self._blocked[source_ip]  # block expired -> re-evaluate from scratch
            return False
        return True

    def respond(self, source_ip: str, fw_decision: str, adaptive_decision: str,
                detections: list[str], score: int, level: str) -> tuple[str, bool]:
        """Decide the final action for this packet's source.
        Returns (action, alert_generated) where action is one of
        ALLOW / MONITOR / BLOCK."""

        if self.is_blocked(source_ip):
            return "BLOCK", False  # already under an active temporary block

        if fw_decision == "BLOCK":
            return "BLOCK", False  # explicit firewall rule, not a new threat alert

        if adaptive_decision == "RESPOND":
            reason = ", ".join(detections) if detections else "HIGH_THREAT"
            self._blocked[source_ip] = {
                "reason": reason,
                "score": score,
                "blocked_at": time.time(),
                "expires_at": time.time() + config.TEMP_BLOCK_DURATION_SECONDS,
            }
            return "BLOCK", True  # new block -> raise an alert

        if adaptive_decision == "MONITOR":
            return "MONITOR", False

        return "ALLOW", False

    def active_blocks(self) -> dict:
        """Currently blocked sources, for the dashboard. Purges expired ones first."""
        now = time.time()
        for ip in [ip for ip, e in self._blocked.items() if now >= e["expires_at"]]:
            del self._blocked[ip]
        return dict(self._blocked)
