"""
ids.py

PIPELINE STAGE 3b: IDS Engine (Intrusion Detection System)

    Traffic Analyzer -> [IDS Engine] -> Threat Score

Watches per-source stats from the Traffic Analyzer for suspicious
behavior. Three simple detections, thresholds configurable in
config.py:

  1. Port scan          - many distinct ports from one source within
                           PORT_SCAN_WINDOW_SECONDS
  2. High connection rate - packets/sec above HIGH_CONNECTION_RATE_THRESHOLD
  3. Traffic anomaly     - sudden spike vs. that source's own rolling
                           baseline (TRAFFIC_ANOMALY_MULTIPLIER)
"""

import config


class IDSEngine:
    def __init__(self):
        self._baseline_pps: dict[str, float] = {}

    def check(self, packet, stats) -> list[str]:
        """Return a list of detection strings for this packet's source, e.g.
        ['PORT_SCAN', 'HIGH_CONNECTION_RATE']. Empty list = nothing suspicious."""
        detections = []

        # 1. Port scan
        distinct_ports = stats.distinct_ports_in_window(config.PORT_SCAN_WINDOW_SECONDS)
        if distinct_ports >= config.PORT_SCAN_DISTINCT_PORTS_THRESHOLD:
            detections.append("PORT_SCAN")

        # 2. High connection rate
        pps = stats.packets_per_second()
        if pps >= config.HIGH_CONNECTION_RATE_THRESHOLD:
            detections.append("HIGH_CONNECTION_RATE")

        # 3. Traffic anomaly (vs. this source's own rolling baseline)
        baseline = self._baseline_pps.get(packet.src_ip)
        if baseline is not None and baseline > 1 and pps >= baseline * config.TRAFFIC_ANOMALY_MULTIPLIER:
            detections.append("TRAFFIC_ANOMALY")

        # slow-moving average baseline, updated every packet
        self._baseline_pps[packet.src_ip] = (
            pps if baseline is None else (0.9 * baseline + 0.1 * pps)
        )

        return detections
