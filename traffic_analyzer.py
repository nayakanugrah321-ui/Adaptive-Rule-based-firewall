"""
traffic_analyzer.py

PIPELINE STAGE 2: Traffic Analyzer

    Packet Sensor -> [Traffic Analyzer] -> Firewall + IDS

Receives one PacketInfo at a time and keeps running, per-source-IP
statistics: number of connections, number of packets, packets/sec,
number of distinct ports contacted, and a protocol breakdown.

The IDS (Step 5) reads these stats to spot port scans and high
connection rates -- this module only *measures*, it doesn't decide
anything.
"""

import time
from collections import Counter, deque
from dataclasses import dataclass, field


@dataclass
class SourceStats:
    """Running stats for one source IP."""

    total_packets: int = 0
    connections: set = field(default_factory=set)     # (dst_ip, dst_port, protocol)
    ports_contacted: set = field(default_factory=set)   # distinct dst ports (all-time)
    protocol_counts: Counter = field(default_factory=Counter)
    recent_timestamps: deque = field(default_factory=lambda: deque(maxlen=500))
    recent_ports: deque = field(default_factory=lambda: deque(maxlen=500))  # (timestamp, port)

    def packets_per_second(self, window_seconds: float = 1.0) -> float:
        if not self.recent_timestamps:
            return 0.0
        now = self.recent_timestamps[-1]
        cutoff = now - window_seconds
        recent = [t for t in self.recent_timestamps if t >= cutoff]
        return len(recent) / window_seconds

    def distinct_ports_in_window(self, window_seconds: float) -> int:
        if not self.recent_ports:
            return 0
        now = self.recent_ports[-1][0]
        cutoff = now - window_seconds
        return len({port for ts, port in self.recent_ports if ts >= cutoff})


class TrafficAnalyzer:
    def __init__(self):
        self._by_source: dict[str, SourceStats] = {}

    def process(self, packet) -> dict:
        """Update running stats for packet.src_ip and return a summary dict."""
        stats = self._by_source.setdefault(packet.src_ip, SourceStats())

        stats.total_packets += 1
        stats.connections.add((packet.dst_ip, packet.dst_port, packet.protocol))
        stats.ports_contacted.add(packet.dst_port)
        stats.protocol_counts[packet.protocol] += 1
        stats.recent_timestamps.append(packet.timestamp)
        stats.recent_ports.append((packet.timestamp, packet.dst_port))

        return {
            "source": packet.src_ip,
            "destination": packet.dst_ip,
            "protocol": packet.protocol,
            "destination_port": packet.dst_port,
            "packets": stats.total_packets,
            "connections": len(stats.connections),
            "distinct_ports_contacted": len(stats.ports_contacted),
            "packets_per_second": round(stats.packets_per_second(), 2),
            "protocol_breakdown": dict(stats.protocol_counts),
        }

    def get_stats(self, source_ip: str) -> SourceStats:
        return self._by_source.setdefault(source_ip, SourceStats())

    def totals(self) -> dict:
        """Aggregate numbers across every source seen so far (for the dashboard)."""
        return {
            "total_packets": sum(s.total_packets for s in self._by_source.values()),
            "total_connections": sum(len(s.connections) for s in self._by_source.values()),
            "distinct_sources": len(self._by_source),
        }
