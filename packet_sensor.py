"""
packet_sensor.py

PIPELINE STAGE 1: Packet Sensor

    Traffic -> Capture -> Extract basic info -> Send to Analyzer

Observes network traffic and extracts: source IP, destination IP,
source port, destination port, protocol, packet size, time.
Makes no security decisions itself -- that happens later in the
pipeline (firewall.py, ids.py, ...).

Two interchangeable capture modes (set in config.py):
  - "simulated" : synthetic traffic generator, no special privileges
                  needed. Good for development, testing, demos.
  - "real"      : live capture via scapy. Needs admin/root (+ npcap on
                  Windows). Only run against traffic you own or are
                  explicitly authorized to monitor.
"""

import random
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Callable, Optional


@dataclass
class PacketInfo:
    """One observed packet, reduced to the fields the project uses."""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str    # "TCP" / "UDP" / "ICMP" / "OTHER"
    size: int         # bytes

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def readable_time(self) -> str:
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc).strftime("%H:%M:%S")

    def __str__(self) -> str:
        return (
            f"[{self.readable_time}] {self.protocol:5s} "
            f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} "
            f"({self.size} bytes)"
        )


# ---------------------------------------------------------------------
# Simulated traffic (used when config.CAPTURE_MODE == "simulated")
# ---------------------------------------------------------------------
COMMON_PORTS = [80, 443, 22, 21, 25, 53, 3306, 8080]
PROTOCOLS = ["TCP", "UDP", "ICMP"]


def _random_ip(prefix: str) -> str:
    return f"{prefix}.{random.randint(2, 254)}"


class _TrafficSimulator:
    """Generates synthetic PacketInfo events. Scenarios exist so the IDS
    (Step 5) has real patterns to detect: normal / port_scan / syn_flood."""

    def __init__(self, packets_per_second: float = 5, scenario: str = "normal"):
        self.packets_per_second = packets_per_second
        self.scenario = scenario
        self._running = False

    def stop(self):
        self._running = False

    def run(self, callback: Callable[["PacketInfo"], None], duration_seconds: Optional[float] = None):
        self._running = True
        start = time.time()
        attacker_ip = _random_ip("203.0.113")
        target_ip = _random_ip("10.0.0")
        interval = 1.0 / self.packets_per_second if self.packets_per_second > 0 else 0.2

        while self._running:
            if self.scenario == "port_scan":
                packet = PacketInfo(
                    timestamp=time.time(), src_ip=attacker_ip, dst_ip=target_ip,
                    src_port=random.randint(1024, 65535), dst_port=random.randint(1, 65535),
                    protocol="TCP", size=random.randint(40, 60),
                )
            elif self.scenario == "syn_flood":
                packet = PacketInfo(
                    timestamp=time.time(), src_ip=attacker_ip, dst_ip=target_ip,
                    src_port=random.randint(1024, 65535), dst_port=80,
                    protocol="TCP", size=random.randint(40, 60),
                )
            else:
                packet = PacketInfo(
                    timestamp=time.time(), src_ip=_random_ip("192.168.1"), dst_ip=_random_ip("10.0.0"),
                    src_port=random.randint(1024, 65535), dst_port=random.choice(COMMON_PORTS),
                    protocol=random.choice(PROTOCOLS), size=random.randint(64, 1500),
                )

            callback(packet)
            if duration_seconds is not None and (time.time() - start) >= duration_seconds:
                break
            time.sleep(interval)
        self._running = False


# ---------------------------------------------------------------------
# Packet Sensor - the public interface the rest of the pipeline uses
# ---------------------------------------------------------------------
class PacketSensor:
    def __init__(self, mode: str = "simulated", interface: Optional[str] = None,
                 packets_per_second: float = 5, scenario: str = "normal"):
        if mode not in ("real", "simulated"):
            raise ValueError("mode must be 'real' or 'simulated'")
        self.mode = mode
        self.interface = interface
        self._simulator = _TrafficSimulator(packets_per_second, scenario)
        self._sniffing = False

    def start(self, on_packet: Callable[[PacketInfo], None], duration_seconds: Optional[float] = None,
              on_site_visit: Optional[Callable[[str, str], None]] = None):
        """Capture traffic, calling on_packet(PacketInfo) for every packet seen.
        If on_site_visit is given, it's called with (source_ip, domain) whenever
        a DNS query is observed -- real mode only, see site_logger.py."""
        if self.mode == "simulated":
            self._simulator.run(on_packet, duration_seconds)
        else:
            self._start_real_capture(on_packet, duration_seconds, on_site_visit)

    def stop(self):
        if self.mode == "simulated":
            self._simulator.stop()
        else:
            self._sniffing = False

    def _start_real_capture(self, on_packet, duration_seconds, on_site_visit=None):
        try:
            from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
        except ImportError as exc:
            raise RuntimeError(
                "Real capture needs scapy installed (`pip install scapy`). On Windows "
                "you also need Npcap installed first: https://npcap.com/#download "
                "(check 'Install Npcap in WinPcap API-compatible Mode' during setup)."
            ) from exc

        if is_windows() and not is_windows_admin():
            raise RuntimeError(
                "Real capture on Windows needs Administrator privileges. Close this "
                "terminal, right-click Command Prompt / PowerShell -> 'Run as "
                "administrator', then run this command again."
            )

        def _handle(raw):
            info = parse_scapy_packet(raw, IP, TCP, UDP)
            if info is not None:
                on_packet(info)
            if on_site_visit is not None:
                from site_logger import extract_domain
                domain = extract_domain(raw, DNS, DNSQR, UDP)
                if domain and raw.haslayer(IP):
                    on_site_visit(raw[IP].src, domain)

        self._sniffing = True
        try:
            sniff(iface=self.interface, prn=_handle, store=False, timeout=duration_seconds,
                  stop_filter=lambda _p: not self._sniffing)
        except PermissionError as exc:
            hint = ("Run Command Prompt / PowerShell as Administrator."
                    if is_windows() else "Run with 'sudo python main.py --mode real ...'.")
            raise RuntimeError(f"Permission denied opening the network interface. {hint}") from exc
        except OSError as exc:
            available = ", ".join(list_interfaces()) or "(none found -- is Npcap installed?)"
            raise RuntimeError(
                f"Could not open interface '{self.interface}': {exc}. "
                f"Available interfaces: {available}"
            ) from exc


def parse_scapy_packet(raw, IP, TCP, UDP):
    """Convert one scapy packet into a PacketInfo, or None to skip it
    (non-IP traffic -- ARP, etc. -- is out of scope for this project).
    Pulled out as a standalone function so it can be unit tested without
    a real network interface, by passing in fake IP/TCP/UDP classes.
    """
    if not raw.haslayer(IP):
        return None
    ip_layer = raw[IP]
    protocol, src_port, dst_port = "OTHER", 0, 0
    if raw.haslayer(TCP):
        protocol, src_port, dst_port = "TCP", int(raw[TCP].sport), int(raw[TCP].dport)
    elif raw.haslayer(UDP):
        protocol, src_port, dst_port = "UDP", int(raw[UDP].sport), int(raw[UDP].dport)
    elif ip_layer.proto == 1:
        protocol = "ICMP"
    return PacketInfo(
        timestamp=float(raw.time), src_ip=ip_layer.src, dst_ip=ip_layer.dst,
        src_port=src_port, dst_port=dst_port, protocol=protocol, size=len(raw),
    )


def is_windows() -> bool:
    import platform
    return platform.system() == "Windows"


def is_windows_admin() -> bool:
    """True if the current process has Administrator rights. Only meaningful
    on Windows; callers should check is_windows() first."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return True  # can't determine -- don't block on a guess, let sniff() fail with its own error


def format_windows_interfaces(raw_interfaces: list) -> list[str]:
    """Turn scapy's Windows interface records into readable strings, e.g.
    'Wi-Fi (Intel Wireless-AC 9560)'. Separated from list_interfaces() so
    the formatting can be unit tested without scapy/Npcap installed."""
    names = []
    for iface in raw_interfaces:
        name = iface.get("name") or iface.get("guid") or "?"
        description = iface.get("description", "")
        names.append(f"{name} ({description})" if description and description != name else name)
    return names


def list_interfaces() -> list[str]:
    """Names of network interfaces scapy can see on this machine. Used by
    `python main.py --list-interfaces` to help pick --interface for real capture.
    On Windows these are friendly names (Wi-Fi, Ethernet); elsewhere they're
    device names (eth0, en0, ...)."""
    try:
        if is_windows():
            from scapy.arch.windows import get_windows_if_list
            return format_windows_interfaces(get_windows_if_list())
        from scapy.all import get_if_list
        return get_if_list()
    except ImportError:
        return []
    except Exception:
        return []
