"""

site_logger.py

Website Visit Logger (extension -- not part of the original 11-step
pipeline). Its only job: notice which domain names get looked up via
DNS during real packet capture, and log them. It does not inspect
page content, decrypt HTTPS, or make any firewall/IDS/threat-score
decision -- it is a separate, simpler observational log.

Only meaningful with --mode real: DNS queries are real network
traffic, and the simulator doesn't generate real DNS payloads.

How it works: almost every website visit starts with the browser
resolving the domain name via DNS before it ever opens a connection.
Since DNS queries are plaintext, scapy can already parse the domain
name out of them (its DNS layer) -- no raw byte parsing needed here.
"""

from datetime import datetime, timezone
from typing import Optional

from database import get_connection


def extract_domain(raw_packet, DNS, DNSQR, UDP) -> Optional[str]:
    """Return the domain name being looked up if this packet is a real,
    ordinary DNS *query* (not a response, and not mDNS/local service
    discovery), else None.

    Devices on any home network constantly broadcast mDNS traffic on
    port 5353 for service discovery -- "_googlecast._tcp.local",
    "_airplay._tcp.local", printers, etc. -- and it uses the exact same
    DNS packet format, so it has to be filtered out explicitly or it
    drowns out actual website lookups (which go to port 53).

    DNS/DNSQR/UDP are passed in rather than imported here so this stays
    unit-testable without scapy/Npcap installed -- same pattern as
    packet_sensor.parse_scapy_packet()."""
    if not raw_packet.haslayer(DNS):
        return None
    if raw_packet.haslayer(UDP) and raw_packet[UDP].dport != 53:
        return None  # not an ordinary DNS query (e.g. mDNS on 5353)
    dns = raw_packet[DNS]
    if dns.qr != 0 or dns.qdcount == 0:   # qr=0 -> query, qr=1 -> response
        return None
    if not raw_packet.haslayer(DNSQR):
        return None
    qname = raw_packet[DNSQR].qname
    if isinstance(qname, bytes):
        qname = qname.decode(errors="ignore")
    domain = qname.rstrip(".")
    if domain.endswith(".local"):
        return None  # mDNS / local service discovery, not a real website
    return domain


def log_site_visit(source_ip: str, domain: str):
    conn = get_connection()
    conn.execute(
        "INSERT INTO site_visits (timestamp, source_ip, domain) VALUES (?, ?, ?)",
        (datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), source_ip, domain),
    )
    conn.commit()
    conn.close()


def get_recent_site_visits(limit: int = 20) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM site_visits ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]
