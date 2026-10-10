# Smart Firewall

A modular cybersecurity system (college PBL project) combining a firewall, IDS, traffic
analyzer, threat scoring, adaptive response, logging, and a live dashboard.

> **Safety:** all testing is done only against systems/networks you own or are explicitly
> authorized to test, ideally in an isolated lab, VM, or container. The system is not
> designed to attack, disrupt, or interfere with third-party systems.

## Architecture

```
NETWORK TRAFFIC
      |
      v
 PACKET SENSOR
      |
      v
TRAFFIC ANALYZER
      |
  +---+---+
  v       v
FIREWALL   IDS
  |         |
  +----+----+
       v
 THREAT SCORE
       |
       v
ADAPTIVE ENGINE
       |
       v
RESPONSE ENGINE
       |
   +---+---+
   v       v
 ALLOW   BLOCK
   +---+---+
       v
     LOGS
       |
       v
   DASHBOARD
```

## Project structure

```
SmartFirewall/
├── main.py                # wires every stage together
├── packet_sensor.py         # capture + extract basic info (real or simulated)
├── traffic_analyzer.py       # per-source stats: packets, pps, ports, connections
├── firewall.py                 # IP/port/protocol allow-block rules
├── ids.py                       # port scan / high rate / anomaly detection
├── threat_score.py               # per-source 0-100 score, LOW/MEDIUM/HIGH
├── adaptive_engine.py             # threat level -> firewall posture
├── response_engine.py              # temporary block, alert
├── logger.py                        # writes events to SQLite
├── database.py                       # SQLite schema + connection
├── site_logger.py            # extension: logs visited domains (DNS queries, real mode)
├── dashboard/
│   ├── app.py                        # Flask routes + JSON API
│   ├── templates/dashboard.html
│   └── static/{style.css,dashboard.js}
├── config.py                # every tunable setting in one place
├── requirements.txt
└── README.md
```

## Run it (Windows)

```powershell
pip install -r requirements.txt
```

For **real (live) capture** you also need **Npcap**: download from
https://npcap.com/#download and install it with **"Install Npcap in WinPcap
API-compatible Mode"** checked. `pip install scapy` alone is not enough --
Npcap is the actual packet-capture driver Windows needs.

```powershell
# Simulated traffic - no admin rights needed, works right away
python main.py --scenario normal
python main.py --scenario port_scan --pps 30    # triggers a temporary block
python main.py --scenario syn_flood --pps 60

# See your real network interfaces (needs scapy + Npcap installed)
python main.py --list-interfaces
#   Wi-Fi (Intel(R) Wireless-AC 9560)
#   Ethernet (Realtek PCIe GbE Family Controller)

# Real capture: open Command Prompt / PowerShell as Administrator, then:
python main.py --mode real --interface "Wi-Fi"
```

Then open **http://127.0.0.1:5000** for the live dashboard, on any OS.

Real capture needs Administrator rights on Windows (the app detects this and
tells you plainly if you're not elevated, rather than failing silently).
Linux/macOS work too -- `sudo python main.py --mode real --interface eth0` --
no Npcap needed there, just root.

## How the pipeline behaves

- **normal** scenario: traffic goes to common ports (443, 22, 80...) from varied sources.
  No detections fire, threat score stays 0, nothing gets logged or blocked.
- **port_scan** scenario: one source sweeps many ports on one target. Once it crosses the
  configured threshold, the IDS flags `PORT_SCAN`, the score climbs (LOW -> MEDIUM -> HIGH),
  and once HIGH, the Response Engine issues a **temporary** block (5 min by default) and
  raises an alert.
- **syn_flood** scenario: one source sends a high rate of small packets to one port.
  Triggers `HIGH_CONNECTION_RATE` the same way, ending in a temporary block.

All thresholds, score weights, and the block duration are in `config.py`.

## Website Visit Logger (extension)

`site_logger.py` is a small, separate logger -- not part of the firewall/IDS decision
pipeline. Its only job: notice which domains get looked up via DNS during **real** capture,
and log them (`site_visits` table). It doesn't inspect page content or decrypt HTTPS --
it works because almost every site visit starts with a plaintext DNS lookup, which scapy
already knows how to parse.

Shows up on the dashboard as **Recent site visits** (time, source IP, domain).

### Testing it against a real website

This only works in `--mode real` (the simulator doesn't generate real DNS traffic):

```powershell
python main.py --list-interfaces
# from an Administrator terminal:
python main.py --mode real --interface "Wi-Fi"
```

Then, on the same machine, open a browser and visit an ordinary site --
`http://example.com` works well for a clean test since it's a single simple page with
nothing else calling out. Within a few seconds **http://127.0.0.1:5000** should show
`example.com` under **Recent site visits**. Visiting a few different sites (e.g.
`github.com`, `wikipedia.org`) should add a row each, per source IP.

If nothing shows up: confirm the interface you picked is the one actually carrying your
traffic (Wi-Fi vs Ethernet), and that your browser/OS isn't using DNS-over-HTTPS for that
request (which encrypts the lookup so it never appears as a plain DNS packet) -- most
browsers' default "secure DNS" setting can be temporarily disabled for this test.

## Status

**All 11 build steps complete, plus the Website Visit Logger extension.** Tested against
`normal`, `port_scan`, and `syn_flood` scenarios, live HTTP checks against the running
dashboard, and mocked-packet unit tests for both the real-capture parsing logic and the
DNS domain-extraction logic (query vs. response, missing-layer cases).
