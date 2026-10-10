"""
main.py

Wires every stage together into the final pipeline:

    Packet Sensor -> Traffic Analyzer -> Firewall + IDS
        -> Threat Score -> Adaptive Engine -> Response Engine
        -> Logging -> Dashboard

The Packet Sensor runs in a background thread (it can run forever);
the Flask dashboard runs in the main thread so Ctrl+C cleanly stops
the whole process.
"""

import argparse
import threading

import config
from packet_sensor import PacketSensor, list_interfaces
from traffic_analyzer import TrafficAnalyzer
from firewall import FirewallEngine
from ids import IDSEngine
from threat_score import ThreatScoreEngine
from adaptive_engine import AdaptiveEngine
from response_engine import ResponseEngine
from database import init_db
from logger import log_event
from site_logger import log_site_visit
from dashboard.app import app as dashboard_app, register_engines


def build_pipeline_handler(analyzer, firewall, ids_engine, score_engine, adaptive, response):
    """Returns the per-packet callback that runs the full pipeline for one packet."""

    def handle_packet(packet):
        # Stage 2: Traffic Analyzer
        analyzer.process(packet)
        stats = analyzer.get_stats(packet.src_ip)

        # Stage 3: Firewall + IDS
        fw_decision = firewall.check(packet)
        detections = ids_engine.check(packet, stats)

        # Stage 4: Threat Score
        score, level = score_engine.update(packet.src_ip, detections)

        # Stage 5: Adaptive Engine
        posture = adaptive.decide(level)

        # Stage 6: Response Engine
        action, alert = response.respond(packet.src_ip, fw_decision, posture, detections, score, level)

        # Stage 7: Logging -- only log what matters (detections, or a non-ALLOW action)
        if detections or action != "ALLOW":
            event_type = ", ".join(detections) if detections else "FIREWALL_RULE"
            log_event(packet.src_ip, event_type, score, level, action)

    return handle_packet


def main():
    parser = argparse.ArgumentParser(description="Smart Firewall")
    parser.add_argument("--mode", choices=["real", "simulated"], default=config.CAPTURE_MODE)
    parser.add_argument("--interface", default=config.CAPTURE_INTERFACE,
                         help='Network interface for --mode real, e.g. "Wi-Fi" or "Ethernet" '
                              '(Windows) -- see --list-interfaces')
    parser.add_argument("--scenario", choices=["normal", "port_scan", "syn_flood"],
                         default=config.SIMULATOR_SCENARIO)
    parser.add_argument("--pps", type=float, default=config.SIMULATOR_PACKETS_PER_SECOND)
    parser.add_argument("--list-interfaces", action="store_true",
                         help="Print available network interfaces and exit "
                              "(needs scapy + Npcap installed on Windows)")
    args = parser.parse_args()

    if args.list_interfaces:
        interfaces = list_interfaces()
        if not interfaces:
            print("No interfaces found. On Windows: install Npcap (https://npcap.com/#download) "
                  "and `pip install scapy`, then run this from an Administrator terminal.")
        else:
            print("Available interfaces:")
            for name in interfaces:
                print(f"  {name}")
        return

    if args.mode == "real" and not args.interface:
        print('Warning: --mode real with no --interface set. Run '
              '`python main.py --list-interfaces` first and pass one, e.g. --interface "Wi-Fi".')

    init_db()

    analyzer = TrafficAnalyzer()
    firewall = FirewallEngine()
    ids_engine = IDSEngine()
    score_engine = ThreatScoreEngine()
    adaptive = AdaptiveEngine()
    response = ResponseEngine()

    sensor = PacketSensor(mode=args.mode, interface=args.interface,
                           packets_per_second=args.pps, scenario=args.scenario)

    handle_packet = build_pipeline_handler(analyzer, firewall, ids_engine, score_engine, adaptive, response)

    # Dashboard (Step 10) reads directly from these live engine instances.
    register_engines(analyzer, firewall, response)

    sensor_thread = threading.Thread(
        target=sensor.start,
        args=(handle_packet,),
        kwargs={"on_site_visit": log_site_visit},
        daemon=True,
    )
    sensor_thread.start()

    print(f"Smart Firewall running (mode={args.mode}, scenario={args.scenario})")
    print(f"Dashboard: http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}")
    dashboard_app.run(host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT,
                       debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
