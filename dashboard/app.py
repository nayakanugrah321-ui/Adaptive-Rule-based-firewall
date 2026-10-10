"""
dashboard/app.py

PIPELINE STAGE 8: Dashboard (Flask)

    Logging -> [Dashboard]

Displays firewall/IDS/auto-response status, packet & connection
totals, recent alerts, current firewall rules, and blocked sources.
Reads from the live engine instances (registered by main.py) and
from the SQLite event log -- it makes no security decisions itself.

The page polls a few small JSON endpoints every couple of seconds
instead of a full page reload, so it stays live while the pipeline
runs in the background.
"""

import time

from flask import Flask, jsonify, render_template

from logger import get_recent_events
from site_logger import get_recent_site_visits

app = Flask(__name__)

# Populated by main.py (Step 11) via register_engines() before the
# server starts, so the dashboard reads the same live objects the
# pipeline is updating -- no database round-trip needed for these.
_engines = {}


def register_engines(analyzer, firewall, response_engine):
    _engines["analyzer"] = analyzer
    _engines["firewall"] = firewall
    _engines["response"] = response_engine


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    analyzer = _engines.get("analyzer")
    response = _engines.get("response")
    totals = analyzer.totals() if analyzer else {"total_packets": 0, "total_connections": 0}
    blocked = response.active_blocks() if response else {}

    return jsonify({
        "firewall_status": "ACTIVE",
        "ids_status": "ACTIVE",
        "auto_response_status": "ACTIVE",
        "packets": totals.get("total_packets", 0),
        "connections": totals.get("total_connections", 0),
        "threats": len(get_recent_events(1000)),
        "blocked_sources": len(blocked),
    })


@app.route("/api/alerts")
def api_alerts():
    return jsonify(get_recent_events(15))


@app.route("/api/blocked")
def api_blocked():
    response = _engines.get("response")
    blocked = response.active_blocks() if response else {}
    now = time.time()
    return jsonify([
        {
            "ip": ip,
            "reason": entry["reason"],
            "score": entry["score"],
            "expires_in": max(0, int(entry["expires_at"] - now)),
        }
        for ip, entry in blocked.items()
    ])


@app.route("/api/rules")
def api_rules():
    firewall = _engines.get("firewall")
    return jsonify(firewall.rules if firewall else [])


@app.route("/api/site-visits")
def api_site_visits():
    """Recent domains looked up via DNS -- real mode only (see site_logger.py)."""
    return jsonify(get_recent_site_visits(15))
