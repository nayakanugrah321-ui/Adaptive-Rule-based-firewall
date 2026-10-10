"""
config.py

Central settings for every stage of the pipeline. Kept in one file so
behavior can be tuned (thresholds, block duration, ports...) without
touching component code -- useful when explaining/demoing the project.
"""

# --- Packet Sensor (Step 2) ---
CAPTURE_MODE = "simulated"     # "real" (scapy, needs admin/root) or "simulated"
CAPTURE_INTERFACE = None        # e.g. "Wi-Fi" or "Ethernet" on Windows, "eth0"/"en0" elsewhere
SIMULATOR_PACKETS_PER_SECOND = 5
SIMULATOR_SCENARIO = "normal"   # "normal" | "port_scan" | "syn_flood"

# --- IDS thresholds (Step 5) ---
PORT_SCAN_DISTINCT_PORTS_THRESHOLD = 10     # distinct ports from one source to flag a scan
PORT_SCAN_WINDOW_SECONDS = 10                # time window the above is measured over
HIGH_CONNECTION_RATE_THRESHOLD = 50           # connections/sec considered "high" (doc example: normal=5, observed=100)
TRAFFIC_ANOMALY_MULTIPLIER = 3                 # traffic X times above baseline = anomaly

# --- Threat Score Engine (Step 6) ---
# Points added per detection (from the spec's example weights)
SCORE_WEIGHT_PORT_SCAN = 30
SCORE_WEIGHT_HIGH_CONNECTION_RATE = 25
SCORE_WEIGHT_TRAFFIC_ANOMALY = 20

# Score buckets
SCORE_LOW_MAX = 29        # 0-29    -> LOW
SCORE_MEDIUM_MAX = 59      # 30-59   -> MEDIUM
# 60-100 -> HIGH

# --- Response Engine (Step 8) ---
TEMP_BLOCK_DURATION_SECONDS = 300   # temporary block, not permanent

# --- Database (Step 9) ---
DATABASE_PATH = "smart_firewall.db"

# --- Dashboard (Step 10) ---
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 5000
