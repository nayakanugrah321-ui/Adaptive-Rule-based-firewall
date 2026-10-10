"""
logger.py

PIPELINE STAGE 7a: Logging

    Response Engine -> [Logging] -> Dashboard

Writes important events (detections + the action taken) to the
SQLite database from database.py. Routine allowed traffic is not
logged -- only PORT_SCAN / HIGH_CONNECTION_RATE / TRAFFIC_ANOMALY /
BLOCK / ALERT events, matching the doc's "every important event
should be logged."
"""

from datetime import datetime, timezone

from database import get_connection


def log_event(source_ip: str, event_type: str, threat_score: int, threat_level: str, action: str):
    conn = get_connection()
    conn.execute(
        "INSERT INTO events (timestamp, source_ip, event_type, threat_score, threat_level, action) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), source_ip, event_type, threat_score, threat_level, action),
    )
    conn.commit()
    conn.close()


def get_recent_events(limit: int = 20) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def count_events_by_level() -> dict:
    conn = get_connection()
    rows = conn.execute(
        "SELECT threat_level, COUNT(*) as n FROM events GROUP BY threat_level"
    ).fetchall()
    conn.close()
    return {row["threat_level"]: row["n"] for row in rows}
