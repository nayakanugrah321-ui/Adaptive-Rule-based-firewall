"""
database.py

PIPELINE STAGE 7b: SQLite Database

Defines and initializes the tables logger.py / site_logger.py write to
and the Dashboard (Step 10) reads from.

Two tables:
  - events       one row per security event (detections, blocks, alerts)
  - site_visits  one row per domain looked up (from site_logger.py) --
                 a separate, simpler log of "what sites were visited",
                 not part of the firewall/IDS decision pipeline.
"""

import sqlite3

import config


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            threat_score INTEGER NOT NULL,
            threat_level TEXT NOT NULL,
            action TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS site_visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            domain TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()
