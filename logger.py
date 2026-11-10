# logger.py: saves every chat exchange to a local SQLite database

import json
import sqlite3
from datetime import datetime, timezone

DB_PATH = "chat_log.db"


def init_db():
    """Create the log table if it doesn't exist yet."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS exchanges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                session_id TEXT,
                question TEXT,
                retrieved_sources TEXT,
                answer TEXT,
                rules_flagged INTEGER,   -- filled in by the detectors on Day 3
                llm_flagged INTEGER,
                severity TEXT,
                reason TEXT
            )"""
        )


def log_exchange(session_id, question, sources, answer):
    """Save one question and answer. Returns the new row's id so detectors can update it later."""
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "INSERT INTO exchanges (timestamp, session_id, question, retrieved_sources, answer) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                datetime.now(timezone.utc).isoformat(),
                session_id,
                question,
                json.dumps(sources),
                answer,
            ),
        )
        return cur.lastrowid