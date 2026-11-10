# logger.py: saves every chat exchange to a local SQLite database
import json # converts the list of sources to a string for storage in SQLite
import sqlite3
from datetime import datetime, timezone # used to timestamp each exchage with the bot

# Where the database file is saved: the folder you run the program from.
# *.db is in .gitignore, so this file never goes to GitHub.
# this means that for each new user, a new databse is created in SQLite so that not one can see the chat history of other users
DB_PATH = "chat_log.db"


def init_db():
    # create the log table if it doesn't exist yet
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS exchanges (
                id lINTEGER PRIMARY KEY AUTOINCREMENT,
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


# this method is used by chat.py and app.py to log every exchange to SQLite
def log_exchange(session_id, question, sources, answer):
    """Save one question and answer. Returns the new row's id so detectors can update it later."""
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "INSERT INTO exchanges (timestamp, session_id, question, retrieved_sources, answer) "
            # the question marks are placeholders to keep the data seperate from the SQL command
            # this is done in order to prevent SQL injection attacks
            # although this might have been a cool attack to simulate I wanted the project to strictly follow
            # attack vectors for AI RAG models
            "VALUES (?, ?, ?, ?, ?)",
            (
                datetime.now(timezone.utc).isoformat(),
                session_id,
                question,
                json.dumps(sources),
                answer,
            ),
        )
        return cur.lastrowid # the row id is returned