# logger.py: saves every chat exchange to a local SQLite database
import json # converts the list of sources to a string for storage in SQLite
import sqlite3
from datetime import datetime, timezone # used to timestamp each exchage with the bot

# Where the database file is saved: the folder you run the program from.
# *.db is in .gitignore, so this file never goes to GitHub.
# this means that for each new user, a new databse is created in SQLite so that not one can see the chat history of other users
DB_PATH = "chat_log.db"

# Used to pick the higher of the two detectors' severities
SEVERITY_ORDER = ["none", "low", "medium", "high"]


def init_db():
    # create the log table if it doesn't exist yet
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            # IF NOT EXISTS means an existing log is never wiped
            """CREATE TABLE IF NOT EXISTS exchanges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,  -- unique row number, assigned automatically
                timestamp TEXT,                        -- when the exchange happened (UTC)
                session_id TEXT,                       -- which chat session it belongs to
                question TEXT,                         -- what the user typed
                retrieved_sources TEXT,                -- which documents were pulled into the prompt
                answer TEXT,                           -- what Fresh replied
                rules_flagged INTEGER,                 -- 1 if the rules detector flagged it
                llm_flagged INTEGER,                   -- 1 if the LLM classifier flagged it (empty if it errored)
                severity TEXT,                         -- the higher of the two detectors' severities
                reason TEXT                            -- both detectors' reasons, combined
            )"""
        )

        # Add per-layer columns to an existing table (safe to run on every start).
        # CREATE TABLE IF NOT EXISTS won't change a table that already exists, so older
        # databases need these columns added separately.
        existing = {row[1] for row in conn.execute("PRAGMA table_info(exchanges)")}
        for column in ("rules_severity TEXT", "rules_reason TEXT", "llm_severity TEXT", "llm_reason TEXT"):
            if column.split()[0] not in existing:
                conn.execute(f"ALTER TABLE exchanges ADD COLUMN {column}")

# this method saves one question and answer to the SQLite log, and returns the new row's id so detectors can update it later
def log_exchange(session_id, question, sources, answer):
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            # The ? placeholders keep the data separate from the SQL command, so
            # attacker-written text in a question can't alter the database (SQL injection).
            "INSERT INTO exchanges (timestamp, session_id, question, retrieved_sources, answer) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                datetime.now(timezone.utc).isoformat(),  # current time in UTC, as text
                session_id,
                question,
                json.dumps(sources),  # e.g. ["a.txt", "b.txt"] becomes the text '["a.txt", "b.txt"]'
                answer,
            ),
        )
        return cur.lastrowid  # the id of the row just created


def update_flags(row_id, rules, llm):
    # save both detectors' verdicts on an existing row
    # 'severity' and 'reason' hold the combined result, and the per-layer columns keep each
    # detector's own verdict so the layers can be compared in the evaluation
    # take the higher severity of the two layers (an errored classifier is ignored)
    ranked = [s for s in (rules["severity"], llm["severity"]) if s in SEVERITY_ORDER]
    overall = max(ranked, key=SEVERITY_ORDER.index) if ranked else "none"

    rules_reason = "; ".join(rules["reasons"])
    llm_reason = f'{llm["kind"]}: {llm["reason"]}'
    # flagged is None when the classifier errored, which is stored as empty (NULL), not 0
    llm_flagged = None if llm["flagged"] is None else int(llm["flagged"])

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE exchanges SET rules_flagged=?, llm_flagged=?, severity=?, reason=?, "
            "rules_severity=?, rules_reason=?, llm_severity=?, llm_reason=? WHERE id=?",
            (
                int(rules["flagged"]),
                llm_flagged,
                overall,
                f"rules: {rules_reason or '-'} | llm: {llm_reason}",
                rules["severity"],
                rules_reason,
                llm["severity"],
                llm_reason,
                row_id,
            ),
        )