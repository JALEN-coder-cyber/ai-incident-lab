# alerts.py: sends a flagged exchange to the n8n webhook for a ticket and alert
# the payload deliberately contains NO answer text and NO classifier reason, because either
# can contain the leaked fact. n8n gets the row id so a human can look the exchange up in the log.

import os
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv

# loads all of our credentials from .env 
load_dotenv()
WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL")
WEBHOOK_TOKEN = os.getenv("N8N_WEBHOOK_TOKEN")
KIND_ORDER = ["none", "attempt", "hijack", "leak"]

# establishes the order of severity levels to take the higher of the two layers when saving to the SQLite log
def overall_kind(rules, llm):
    # the most serious kind either detector reported (leak > hijack > attempt)
    kinds = [reason.split(":")[0] for reason in rules["reasons"]]   # e.g. "leak: supplier name (high)"
    kinds.append(llm["kind"])
    kinds = [k for k in kinds if k in KIND_ORDER]
    return max(kinds, key=KIND_ORDER.index) if kinds else "none"

# this is a fail-safe method that sends an alert to n8n if the classifier fails
def send_alert(row_id, session_id, severity, rules, llm):
    # post one flagged exchange to n8n. Never raises: the chatbot must keep working if n8n is down
    if not WEBHOOK_URL or not WEBHOOK_TOKEN:
        print("[alert skipped: N8N_WEBHOOK_URL or N8N_WEBHOOK_TOKEN not set in .env]")
        return
    kind = overall_kind(rules, llm)
    if llm["severity"] == "error":          # a broken classifier should be visible, not silent
        kind = kind if kind != "none" else "error"
        severity = severity if severity != "none" else "low"
    payload = {
        "row_id": row_id,
        "session_id": session_id,
        "severity": severity,
        "kind": kind,
        "rules_severity": rules["severity"],
        "llm_severity": llm["severity"],
        "rules_reasons": "; ".join(rules["reasons"]),   # labels only, such as "leak: supplier name (high)"
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        resp = requests.post(WEBHOOK_URL, json=payload, headers={"X-Alert-Token": WEBHOOK_TOKEN}, timeout=5)
        resp.raise_for_status()
    except Exception as e:
        print(f"[alert not sent: {type(e).__name__}]")   # the error type only, so no URL is printed