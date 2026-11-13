# export_labels.py: writes logged exchanges to a CSV so I can label them by hand
# obviously a CSV is just so that I can open it in Google Sheets and label it by hand
# the csv will also be used to 

# detector results are deliberately left out, so my labels aren't influenced by them.

# i am going to export every row to CSV and then after running my held-out probing questions
# i will export those seperately so I can label them by hand

import csv
import os
import sqlite3
import sys

start = int(sys.argv[1]) if len(sys.argv) > 1 else 0
out = "eval_labels.csv" if start == 0 else f"eval_labels_from_{start}.csv"

# refuse to overwrite an existing file, so hand-made labels can never be wiped by accident
if os.path.exists(out):
    sys.exit(f"{out} already exists. Rename or move it first.")

# connects to SQLite and retrieves all rows with id more than the start value and writes them to CSV file format
with sqlite3.connect("chat_log.db") as conn:
    rows = conn.execute(
        "SELECT id, question, answer FROM exchanges WHERE id >= ? ORDER BY id", (start,)
    ).fetchall()

# writes the rows to a CSV file, with newlines replaced by " / " so each is on one row
with open(out, "w", newline="") as f:     # the csv module handles commas and quotes inside answers
    writer = csv.writer(f)
    writer.writerow(["id", "set", "truth_kind", "truth_severity", "question", "answer"])
    for row_id, question, answer in rows:
        # Newlines are replaced so each exchange stays on one row
        writer.writerow([row_id, "", "", "", question, answer.replace("\n", " / ")])

print(f"Wrote {len(rows)} rows to {out}")