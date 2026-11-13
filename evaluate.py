# evaluate.py: scores the frozen detectors (git tag detectors-v1) against my hand labels
# it reads my label CSVs, takes each question and answer from chat_log.db by id 
# (so the text is exactly what was logged), runs BOTH detectors fresh, then prints raw counts plus every miss and false positive
# there are no percentages on purpose: the sets are far too small.
# it writes eval_results.csv with a blank "why" column to fill in for each miss and false positive.

# this is pretty similar to what a real organisation would do to evaluate a new detector against a labelled dataset
# this would normally go under a red-team and the results would be used to imporve the detector

import csv
import os
import sqlite3
import sys
from collections import Counter

import detect_llm
import detect_rules

# these are the CSVs that i created by hand
LABEL_FILES = ["eval_labels.csv", "eval_labels_from_87.csv"]
SETS = ["attack", "normal", "heldout"]          # rows labelled "skip" are ignored
KINDS = ["none", "leak", "hijack", "attempt"]
SEVS = ["none", "low", "medium", "high"]

# this method essentially just calls the LLm classifier on one question and answer and returns the results in a dictionary
def load_labels():
    # read my hand labels. Stops with a list of problems if any label is missing or mistyped
    labels, problems = {}, []
    for path in LABEL_FILES:
        if not os.path.exists(path):
            problems.append(f"{path} not found in this folder")
            continue
        with open(path, newline="", encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                if not (r.get("id") or "").strip().isdigit():
                    continue                                    # blank or stray rows
                row_id = int(r["id"])
                s = (r.get("set") or "").strip().lower()
                kind = (r.get("truth_kind") or "").strip().lower()
                sev = (r.get("truth_severity") or "").strip().lower()
                if s == "skip":
                    continue                                    # skipped rows are not scored
                if s not in SETS:
                    problems.append(f"id {row_id}: set '{s}' must be one of {SETS + ['skip']}")
                elif kind not in KINDS or sev not in SEVS:
                    problems.append(f"id {row_id}: truth_kind '{kind}' or truth_severity '{sev}' is missing or mistyped")
                elif (kind == "none") != (sev == "none"):
                    problems.append(f"id {row_id}: kind '{kind}' and severity '{sev}' don't match (none goes with none)")
                elif row_id in labels:
                    problems.append(f"id {row_id}: appears twice across the label files")
                else:
                    labels[row_id] = {"set": s, "truth_kind": kind, "truth_sev": sev}
    if problems:
        sys.exit("Fix these label problems first:\n  " + "\n  ".join(problems))
    return labels


# runs both detectors on one question and answer, returning their verdicts in a dictionary
def score(question, answer):
    # run both frozen detectors on one exchange
    rules = detect_rules.check(question, answer)
    llm = detect_llm.check(question, answer)
    if llm["severity"] == "error":              # one retry, since a failed call isn't a verdict
        llm = detect_llm.check(question, answer)
    return rules, llm

# takes the verdicts from score() and returns a strin to describe the outcome for one row 
# (e.g. "caught by rules only", "missed by both", "false positive (llm)", etc.)
def outcome(r):
    # describe what happened for one row, given the truth label and both verdicts
    if r["llm_flag"] is None:
        return "classifier error"
    if r["truth_kind"] == "none":
        if r["rules_flag"] and r["llm_flag"]:
            return "false positive (both)"
        if r["rules_flag"]:
            return "false positive (rules)"
        if r["llm_flag"]:
            return "false positive (llm)"
        return "clean"
    if r["rules_flag"] and r["llm_flag"]:
        return "caught by both"
    if r["rules_flag"]:
        return "caught by rules only"
    if r["llm_flag"]:
        return "caught by llm only"
    return "missed by both"

# formats a string to fit on one line
def one_line(text, n=90):
    return text.replace("\n", " / ")[:n]

# displays a list of rows with their details
def show(title, rows):
    print(f"\n{title} ({len(rows)})")
    for r in rows:
        print(f"  id {r['id']} [{r['set']}] truth: {r['truth_kind']}/{r['truth_sev']}")
        print(f"     Q: {one_line(r['question'])}")
        print(f"     A: {one_line(r['answer'])}")
        print(f"     rules: {r['rules_sev']}  {r['rules_reasons'] or '-'}")
        print(f"     llm:   {r['llm_sev']}  {r['llm_reason'] or '-'}")

# generates a unique filename for the results file
def free_name(base):
    # never overwrite an earlier results file, because the 'why' column is filled in by hand
    name, n = f"{base}.csv", 2
    while os.path.exists(name):
        name, n = f"{base}_{n}.csv", n + 1
    return name

# orchestrates the evaluation of the frozen detectors against my hand labels, printing raw counts and writing a CSV 
# for me to fill in the "why" column for every miss and false positive
def main():
    labels = load_labels()
    with sqlite3.connect("chat_log.db") as conn:
        logged = {i: (q, a) for i, q, a in conn.execute("SELECT id, question, answer FROM exchanges")}
    missing = [i for i in labels if i not in logged]
    if missing:
        sys.exit(f"These labelled ids aren't in chat_log.db: {missing}")

    results = []
    for n, row_id in enumerate(sorted(labels), start=1):
        question, answer = logged[row_id]
        rules, llm = score(question, answer)
        r = {
            "id": row_id, **labels[row_id], "question": question, "answer": answer,
            "rules_flag": rules["flagged"], "rules_sev": rules["severity"],
            "rules_reasons": "; ".join(rules["reasons"]),
            "llm_flag": llm["flagged"], "llm_sev": llm["severity"],
            "llm_reason": f'{llm["kind"]}: {llm["reason"]}',
        }
        # gives periodic updates on progress, since this can take a while if the label set is large
        r["outcome"] = outcome(r)
        results.append(r)
        if n % 10 == 0:
            print(f"  scored {n} of {len(labels)} rows...")

    # Raw counts, by set and truth kind
    print("\n=== RAW COUNTS (no percentages: the sets are too small) ===")
    for s in SETS:
        for k in KINDS:
            sub = [r for r in results if r["set"] == s and r["truth_kind"] == k]
            if not sub:
                continue
            counts = Counter(r["outcome"] for r in sub)
            ok = [r for r in sub if r["llm_flag"] is not None]
            print(f"\n{s} / truth {k}: {len(sub)} rows")
            print(f"  rules flagged {sum(r['rules_flag'] for r in sub)} of {len(sub)}; "
                  f"llm flagged {sum(r['llm_flag'] for r in ok)} of {len(ok)}")
            print("  " + ", ".join(f"{o}: {c}" for o, c in sorted(counts.items())))

    # Severity calibration on the leaks each layer did flag
    print("\n=== SEVERITY ON LEAKS EACH LAYER FLAGGED (vs my label) ===")
    leaks = [r for r in results if r["truth_kind"] == "leak"]
    for layer, flag_key, sev_key in (("rules", "rules_flag", "rules_sev"), ("llm", "llm_flag", "llm_sev")):
        flagged = [r for r in leaks if r[flag_key]]
        diffs = [SEVS.index(r[sev_key]) - SEVS.index(r["truth_sev"]) for r in flagged]
        print(f"  {layer}: {len(flagged)} flagged, exact {diffs.count(0)}, "
              f"rated lower {sum(d < 0 for d in diffs)}, rated higher {sum(d > 0 for d in diffs)}")

    # Every row that needs a written reason
    show("MISSED BY BOTH LAYERS", [r for r in results if r["outcome"] == "missed by both"])
    show("FALSE POSITIVES", [r for r in results if r["outcome"].startswith("false positive")])
    show("CAUGHT BY ONE LAYER ONLY", [r for r in results if r["outcome"] in ("caught by rules only", "caught by llm only")])
    show("CLASSIFIER ERRORS", [r for r in results if r["outcome"] == "classifier error"])

    out = free_name("eval_results")
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "set", "truth_kind", "truth_severity", "outcome", "rules_flagged", "rules_severity",
                    "llm_flagged", "llm_severity", "question", "answer", "rules_reasons", "llm_reason", "why"])
        for r in results:
            w.writerow([r["id"], r["set"], r["truth_kind"], r["truth_sev"], r["outcome"], r["rules_flag"],
                        r["rules_sev"], r["llm_flag"], r["llm_sev"], r["question"], one_line(r["answer"], 400),
                        r["rules_reasons"], r["llm_reason"], ""])
    print(f"\nWrote {len(results)} rows to {out}. Fill in the 'why' column for every miss and false positive.")


if __name__ == "__main__":
    main()