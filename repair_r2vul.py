"""Repair r2vul in place of discarding it. Two mechanical fixes, nothing invented.

    CWE BACKFILL   records with no CWE take the one from the upstream dataset they
                   were matched to. Safe because the cross-check measured 77.7%
                   agreement and 0.1% disagreement where both sides had a label --
                   we are copying a field, not guessing one.

    RECUT EXCERPT  records outside the size limit are re-cut around the lines the
                   trace actually names, so the claim stays visible. If the source
                   or sink would fall outside the window, the record is left alone
                   and reported: a recut that hides the evidence is worse than an
                   oversized excerpt.

The 303 records whose `trace:` line names something absent are NOT auto-rewritten.
Re-picking a source and sink mechanically would leave the prose arguing about one
flow and the claim asserting another. They are labelled for review.

    python repair_r2vul.py --write
"""
import argparse
import collections
import csv
import json
import os
import re
import sys

OUT_DIR = "data/cot/repaired/"
REPORT = "data/osv/r2vul_repair_report.tsv"
MIN_CHARS, MAX_CHARS = 120, 6000


def scan_parts(user_content):
    m = re.search(r"(<SCAN>\n?)(.*?)(\n?</SCAN>)", user_content, re.S)
    if not m:
        return None, user_content, None
    return m.group(1), m.group(2), m.group(3)


def trace_names(assistant):
    m = re.search(r"^trace:\s*(.+)$", assistant, re.M)
    if not m:
        return []
    return [p.strip(" `") for p in re.split(r"->|,", m.group(1)) if p.strip(" `")]


def recut(code, names, budget=MAX_CHARS):
    """Window the excerpt around the lines the trace names."""
    lines = code.splitlines()
    hits = [i for i, l in enumerate(lines)
            if any(re.search(r"(?<![\w])" + re.escape(n.split(".")[-1]) + r"(?![\w])", l)
                   for n in names if len(n.split(".")[-1]) >= 3)]
    if not hits:
        return None
    lo, hi = min(hits), max(hits)
    span = "\n".join(lines[lo:hi + 1])
    if len(span) > budget:
        return None                    # the named lines alone overflow; leave it
    pad = 0
    while True:
        a, b = max(0, lo - pad - 1), min(len(lines), hi + pad + 2)
        cand = "\n".join(lines[a:b])
        if len(cand) > budget:
            a, b = max(0, lo - pad), min(len(lines), hi + pad + 1)
            return "\n".join(lines[a:b])
        if a == 0 and b == len(lines):
            return cand
        pad += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    tri = {}
    for r in csv.DictReader(open("data/osv/r2vul_triage.tsv", encoding="utf-8"),
                            delimiter="\t"):
        tri[(r["shape"], int(r["line"]))] = r

    if args.write:
        os.makedirs(OUT_DIR, exist_ok=True)

    tally, report = collections.Counter(), []
    for d in ("data/cot/pilot/", "data/cot/staging/"):
        for f in sorted(os.listdir(d)):
            if not f.endswith(".jsonl"):
                continue
            shape = f[:-6]
            out, touched = [], False
            for i, line in enumerate(open(d + f, encoding="utf-8")):
                t = tri.get((shape, i))
                if not t:
                    out.append(line)
                    continue
                r = json.loads(line)
                m = r["_meta"]
                acts = []

                if t["verdict"] == "NEEDS_CWE_FIRST" and not m.get("ground_truth_cwe"):
                    up = [c.strip() for c in (t["cwe_upstream"] or "").split("|") if c.strip()]
                    up = [c for c in up if c.upper().startswith("CWE-")]
                    if len(up) == 1:
                        m["ground_truth_cwe"] = up[0]
                        m["cwes"] = up
                        m["cwe_source"] = "r2vul_upstream_backfill"
                        acts.append("cwe_backfilled")
                    elif len(up) > 1:
                        acts.append("cwe_ambiguous_upstream")
                    else:
                        acts.append("cwe_unavailable")

                if t["verdict"] == "RECUT_EXCERPT":
                    pre, body, post = scan_parts(r["messages"][0]["content"])
                    if pre and len(body) > MAX_CHARS:
                        cut = recut(body, trace_names(r["messages"][1]["content"]))
                        if cut and MIN_CHARS <= len(cut) <= MAX_CHARS:
                            r["messages"][0]["content"] = pre + cut + post
                            m["excerpt_recut_from"] = len(body)
                            acts.append("recut")
                        else:
                            acts.append("recut_failed")
                    elif len(body) < MIN_CHARS:
                        acts.append("too_small_to_repair")

                if t["verdict"] == "REGENERATE_TRACE":
                    m["needs_review"] = "R6a: trace names an identifier not in the code"
                    acts.append("labelled_for_review")
                if t["verdict"] == "PROSE_BLEMISH_ONLY":
                    m["note"] = "R6b: claim grounded, prose names an absent identifier"
                    acts.append("flagged_prose")

                for a in acts:
                    tally[a] += 1
                if acts:
                    touched = True
                    report.append(dict(shape=shape, line=i, verdict=t["verdict"],
                                       actions="|".join(acts), cve=t["cve"],
                                       repo=t["repo"], ghost=t["ghost"]))
                out.append(json.dumps(r, ensure_ascii=False) + "\n")

            if args.write and touched:
                with open(OUT_DIR + f, "w", encoding="utf-8") as fh:
                    fh.writelines(out)

    print("repair actions:")
    for k, v in tally.most_common():
        print(f"  {k:26s} {v:6d}")
    if args.write and report:
        with open(REPORT, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(report[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(report)
        print(f"\n-> {OUT_DIR}\n-> {REPORT} ({len(report)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
