"""Two corrections that follow directly from the provenance recovery.

1. SYNC THE TEXT. `recover_verified_provenance.py` wrote the OSV-authoritative CWE into
   `_meta.ground_truth_cwe` but not into the assistant message, and the assistant message
   is what actually trains. 50 records would have carried a corrected label in metadata
   while still teaching the old wrong one -- worse than not correcting them at all,
   because the metadata would then vouch for text that disagrees with it.

2. HOLD THE EVAL LEAKS. Recovering `repo` made a repo-level leak visible for the first
   time on these shapes: records from a repo that also appears in `data/cot/eval_v2`.
   Code-hash de-leaking does not catch this -- a different function from the same repo
   is still the same project the exam is drawn from, which is how the first TS/JS
   holdout leaked (3 code, 13 repo).

    python fix_verified_after_recovery.py --write
"""
import argparse
import csv
import json
import os
import re
import sys

SHAPES = ("shape1_verified", "shape1_verified_safe")
EVAL_DIR = "data/cot/eval_v2"
MANIFEST = "data/osv/verified_eval_leak_held.tsv"


def path_of(shape):
    for d in ("pilot", "staging"):
        p = f"data/cot/{d}/{shape}.jsonl"
        if os.path.exists(p):
            return p
    return None


def eval_repos():
    out = set()
    for name in os.listdir(EVAL_DIR):
        if not name.endswith(".jsonl"):
            continue
        for line in open(os.path.join(EVAL_DIR, name), encoding="utf-8"):
            if not line.strip():
                continue
            repo = json.loads(line).get("_meta", {}).get("repo")
            if repo:
                # the patch corpus writes `owner_repo`, eval writes `owner/repo`
                out.add(repo.lower())
                out.add(repo.lower().replace("/", "_"))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    ev = eval_repos()
    print(f"eval repos: {len(ev)//2}")
    synced = leaked = 0
    rows = []

    for shape in SHAPES:
        p = path_of(shape)
        recs = [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
        for i, r in enumerate(recs):
            m = r["_meta"]

            was, now = m.get("cwe_was"), m.get("ground_truth_cwe")
            if was and now and was != now:
                msg = r["messages"][1]
                before = msg["content"]
                # The CWE in these traces IS the record's claim, in both the think block
                # ("Confirmed CWE-79") and the verdict line, so every occurrence moves.
                msg["content"] = re.sub(r"\b" + re.escape(was) + r"\b", now, before)
                if msg["content"] != before:
                    synced += 1

            repo = (m.get("repo") or "").lower()
            if repo and repo in ev and not m.get("held"):
                m["held"] = "eval_repo_leak"
                rows.append(dict(shape=shape, index=i, repo=m.get("repo", ""),
                                 sha=m.get("sha", "")[:12],
                                 reason="repo also appears in data/cot/eval_v2; a "
                                        "different function from the same project is "
                                        "still the exam's project"))
                leaked += 1

        if args.write:
            with open(p, "w", encoding="utf-8") as fh:
                for rec in recs:
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"  assistant text synced to corrected CWE: {synced}")
    print(f"  held for eval repo leak:                {leaked}")
    if args.write and rows:
        with open(MANIFEST, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(rows)
        print(f"-> {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
