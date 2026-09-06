"""Hold the CodeQL localize records whose flow cannot be followed from the excerpt.

The task is "name the source, the sink, and the path between them". That is answerable
from the excerpt -- which is why the set survives the no-C-grade rule -- but only when
the files the path names are actually shown. On 39% of records the stated path steps
through a file that is not in the excerpt, so the correct answer is not derivable from
what the model is given. Training on those teaches it to produce a path it cannot see,
which is the same failure as an unverifiable verdict.

The 61% that remain are kept: they are the only interprocedural data in the corpus
(99.8% multi-file), and their answer is checkable against the two files shown.

Not dropped -- held with a reason, so if the excerpts are ever re-carved to include the
whole path these come back.

    python hold_unfollowable_codeql.py --write
"""
import argparse
import collections
import csv
import json
import re
import sys

PATH = "data/cot/staging/shape3_codeql_localize.jsonl"
MANIFEST = "data/osv/codeql_unfollowable_held.tsv"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    recs = [json.loads(l) for l in open(PATH, encoding="utf-8") if l.strip()]
    rows, f = [], collections.Counter()
    for i, r in enumerate(recs):
        m = r.setdefault("_meta", {})
        if m.get("held"):
            continue
        user = r["messages"][0]["content"]
        ans = r["messages"][1]["content"]
        shown = {p.split("/")[-1] for p in re.findall(r"^# (\S+) \(line", user, re.M)}
        pl = re.search(r"^path[^:]*: (.+)$", ans, re.M)
        if not pl:
            m["held"] = "no_path_stated"
            rows.append(dict(index=i, missing="", reason="record states no path"))
            f["no_path"] += 1
            continue
        named = {x.split(":")[0] for x in re.findall(r"([\w./-]+:\d+)", pl.group(1))}
        missing = sorted(named - shown)
        if missing:
            m["held"] = "path_not_in_excerpt"
            rows.append(dict(index=i, missing=";".join(missing)[:120],
                             reason="path steps through files not shown to the model"))
            f["HELD_unfollowable"] += 1
        else:
            f["KEPT_followable"] += 1

    for k, v in f.most_common():
        print(f"  {k:24s} {v:6d}")
    if args.write:
        with open(PATH, "w", encoding="utf-8") as fh:
            for r in recs:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        with open(MANIFEST, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(rows)
        print(f"-> {MANIFEST} ({len(rows)} held)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
