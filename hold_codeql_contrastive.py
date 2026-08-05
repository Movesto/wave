"""Hold `shape_codeql_contrastive`: it taught a memorizable pattern, not cross-file reasoning.

Measured on v13 (80-pair eval, v12.1b as baseline):

    slice                  v12.1b      v13     delta
    ALL pairs              9/75       31/75     +22
      codeql cross-file    0/25       25/25     +25   <- the entire gain
      everything else      9/50        6/50      -3
    McNemar on non-codeql records (n=107): p = 0.883  -- no difference
    FPR on real safe code: 40% -> 75%

25 of 25 pairs correct, both sides, MCC 1.000 -- while the model was below chance on
everything else. That is not cross-file reasoning; the safe side of every pair in this
shape was AUTHORED, differing from its vulnerable twin by one inserted guard drawn from
a handful of per-CWE templates (`os.path.isabs(...) or ".." in normpath(...)`,
`shlex.quote(...)`, `replace("\\r","")`). The model learned "that string is present =>
safe" and never had to read the flow.

Worse than useless: the false-positive rate on REAL safe code nearly doubled. Having
learned a specific token pattern for "safe", the model appears to treat its absence as
evidence of vulnerability -- so the shape added to fix the always-vuln bias made it
worse everywhere it could not pattern-match.

The risk was named in `build_codeql_safe.py`'s own docstring ("a sanitiser appears =>
safe") and the mitigation -- naming the real variable, a few formulations per class --
was nowhere near sufficient. The standard every other shape is held to is that the code
is REAL; this shape was exempted from that, and it is exactly where it failed.

The eval holdout keeps its codeql pairs. With the training shape held they become a
genuinely unseen cross-file test: if the next run scores near chance there, that is an
honest measurement of cross-file ability rather than recall of an inserted string.

    python hold_codeql_contrastive.py --write
"""
import argparse
import csv
import json
import sys

PATH = "data/cot/staging/shape_codeql_contrastive.jsonl"
MANIFEST = "data/osv/codeql_contrastive_held.tsv"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    recs = [json.loads(l) for l in open(PATH, encoding="utf-8") if l.strip()]
    rows = []
    n = 0
    for r in recs:
        m = r.setdefault("_meta", {})
        if m.get("held"):
            continue
        m["held"] = "authored_guard_memorized"
        rows.append(dict(pair_id=m.get("pair_id", ""), cwe=m.get("ground_truth_cwe", ""),
                         label=m.get("label", ""), sink_var=m.get("sink_var", ""),
                         reason="authored safe side; v13 scored 25/25 here and below "
                                "chance elsewhere, and FPR on real safe code went "
                                "40%->75%"))
        n += 1
    print(f"holding {n} records ({n // 2} pairs)")
    if args.write:
        with open(PATH, "w", encoding="utf-8") as fh:
            for r in recs:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        with open(MANIFEST, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(rows)
        print(f"-> {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
