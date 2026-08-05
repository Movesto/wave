"""Hold every record that makes a SECURITY VERDICT it cannot support.

The standard: a record may claim `vuln` or `safe` only if that claim can be checked --
either against an outside authority (a CVE with a CISA/OSV CWE) or from the excerpt
itself. Anything else is the model being taught to assert something nobody can verify,
which is the exact failure this project exists to avoid.

That splits the corpus in a way that does NOT map to "has provenance":

  KEPT, no provenance, still verifiable -- the task's correct answer is derivable from
  the excerpt in front of it:
      shape3_codeql_localize   where does this flow go (the flow is in the excerpt)
      shape1_localize          which line is the sink
      shape1_fixgen            produce the fix for the shown code
      shape2                   the helper is not shown, so the answer IS "needs context"
      shape3                   caller and callee are both in the excerpt
      shape4                   synthesis over findings that are listed above it

  HELD, makes a vuln/safe call nothing can check:
      shape1_ts, shape1_ts_safe, shape1_react, shape1_react_safe, shape1_unique
      and the records of shape1_verified / shape1_verified_safe with no CVE.

The evidence that these are not merely unlabelled but WRONG: their CWEs come from
`upstream_dataset` (MoreFixes/NVD, applied per hunk), and where OSV could resolve the
advisory those labels agreed only 28% of the time -- consistent with the 19.7% measured
for classifier CWEs. A record whose CWE is wrong ~70% of the time is teaching the wrong
weakness class along with an unverifiable verdict.

Held, not deleted: every record keeps a reason and appears in the manifest, so this is
reversible if provenance is ever recovered for them (see `probe_ctier_provenance.py` --
the TS/react sets matched the patch corpus at only 2-6%).

    python hold_unattested_verdicts.py --write
"""
import argparse
import collections
import csv
import json
import os
import sys

FULL = ("shape1_ts", "shape1_ts_safe", "shape1_react", "shape1_react_safe",
        "shape1_unique")
BY_RECORD = ("shape1_verified", "shape1_verified_safe")
MANIFEST = "data/osv/unattested_verdict_held.tsv"


def path_of(shape):
    for d in ("pilot", "staging"):
        p = f"data/cot/{d}/{shape}.jsonl"
        if os.path.exists(p):
            return p
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    rows, f = [], collections.Counter()
    for shape in FULL + BY_RECORD:
        path = path_of(shape)
        if not path:
            continue
        recs = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
        changed = 0
        for i, r in enumerate(recs):
            m = r.setdefault("_meta", {})
            if m.get("held"):
                continue
            if shape in BY_RECORD and m.get("cve"):
                f[f"{shape}_kept_attested"] += 1
                continue
            m["held"] = "unattested_verdict"
            rows.append(dict(shape=shape, index=i, label=m.get("label", ""),
                             cwe=m.get("ground_truth_cwe", ""),
                             cwe_source=m.get("cwe_source", ""),
                             reason="security verdict with no CVE and no in-excerpt "
                                    "basis; CWE (where present) is upstream_dataset, "
                                    "measured 28% agreement with OSV advisories"))
            changed += 1
            f["HELD"] += 1
        if changed and args.write:
            with open(path, "w", encoding="utf-8") as fh:
                for r in recs:
                    fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        if changed:
            print(f"  {shape:24s} {changed:5d} held")

    print()
    for k, v in f.most_common():
        print(f"  {k:30s} {v:5d}")
    if args.write and rows:
        with open(MANIFEST, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(rows)
        print(f"-> {MANIFEST} ({len(rows)} held)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
