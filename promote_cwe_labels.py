"""Promote the CWE label that is already in the record but in the wrong field.

999 records carry a single-element `cwes` list while `ground_truth_cwe` is empty. The
scanner, the trainer and the corpus audit all read `ground_truth_cwe`, so a populated
label read as "no label" and those shapes were graded as unlabelled. Nothing is being
invented here -- the value is copied from the field the upstream builder wrote it to.

PROVENANCE, so this is not mistaken for attestation later: these are MoreFixes/CVEFixes
labels, ultimately NVD's CWE for the CVE. They are NOT verified by us against the diff,
so they get `cwe_source: upstream_dataset`, which sits BELOW cisa_vulnrichment and
osv_advisory in the hierarchy. Only CISA/OSV-sourced records may be called attested.

Two things are deliberately NOT promoted:

  * multi-element `cwes` (shape4 carries 8 per record) -- that is a findings list for a
    synthesis task, not a ground truth for one excerpt.
  * the CWE-1000-series QUALITY categories (CWE-1135 "Inappropriate Whitespace Style",
    CWE-1136, CWE-1138). Those are code-style rules, not vulnerabilities. A record whose
    ground truth is a lint rule teaches that lint findings are vulnerabilities, which is
    the false-positive behaviour this project exists to avoid. They are HELD, not
    dropped, and written to a manifest with their CWE.

    python promote_cwe_labels.py --write
"""
import argparse
import collections
import csv
import json
import os
import re
import sys

SHAPES = ("shape1_verified", "shape1_verified_safe", "shape1_ts", "shape1_ts_safe",
          "shape1_react", "shape1_react_safe", "shape2", "shape3", "shape4",
          "shape1_unique", "shape_react_syn")
HELD_MANIFEST = "data/osv/cwe_nonsecurity_held.tsv"

# CWE-1000..CWE-1199 is the "Software Quality" pillar -- maintainability and style, not
# exploitability. Checked by hand against the ones actually present: 1135 (whitespace
# style), 1136 (whitespace in source), 1138 (inappropriate whitespace).
QUALITY_CWE = re.compile(r"^CWE-1(?:0\d\d|1\d\d)$")


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

    f = collections.Counter()
    held_rows = []
    promoted_cwes = collections.Counter()

    for shape in SHAPES:
        path = path_of(shape)
        if not path:
            continue
        recs = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
        changed = 0
        for i, r in enumerate(recs):
            m = r.setdefault("_meta", {})
            if m.get("ground_truth_cwe"):
                f["already_labelled"] += 1
                continue
            cwes = m.get("cwes")
            if not isinstance(cwes, list) or len(cwes) != 1:
                f["not_single_cwe"] += 1
                continue
            cwe = str(cwes[0]).strip().upper()
            if not re.fullmatch(r"CWE-\d+", cwe):
                f["malformed_cwe"] += 1
                continue
            if QUALITY_CWE.match(cwe):
                m["held"] = "nonsecurity_cwe"
                held_rows.append(dict(
                    shape=shape, index=i, cwe=cwe,
                    reason="CWE-1000-series software-quality category (style/"
                           "maintainability), not a vulnerability class"))
                f["HELD_nonsecurity"] += 1
                changed += 1
                continue
            m["ground_truth_cwe"] = cwe
            m["cwe_source"] = "upstream_dataset"
            promoted_cwes[cwe] += 1
            f["PROMOTED"] += 1
            changed += 1
        if changed and args.write:
            with open(path, "w", encoding="utf-8") as fh:
                for r in recs:
                    fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        if changed:
            print(f"  {shape:22s} {changed:5d} records updated  -> {path}")

    print()
    for k, v in f.most_common():
        print(f"  {k:24s} {v:6d}")
    print("  top promoted CWEs:", dict(promoted_cwes.most_common(8)))

    if args.write and held_rows:
        os.makedirs(os.path.dirname(HELD_MANIFEST), exist_ok=True)
        with open(HELD_MANIFEST, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(held_rows[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(held_rows)
        print(f"\n-> {HELD_MANIFEST} ({len(held_rows)} held)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
