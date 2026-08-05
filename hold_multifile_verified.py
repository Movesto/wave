"""Hold the shape1_verified vuln records whose commit touched more than one code file.

These records are a single hunk labelled `vuln` because the commit it came from fixed a
CVE. On a commit that touches one file that inference is sound. On a commit that touches
three -- the median here -- the hunk we kept may be an unrelated change that shipped
alongside the fix, and we would be teaching that correct code is vulnerable.

Measured: 571 of 646 vuln records (88%) come from multi-file commits. The same split
explains the 28% CWE agreement against OSV advisories -- if roughly a third of hunks are
the actual vulnerability, roughly a third of the labels come out right. The CWE was the
symptom; this is the cause.

The SAFE side is not held. A post-fix hunk from a real project is safe regardless of
which file in the commit it came from, so the multi-file problem does not make that
label false.

This is the `SINGLE-FILE COMMITS ONLY` constraint that `rebuild_wave3.py` already
enforces for exactly this reason. It was not applied here.

    python hold_multifile_verified.py --write
"""
import argparse
import collections
import csv
import json
import os
import re
import sys

PATCH_DIR = "data/downloads/morefixes-patches/cvedataset-patches"
CACHE = "data/osv/verified_provenance.tsv"
PATH = "data/cot/pilot/shape1_verified.jsonl"
MANIFEST = "data/osv/verified_multifile_held.tsv"


def patch_index():
    out = {}
    for f in os.listdir(PATCH_DIR):
        m = re.match(r"^github\.com_(.+)_([0-9a-f]{40})\.patch$", f)
        if m:
            out[m.group(2)] = f
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    patches = patch_index()
    nfiles = {}

    def files_touched(sha):
        sha = (sha or "").lower()
        if sha not in nfiles:
            f = patches.get(sha)
            n = None
            if f:
                text = open(os.path.join(PATCH_DIR, f), encoding="utf-8",
                            errors="replace").read()
                n = len(set(re.findall(r"^diff --git a/(.+?) b/", text, re.M)))
            nfiles[sha] = n
        return nfiles[sha]

    recs = [json.loads(l) for l in open(PATH, encoding="utf-8") if l.strip()]
    rows, f = [], collections.Counter()
    for i, r in enumerate(recs):
        m = r["_meta"]
        if m.get("held") or m.get("label") == "safe":
            continue
        n = files_touched(m.get("sha"))
        if n is None:
            f["no_patch"] += 1
            continue
        if n == 1:
            f["KEPT_single_file"] += 1
            m["commit_files"] = 1
            continue
        m["held"] = "multifile_commit_hunk"
        m["commit_files"] = n
        rows.append(dict(index=i, repo=m.get("repo", ""), sha=(m.get("sha") or "")[:12],
                         files=n, cwe=m.get("ground_truth_cwe", ""),
                         reason="commit touched %d code files; this hunk is not "
                                "established as the vulnerable one" % n))
        f["HELD_multifile"] += 1

    for k, v in f.most_common():
        print(f"  {k:22s} {v:5d}")
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
