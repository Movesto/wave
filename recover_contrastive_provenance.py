"""Recover repo+sha for the 12,390 `origin: real` contrastive records.

The investigation into what `origin: real` actually is turned up two things.

1. It is three sub-sources -- raw git patches, morefixes, cve_fix_pairs -- and the
   patch files are named `github.com_{owner}_{repo}_{sha}.patch`. The loader even
   captures it (`"source": f"patch:{fname[:40]}"`), but build_contrastive.py then
   overwrites `source` with the literal "contrastive" and the lineage is lost.
   Nothing is missing upstream; it was discarded in transit.

2. The CWE on these records is ALWAYS derived, never authoritative:
       _from_morefixes      "cwe": None  -> classify(vuln_code)
       _from_patches        "cwe": None  -> classify(vuln_code)
       _from_cve_fix_pairs  _type_to_cwe(row["vulnerability_type"])
   which is why reading found an integer-overflow check labelled CWE-89.

Re-running the extraction and matching on the hunk text puts repo+sha back, and a
sha is enough to look the real CWE up later instead of trusting the classifier.

    python recover_contrastive_provenance.py --write
"""
import argparse
import collections
import csv
import hashlib
import json
import os
import re
import sys

SRC = "data/cot/staging/shape1_contrastive.jsonl"
OUT = "data/osv/contrastive_provenance.tsv"
PATCH_DIR = "data/downloads/morefixes-patches/cvedataset-patches"

_NAME = re.compile(r"^github\.com_(.+)_([0-9a-f]{40})\.patch$")


def norm(code):
    return hashlib.sha1(re.sub(r"\s+", "", code).encode("utf-8", "replace")).hexdigest()


def build_index():
    """norm(hunk) -> (repo, sha), replaying the loader's own extraction."""
    from cot.fix_pairs import (_EXT_LANG, _RELEVANT, _SKIP_PATH, _TEST_PATH,
                               _reconstruct_hunks)
    idx = {}
    files = sorted(f for f in os.listdir(PATCH_DIR) if f.endswith(".patch"))
    for n, fname in enumerate(files):
        if n % 5000 == 0:
            print(f"  {n}/{len(files)} patches, {len(idx)} hunks", flush=True)
        m = _NAME.match(fname)
        if not m:
            continue
        owner_repo, sha = m.group(1), m.group(2)
        try:
            text = open(os.path.join(PATCH_DIR, fname), encoding="utf-8",
                        errors="replace").read()
        except OSError:
            continue
        for part in re.split(r"^diff --git ", text, flags=re.M)[1:]:
            head = re.match(r"a/(.+?) b/(.+?)\s*$", part.split("\n", 1)[0])
            if not head:
                continue
            path_b = head.group(2)
            ext = "." + path_b.rsplit(".", 1)[-1] if "." in path_b else ""
            if not _EXT_LANG.get(ext):
                continue
            if _TEST_PATH.search(path_b) or _SKIP_PATH.search(path_b):
                continue
            for old_hunk, new_hunk in _reconstruct_hunks(part):
                if old_hunk == new_hunk or not (80 <= len(old_hunk) <= 1500):
                    continue
                if not (_RELEVANT.search(old_hunk) or _RELEVANT.search(new_hunk)):
                    continue
                for h in (old_hunk, new_hunk):
                    idx.setdefault(norm(h), (owner_repo, sha, path_b))
    return idx


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    print("indexing patch files...", flush=True)
    idx = build_index()
    print(f"index: {len(idx)} distinct hunks\n", flush=True)

    from scan_ts_standard import code_of
    rows, tally = [], collections.Counter()
    for line in open(SRC, encoding="utf-8"):
        r = json.loads(line)
        m = r["_meta"]
        if m.get("origin") != "real":
            tally[f"skip:{m.get('origin')}"] += 1
            continue
        hit = idx.get(norm(code_of(r)))
        if not hit:
            tally["no_match"] += 1
            continue
        repo, sha, path = hit
        tally["MATCHED"] += 1
        rows.append(dict(pair_id=m["pair_id"], label=m["label"],
                         language=m.get("language", ""),
                         cwe_derived=m.get("ground_truth_cwe", ""),
                         repo=repo.replace("_", "/", 1), sha=sha, src_file=path))

    for k, v in tally.most_common():
        print(f"  {k:22s} {v:6d}")
    if rows:
        pids = {r["pair_id"] for r in rows}
        print(f"\n  distinct pairs with recovered lineage: {len(pids)}")
    if args.write and rows:
        with open(OUT, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(rows)
        print(f"\n-> {OUT} ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
