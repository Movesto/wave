"""Remove from TRAINING any record whose code appears in the held-out eval.

PrimeVul's test split was excluded from `build_contrastive.py` deliberately, but the
same functions arrived by other routes -- r2vul, morefixes patches, cve_fix_pairs --
so 166 training records currently contain eval code. An eval a model has trained on
measures memorisation.

The direction matters: we remove from TRAINING, never from the eval. Shrinking the
eval to fit the training data would be choosing the number over the measurement.

Removals are written to a manifest, and the training files are backed up first.

    python deleak_training.py            # report
    python deleak_training.py --write    # rewrite training files
"""
import argparse
import collections
import csv
import hashlib
import json
import os
import re
import shutil
import sys

from scan_ts_standard import code_of

EVAL_DIRS = ("data/cot/eval_v2/",)
# The full published PrimeVul TEST split, not just the 82 pairs we built from it.
# bench_primevul.py scores all 435 pairs and excludes leaked ones by content hash;
# 63 pairs were being excluded, so the benchmark ran at 85.5% of its real size.
# Removing 47 shipped records restores it to the full published split, which is
# what makes our numbers comparable to the paper's baselines.
EXTRA_HOLDOUT = ("data/downloads/PrimeVul/primevul_test_paired.jsonl",)
TRAIN_DIRS = ("data/cot/staging/", "data/cot/pilot/")
MANIFEST = "data/osv/deleak_manifest.tsv"


def norm(code):
    return hashlib.sha1(re.sub(r"\s+", "", code).encode("utf-8", "replace")).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    evalcodes, evalrepos = {}, set()
    for d in EVAL_DIRS:
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if not f.endswith(".jsonl"):
                continue
            for line in open(d + f, encoding="utf-8"):
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not r.get("messages"):
                    continue
                evalcodes[norm(code_of(r))] = r["_meta"].get("cve", "")
                if r["_meta"].get("repo"):
                    evalrepos.add(r["_meta"]["repo"].lower())
    for path in EXTRA_HOLDOUT:
        if not os.path.exists(path):
            continue
        n0 = len(evalcodes)
        for line in open(path, encoding="utf-8"):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            fn = (r.get("func") or "").strip()
            if len(fn) >= 40:
                evalcodes.setdefault(norm(fn), r.get("cve") or "")
                if r.get("project"):
                    evalrepos.add(str(r["project"]).lower())
        print(f"  +{len(evalcodes)-n0} hashes from {os.path.basename(path)}", flush=True)
    print(f"eval: {len(evalcodes)} distinct code hashes, {len(evalrepos)} repos",
          flush=True)

    removed, by_shape, repo_hits = [], collections.Counter(), collections.Counter()
    for d in TRAIN_DIRS:
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if not f.endswith(".jsonl"):
                continue
            path = d + f
            keep, drop = [], 0
            for i, line in enumerate(open(path, encoding="utf-8")):
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    keep.append(line)
                    continue
                if not r.get("messages"):
                    keep.append(line)
                    continue
                h = norm(code_of(r))
                repo = (r["_meta"].get("repo") or "").lower()
                if h in evalcodes:
                    drop += 1
                    removed.append(dict(shape=f[:-6], line=i, why="code_in_eval",
                                        cve=evalcodes[h], repo=repo))
                    continue
                if repo and repo in evalrepos:
                    repo_hits[f[:-6]] += 1
                keep.append(line)
            if drop:
                by_shape[f[:-6]] = drop
                if args.write:
                    if not os.path.exists(path + ".pre_deleak_bak"):
                        shutil.copy2(path, path + ".pre_deleak_bak")
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.writelines(keep)

    print("\nrecords removed from TRAINING (code present in eval):")
    for k, v in by_shape.most_common():
        print(f"  {k:34s} {v:5d}")
    print(f"  {'TOTAL':34s} {sum(by_shape.values()):5d}")

    if repo_hits:
        print("\nSAME-REPO overlap (kept, but the eval is not fully independent):")
        for k, v in repo_hits.most_common(10):
            print(f"  {k:34s} {v:5d} records share a repo with the eval")

    if args.write and removed:
        with open(MANIFEST, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(removed[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(removed)
        print(f"\n-> {MANIFEST} ({len(removed)} rows); .pre_deleak_bak written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
