"""Strip the r2vul duplicates out of shape1, keep only what is unique AND clean.

shape1 is 69.7% duplicate of shape1_r2vul_clean -- the same records under an older
name, but without the provenance and resolved CWEs the rebuild added. Its unique
remainder is 1,233 records of which only 24% pass the filter, because most of it is
what finalize_r2vul dropped on purpose.

So: keep the unique records that pass, drop the duplicates (present in better form)
and hold the unique-but-failing ones with a reason. Backup written first.

    python carve_shape1_unique.py --write
"""
import argparse
import collections
import csv
import hashlib
import json
import re
import shutil
import sys

from filter_corpus import judge, load_eval_codes
from scan_ts_standard import code_of

SRC = "data/cot/pilot/shape1.jsonl"
CLEAN = "data/cot/staging/shape1_r2vul_clean.jsonl"
OUT = "data/cot/staging/shape1_unique.jsonl"
HELD = "data/osv/shape1_carve_held.tsv"


def norm(code):
    return hashlib.sha1(re.sub(r"\s+", "", code).encode("utf-8", "replace")).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    dup = {norm(code_of(json.loads(l))) for l in open(CLEAN, encoding="utf-8")}
    ev = load_eval_codes()

    keep, held, f = [], [], collections.Counter()
    for i, line in enumerate(open(SRC, encoding="utf-8")):
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not r.get("messages"):
            continue
        f["total"] += 1
        m = r["_meta"]
        if norm(code_of(r)) in dup:
            f["duplicate_of_r2vul_clean"] += 1
            continue
        bad = judge(r, ev, "shape1")
        if bad:
            f["unique_but_fails_filter"] += 1
            held.append(dict(line=i, source=m.get("source", ""),
                             rules="|".join(sorted({x[0] for x in bad})),
                             detail="; ".join(f"{a}:{b}" for a, b in bad)[:120]))
            continue
        m["carved_from"] = "shape1 (r2vul duplicates removed)"
        keep.append(r)
        f["KEPT"] += 1

    for k, v in f.most_common():
        print(f"  {k:28s} {v:6d}")
    src = collections.Counter((r["_meta"].get("source") or "?") for r in keep)
    print(f"\n  kept by source: {dict(src.most_common())}")

    if args.write and keep:
        with open(OUT, "w", encoding="utf-8") as fh:
            for r in keep:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        if not shutil.os.path.exists(SRC + ".pre_carve_bak"):
            shutil.copy2(SRC, SRC + ".pre_carve_bak")
        if held:
            with open(HELD, "w", encoding="utf-8", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=list(held[0].keys()), delimiter="\t")
                w.writeheader()
                w.writerows(held)
        print(f"\n-> {OUT} ({len(keep)} records)\n-> {HELD} ({len(held)} held)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
