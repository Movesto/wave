"""Can the C tier be attested after all? Measure it, do not assert it.

I told the user the C tier's provenance was unrecoverable because
`data/sft/morefixes_pairs.jsonl` is messages-only and `CVEFixes.csv` has no provenance
columns. Both facts are true and the conclusion did not follow: the provenance lives in
`data/downloads/morefixes-patches/cvedataset-patches` -- 32,008 raw patch files named
`github.com_{owner}_{repo}_{sha}.patch` -- which is the same corpus that recovered
`shape1_wave3_attested` at 99.8% and put repo+sha back on the contrastive set.

The join is on normalised hunk text, so it only lands if a record's excerpt IS a hunk
from one of those patches. That is why this is a measurement and not a plan.

    python probe_ctier_provenance.py
"""
import collections
import json
import os
import sys

from recover_contrastive_provenance import build_index, norm
from scan_ts_standard import code_of

SHAPES = ("shape1_verified", "shape1_verified_safe", "shape1_ts", "shape1_ts_safe",
          "shape1_react", "shape1_react_safe", "shape1_unique", "shape3", "shape2")


def path_of(shape):
    for d in ("pilot", "staging"):
        p = f"data/cot/{d}/{shape}.jsonl"
        if os.path.exists(p):
            return p
    return None


def main():
    print("building patch index (32,008 patches)...", flush=True)
    idx = build_index()
    print(f"index: {len(idx)} hunks\n", flush=True)

    print(f"{'shape':22s}{'live':>7s}{'matched':>9s}{'rate':>7s}  distinct repos")
    total = matched_total = 0
    for shape in SHAPES:
        p = path_of(shape)
        if not p:
            continue
        recs = [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
        live = [r for r in recs if not r["_meta"].get("held")]
        hits, repos = 0, set()
        for r in live:
            got = idx.get(norm(code_of(r)))
            if got:
                hits += 1
                repos.add(got[0])
        total += len(live)
        matched_total += hits
        print(f"{shape:22s}{len(live):7d}{hits:9d}{100*hits//max(1,len(live)):6d}%  {len(repos)}")
    print(f"\nTOTAL {matched_total}/{total} "
          f"({100*matched_total//max(1,total)}%) C-tier records resolvable to repo+sha")
    return 0


if __name__ == "__main__":
    sys.exit(main())
