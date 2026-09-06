"""Carve an eval that measures what this corpus actually teaches.

`data/cot/eval_v2` is 216 records and **164 of them are C/C++** from PrimeVul, with zero
cross-file and zero counterexample records. Everything built in the corpus rebuild --
attested py/js/ts contrastive pairs, cross-file pairs, guard-present-but-exploitable
counterexamples -- is invisible to it. Training against it would risk the failure that
retired the old 369 bench: a real improvement and a dead metric look the same.

This adds a matched holdout ALONGSIDE eval_v2 (the C/C++ slice stays as a cross-language
control). Carved by REPO, not by record, because that is the only way the disjointness
holds: a different function from a repo the model trained on is still that project, which
is how the first TS/JS holdout leaked (3 code overlaps, 13 repo overlaps).

    selection unit   = repo (or sink_file for codeql, which carries no repo)
    admission rule   = every live record of that repo, corpus-wide, moves to the holdout
    consequence      = zero repo overlap by construction, not by later checking

`shape_codeql_contrastive` has no `repo` on any record -- CodeQL provenance was never
retained -- so its disjointness key is `sink_file`. That is weaker than a repo (two repos
could share a filename) but it is what exists, and the pairs are still code-disjoint by
hash. Recorded here so nobody later reads "repo-disjoint" and assumes it covered codeql.

`shape_crossfile_import` is NOT sampled: 7 pairs total, and holding any out would gut the
only import-verified cross-file data in training. Cross-file eval comes from the codeql
contrastive pairs, which are also `cross_file: True`.

    python build_eval_v3.py            # report the carve
    python build_eval_v3.py --write
"""
import argparse
import collections
import json
import os
import random
import re
import sys
from pathlib import Path

OUT = "data/cot/eval_v2/shape1_eval_v3_matched.jsonl"

# (shape, target pairs) -- proportional to pool size within each capability
ATTESTED = [("shape1_contrastive_attested", 25), ("shape1_contrastive_ts_osv", 8),
            ("shape1_contrastive_r2vul", 4), ("shape1_contrastive_js_osv", 2),
            ("shape1_contrastive_react_osv", 1)]
CROSSFILE = [("shape_codeql_contrastive", 20)]
COUNTEREX = [("shape_counterexample_augment", 7), ("shape_completeness_osv", 3)]
ALL_TARGETS = ATTESTED + CROSSFILE + COUNTEREX


def path_of(shape):
    for d in ("pilot", "staging"):
        p = f"data/cot/{d}/{shape}.jsonl"
        if os.path.exists(p):
            return p
    return None


def wired_shapes():
    src = re.sub(r"#[^\n]*", "", open("train_qwen_cot.py", encoding="utf-8").read())
    block = re.search(r'"shapes":\s*\[(.*?)\]', src, re.S).group(1)
    return re.findall(r'"([\w]+)"', block)


def key_of(meta, shape):
    """The disjointness key: repo normally, sink_file for the codeql set."""
    if shape == "shape_codeql_contrastive":
        return ("file", (meta.get("sink_file") or "").lower())
    repo = (meta.get("repo") or "").lower().replace("_", "/", 1)
    return ("repo", repo) if repo else (None, None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()
    rng = random.Random(1301)

    shapes = wired_shapes()
    # every live record, indexed by shape and by disjointness key
    live = {}
    key_owner = collections.defaultdict(set)      # key -> {shapes it appears in}
    key_count = collections.Counter()             # key -> live records corpus-wide
    for s in shapes:
        p = path_of(s)
        if not p:
            continue
        recs = [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
        live[s] = recs
        for r in recs:
            if r["_meta"].get("held"):
                continue
            k = key_of(r["_meta"], s)
            if k[1]:
                key_owner[k].add(s)
                key_count[k] += 1

    chosen_keys, report = set(), []
    for shape, want in ALL_TARGETS:
        recs = live.get(shape)
        if not recs:
            print(f"  {shape}: MISSING")
            continue
        pairs = collections.defaultdict(list)
        for i, r in enumerate(recs):
            if r["_meta"].get("held"):
                continue
            pid = r["_meta"].get("pair_id")
            if pid:
                pairs[pid].append((i, r))
        # a candidate pair must be complete, and its key must be cheap to remove:
        # used by no other shape, and covering few records corpus-wide
        cands = []
        for pid, items in pairs.items():
            if len(items) != 2:
                continue
            k = key_of(items[0][1]["_meta"], shape)
            if not k[1] or k in chosen_keys:
                continue
            # A key used by SEVERAL shapes is fine -- the move below is corpus-wide, so
            # every record of that repo leaves training together. Rejecting shared keys
            # scored 0 counterexample pairs, because that set is DERIVED from the
            # attested pairs and therefore always shares their repos: the most valuable
            # capability to measure was the one guaranteed to be excluded.
            if key_count[k] > 8:
                continue                      # would drag too much training data out
            cands.append((pid, k, items))
        rng.shuffle(cands)
        took = 0
        for pid, k, items in cands:
            if took >= want:
                break
            chosen_keys.add(k)
            report.append((shape, pid, k, len(items)))
            took += 1
        print(f"  {shape:32s} took {took:3d}/{want:<3d} of {len(cands)} eligible pairs")

    # every live record whose key was chosen leaves training -- not just the sampled pair
    out, moved = [], collections.Counter()
    for s, recs in live.items():
        for r in recs:
            if r["_meta"].get("held"):
                continue
            if key_of(r["_meta"], s) in chosen_keys:
                rec = json.loads(json.dumps(r))
                rec["_meta"]["eval_source_shape"] = s
                out.append(rec)
                moved[s] += 1
                r["_meta"]["held"] = "eval_holdout_v3"

    pid_n = collections.Counter(r["_meta"].get("pair_id") for r in out)
    split = [k for k, v in pid_n.items() if k and v != 2]
    print(f"\nholdout: {len(out)} records from {len(chosen_keys)} keys")
    print("  by shape:", dict(moved))
    print("  incomplete pairs:", split or "none")
    caps = collections.Counter("cross_file" if r["_meta"].get("cross_file") else
                               ("counterexample" if r["_meta"].get("weakness_class")
                                else "contrastive") for r in out)
    print("  capability mix:", dict(caps))
    print("  language mix  :", dict(collections.Counter(
        r["_meta"].get("language") for r in out).most_common(6)))

    if args.write and out:
        with open(OUT, "w", encoding="utf-8") as fh:
            for r in out:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        for s, recs in live.items():
            with open(path_of(s), "w", encoding="utf-8") as fh:
                for r in recs:
                    fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"\n-> {OUT}")
        print("   source shapes rewritten with held: eval_holdout_v3")
    return 0


if __name__ == "__main__":
    sys.exit(main())
