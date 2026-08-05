"""Move a stratified slice of the vetted TS/JS pairs from training into the eval.

A fresh TS/JS harvest was tried twice and measured: a raw pass over 864 unseen
commits gave 23 pairs of which ~4 were sound, and the vetted-guard route gave 6 of
which 2 were. The pipeline's precision depends on the hand-judging step that
produced the training set (410 candidates -> 244 keeps), and 219 of the 257 vetted
guards come from repos already in training.

So the TS/JS eval comes out of training after all. These pairs are already
hand-vetted, so their quality is known -- which is the property an eval needs most.

HOLD OUT WHOLE REPOS, not individual pairs. Two pairs from one project share helper
names and idioms; splitting a repo across train and eval leaks a hint. Repos are
chosen smallest-first so the fewest training pairs are spent reaching the target.

    python holdout_tsjs_eval.py --target 20 --write
"""
import argparse
import collections
import csv
import json
import os
import shutil
import sys

SETS = ("data/cot/staging/shape1_contrastive_ts_osv.jsonl",
        "data/cot/staging/shape1_contrastive_js_osv.jsonl")
OUT = "data/cot/eval_v2/shape1_eval_tsjs_holdout.jsonl"
MANIFEST = "data/osv/tsjs_holdout_manifest.tsv"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=20)
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    # pair_id -> records, and repo -> pair_ids
    by_pair, by_repo, src_of = collections.defaultdict(list), collections.defaultdict(set), {}
    for path in SETS:
        for line in open(path, encoding="utf-8"):
            r = json.loads(line)
            m = r["_meta"]
            pid = m["pair_id"]
            by_pair[pid].append((path, r))
            by_repo[(m.get("repo") or "?").lower()].add(pid)
            src_of[pid] = path

    langs = {pid: by_pair[pid][0][1]["_meta"].get("language") for pid in by_pair}
    print(f"vetted TS/JS pairs available: {len(by_pair)} across {len(by_repo)} repos")
    print(f"  by language: {dict(collections.Counter(langs.values()))}")

    # A repo is only holdable if NO OTHER training shape uses it. `ts_augment_edits`
    # is DERIVED from ts_osv bases, so holding a base out left its augment behind
    # carrying the same code and repo -- 3 code and 13 repo overlaps on the first
    # attempt. `r2vul_clean` and `completeness_js` collide the same way.
    elsewhere = set()
    for d in ("data/cot/staging/", "data/cot/pilot/"):
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".jsonl") or (d + fn) in SETS:
                continue
            for line in open(d + fn, encoding="utf-8"):
                try:
                    m = json.loads(line).get("_meta") or {}
                except json.JSONDecodeError:
                    continue
                if m.get("repo"):
                    elsewhere.add(m["repo"].lower())
    blocked = {r for r in by_repo if r in elsewhere}
    if blocked:
        print(f"  {len(blocked)} repos excluded -- also used by another training shape")
    by_repo = {r: p for r, p in by_repo.items() if r not in blocked}

    # Smallest repos first: spend the fewest training pairs to reach the target,
    # and keep the big multi-pair repos (which carry the most training signal) whole
    # on the training side.
    order = sorted(by_repo.items(), key=lambda kv: (len(kv[1]), kv[0]))
    chosen_repos, chosen_pairs = [], set()
    want_js = max(4, args.target // 4)          # keep some JS, not TS only
    js_have = 0
    for repo, pids in order:
        if len(chosen_pairs) >= args.target:
            break
        pl = {p: langs[p] for p in pids}
        adds_js = sum(1 for v in pl.values() if v == "javascript")
        if len(chosen_pairs) + len(pids) > args.target and chosen_pairs:
            continue
        chosen_repos.append(repo)
        chosen_pairs |= pids
        js_have += adds_js
    # top up JS if the smallest-first pass under-sampled it
    if js_have < want_js:
        for repo, pids in order:
            if repo in chosen_repos:
                continue
            if all(langs[p] == "javascript" for p in pids):
                chosen_repos.append(repo)
                chosen_pairs |= pids
                js_have += len(pids)
                if js_have >= want_js:
                    break

    held = collections.Counter(langs[p] for p in chosen_pairs)
    print(f"\nholding out {len(chosen_pairs)} pairs from {len(chosen_repos)} repos: "
          f"{dict(held)}")

    eval_recs, manifest = [], []
    keep_by_path = collections.defaultdict(list)
    for path in SETS:
        for line in open(path, encoding="utf-8"):
            r = json.loads(line)
            m = r["_meta"]
            if m["pair_id"] in chosen_pairs:
                m["split"] = "eval"
                m["holdout_reason"] = ("vetted TS/JS pair moved to eval; a fresh "
                                       "harvest yielded too few sound pairs to measure")
                eval_recs.append(r)
            else:
                keep_by_path[path].append(line)
    for pid in sorted(chosen_pairs):
        m = by_pair[pid][0][1]["_meta"]
        manifest.append(dict(pair_id=pid, language=m.get("language", ""),
                             repo=m.get("repo", ""), cwe=m.get("ground_truth_cwe", ""),
                             cve=m.get("cve", ""), from_file=os.path.basename(src_of[pid])))

    for path in SETS:
        kept = len(keep_by_path[path]) // 2
        print(f"  {os.path.basename(path):34s} -> {kept} pairs remain in training")

    if args.write:
        os.makedirs("data/cot/eval_v2", exist_ok=True)
        for path in SETS:
            if not os.path.exists(path + ".pre_holdout_bak"):
                shutil.copy2(path, path + ".pre_holdout_bak")
            with open(path, "w", encoding="utf-8") as fh:
                fh.writelines(keep_by_path[path])
        with open(OUT, "w", encoding="utf-8") as fh:
            for r in eval_recs:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        with open(MANIFEST, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(manifest[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(manifest)
        print(f"\n-> {OUT} ({len(eval_recs)//2} pairs)\n-> {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
