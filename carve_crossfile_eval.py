"""Split harvested cross-file pairs into an eval holdout and a training file.

Splits by PAIR, never by record: if the vuln side were trained on and the safe
side evaluated, the model would have seen the code and the eval would be leaked.
Splitting whole pairs keeps both sides on the same side of the wall.

Also splits by REPO, so no repository appears in both train and eval — two CVE
fixes in one project share idioms, and repo-level bleed is how a holdout quietly
stops being held out.

  python carve_crossfile_eval.py --eval-frac 0.4
"""
import argparse
import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path

SRC = Path("data/cot/pilot/shape3_crossfile_pairs.jsonl")
EVAL_OUT = Path("data/cot/eval/shape3_crossfile_pairs.jsonl")
TRAIN_OUT = Path("data/cot/pilot_clean/shape3_crossfile_pairs.jsonl")


def norm(text: str) -> str:
    return " ".join(text.split()).lower()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval-frac", type=float, default=0.4,
                    help="fraction of pairs held out (default 0.4 — the eval is "
                         "the point of this data, so it gets a big share)")
    ap.add_argument("--seed", type=int, default=13)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not SRC.exists():
        raise SystemExit(f"no harvested pairs at {SRC}")

    by_pair: dict[str, dict] = defaultdict(dict)
    for line in open(SRC, encoding="utf-8"):
        rec = json.loads(line)
        by_pair[rec["_meta"]["pair_id"]][rec["_meta"]["label"]] = rec

    complete, incomplete = {}, 0
    for pid, sides in by_pair.items():
        if "vuln" in sides and "safe" in sides:
            complete[pid] = sides
        else:
            incomplete += 1

    # Drop pairs whose two sides are identical after normalisation — the "fix"
    # was whitespace, so the pair teaches nothing. Same defect build_contrastive
    # hit; re-checked here because this builder is newer.
    cosmetic = [pid for pid, s in complete.items()
                if norm(s["vuln"]["messages"][0]["content"]) == norm(s["safe"]["messages"][0]["content"])]
    for pid in cosmetic:
        del complete[pid]

    by_repo: dict[str, list[str]] = defaultdict(list)
    for pid, sides in complete.items():
        by_repo[sides["vuln"]["_meta"].get("repo", pid)].append(pid)

    repos = sorted(by_repo)
    random.Random(args.seed).shuffle(repos)
    target = int(len(complete) * args.eval_frac)
    eval_pids: set[str] = set()
    for repo in repos:
        if len(eval_pids) >= target:
            break
        eval_pids.update(by_repo[repo])

    eval_recs, train_recs = [], []
    for pid, sides in complete.items():
        bucket = eval_recs if pid in eval_pids else train_recs
        bucket.extend([sides["vuln"], sides["safe"]])

    print(f"harvested pairs      {len(by_pair)}")
    print(f"  incomplete dropped {incomplete}")
    print(f"  cosmetic dropped   {len(cosmetic)}")
    print(f"  usable pairs       {len(complete)}  across {len(by_repo)} repos")
    print(f"eval  {len(eval_pids)} pairs / {len(eval_recs)} records -> {EVAL_OUT}")
    print(f"train {len(complete)-len(eval_pids)} pairs / {len(train_recs)} records -> {TRAIN_OUT}")

    langs = defaultdict(int)
    cwes = defaultdict(int)
    for pid in eval_pids:
        m = complete[pid]["vuln"]["_meta"]
        langs[m["language"]] += 1
        cwes[m["ground_truth_cwe"]] += 1
    print(f"  eval langs {dict(langs)}")
    print(f"  eval CWEs  {dict(sorted(cwes.items(), key=lambda x: -x[1]))}")

    if args.dry_run:
        print("\n(dry run — nothing written)")
        return

    for path, recs in ((EVAL_OUT, eval_recs), (TRAIN_OUT, train_recs)):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for rec in recs:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print("\nwritten. Next: register shape3_crossfile_pairs in eval/loader.py SHAPES "
          "and in train_qwen_cot.py CONFIG (shapes + weight) before the next run.")


if __name__ == "__main__":
    main()
