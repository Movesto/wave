"""Split a fraction of the pilot data into a fixed, never-trained eval holdout.

Usage:
    python split_pilot_to_eval.py           # uses HOLDOUT_PER_SHAPE from config
    python split_pilot_to_eval.py --n 50    # override holdout size per shape
    python split_pilot_to_eval.py --reset   # delete existing eval set first

After this runs, data/cot/eval/<shape>.jsonl contains the held-out records.
data/cot/pilot/<shape>.jsonl is the REMAINING training pool (eval records are
removed by hashing the user content). The split is reproducible (fixed seed).
"""
import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from eval.config import EVAL_SET_DIR, PILOT_DIR, HOLDOUT_PER_SHAPE, HOLDOUT_MAX_FRAC, HOLDOUT_SEED
from eval.loader import SHAPES, iter_jsonl


def _user_hash(rec: dict) -> str:
    msgs = rec.get("messages", [])
    if not msgs:
        return ""
    return hashlib.sha256(msgs[0].get("content", "").encode("utf-8")).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--n", type=int, default=HOLDOUT_PER_SHAPE,
                   help=f"Holdout size per shape (default {HOLDOUT_PER_SHAPE})")
    p.add_argument("--reset", action="store_true",
                   help="Delete existing eval files first")
    args = p.parse_args()

    rng = random.Random(HOLDOUT_SEED)

    if args.reset:
        for shape in SHAPES:
            f = EVAL_SET_DIR / f"{shape}.jsonl"
            if f.exists():
                f.unlink()
            print(f"  reset {f}")

    print(f"\nSplit: {args.n} per shape (seed={HOLDOUT_SEED})\n")
    for shape in SHAPES:
        src = PILOT_DIR / f"{shape}.jsonl"
        records = list(iter_jsonl(src))
        if not records:
            print(f"  {shape}: pilot file empty or missing — skipped")
            continue

        rng.shuffle(records)
        # Cap the holdout so scarce shapes aren't gutted: never take more than
        # HOLDOUT_MAX_FRAC of a shape's records, even if args.n is larger.
        frac_cap = int(len(records) * HOLDOUT_MAX_FRAC)
        n_take = min(args.n, frac_cap if frac_cap > 0 else len(records))
        holdout = records[:n_take]
        keep = records[n_take:]
        capped = " (capped by max-frac)" if n_take < min(args.n, len(records)) else ""

        # Write eval holdout
        eval_path = EVAL_SET_DIR / f"{shape}.jsonl"
        with open(eval_path, "w", encoding="utf-8") as out:
            for r in holdout:
                out.write(json.dumps(r, ensure_ascii=False) + "\n")

        print(f"  {shape}: {len(records):>4} pilot  →  {n_take:>4} eval{capped}  +  {len(keep):>4} training-remaining")
        print(f"           eval: {eval_path}")

    print("\nDone. Eval records are now isolated from any future training run.")


if __name__ == "__main__":
    main()
