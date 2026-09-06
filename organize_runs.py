"""Group every training run's artifacts under data/runs/<version>/.

45 loose `data/qwen_cot_*` directories had accumulated -- final and best adapters,
crash rescues, mid-run backups -- with the logs in data/osv/ and the bench results in
data/eval_runs/, so nothing about a version lived in one place.

After this:

    data/runs/v13/
        final/        last-epoch adapter
        best/         selected checkpoint
        logs/         training + bench logs
        bench/        prediction runs for this version
        MANIFEST.md   what produced it, what it scored

Only ARTIFACTS move. The corpus (data/cot/...) is untouched: ~50 scripts reference
those paths and breaking them to tidy directories would be a bad trade.

    python organize_runs.py --dry-run
    python organize_runs.py --write
"""
import argparse
import json
import re
import shutil
import sys
from pathlib import Path

DATA = Path("data")
RUNS = DATA / "runs"

# what each version is, for the manifest
NOTES = {
    "v13": ("SFT, fresh adapter on base Qwen3-8B, 3 epochs, best=epoch 2. "
            "Pair accuracy 30.0/37.5/35.0 by epoch. Gate: 31/77 pairs, but 25/25 of "
            "that was the AUTHORED shape_codeql_contrastive it memorized; 6/52 on real "
            "data, FPR 75%. train_qwen_cot.py"),
    "v14": ("SFT, identical to v13 minus shape_codeql_contrastive (held). "
            "Pair accuracy 0.0/20.0/17.5, best=epoch 2. Gate: 7/52 real pairs, "
            "MCC 0.039 -- at chance, p=0.868 vs v12.1b. train_qwen_cot.py"),
    "v15_dpo": ("DPO on 385 contrastive pairs (1,540 triples) from the v14 adapter. "
                "trl runs were OS-killed 5x; train_dpo_manual.py precomputes the frozen "
                "reference log-probs once and processes one sequence at a time."),
    "v12_1": ("Prior production candidate (v12.1b). Baseline for the v13/v14 gate: "
              "8/52 real pairs, MCC 0.087, FPR 40%."),
}


def version_of(name: str) -> str | None:
    """`qwen_cot_v12_1b_best` -> `v12_1`, `qwen_dpo_v15m` -> `v15_dpo`."""
    if name.startswith("qwen_dpo_v15"):
        return "v15_dpo"
    m = re.match(r"qwen_cot_v(\d+(?:_\d+)?)", name)
    if m:
        return "v" + m.group(1).rstrip("b").rstrip("_") if m.group(1).endswith("b") \
            else "v" + m.group(1)
    if name in ("qwen_cot", "qwen_cot_best"):
        return "v0_unversioned"
    return None


def role_of(name: str) -> str:
    if name.endswith("_best"):
        return "best"
    for tag in ("crashed", "run1_bak", "step200_rescue", "run1", "run2_mid6400", "mid_best"):
        if tag in name:
            return f"variant_{tag}"
    return "final"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    moves = []
    for d in sorted(DATA.glob("qwen_*")):
        if not d.is_dir():
            continue
        ver = version_of(d.name)
        if not ver:
            print(f"  SKIP (unmapped): {d}")
            continue
        moves.append((d, RUNS / ver / role_of(d.name)))

    # logs and bench results follow their version
    for log in sorted(DATA.glob("osv/*.log")):
        m = re.search(r"(v\d+(?:_\d+)?[a-z]?)", log.name)
        if m:
            v = "v15_dpo" if "dpo" in log.name else "v" + m.group(1)[1:].rstrip("b")
            moves.append((log, RUNS / v / "logs"))
    # data/eval_runs is NOT moved: eval_bench.load_run() reads
    # `bench_<label>.raw.jsonl` from there at scoring time, and those files are live
    # working data for the v12.1b/v13/v14 comparison. Tidiness is not worth breaking
    # the scorer.

    by_ver = {}
    for src, dst in moves:
        by_ver.setdefault(dst.parts[2], []).append((src, dst))
    for ver in sorted(by_ver):
        print(f"\n{ver}:")
        for src, dst in by_ver[ver]:
            print(f"    {src}  ->  {dst / src.name}")

    print(f"\n{len(moves)} items across {len(by_ver)} versions")
    if not args.write:
        print("(dry run -- pass --write to apply)")
        return 0

    for src, dst in moves:
        dst.mkdir(parents=True, exist_ok=True)
        target = dst / src.name
        if target.exists():
            print(f"  exists, skipping: {target}")
            continue
        shutil.move(str(src), str(target))
    for ver in sorted(by_ver):
        man = RUNS / ver / "MANIFEST.md"
        if man.exists():
            continue
        note = NOTES.get(ver, "(no notes recorded)")
        man.write_text(f"# {ver}\n\n{note}\n\n## contents\n\n"
                       + "\n".join(f"- `{d.name}/{s.name}`" for s, d in by_ver[ver])
                       + "\n", encoding="utf-8")
    print(f"\nmoved {len(moves)} items -> {RUNS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
