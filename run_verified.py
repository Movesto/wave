"""Run the verified vuln-regeneration with a gate-feedback correction loop.

For each clean patch task: generate a trace, and if it fails a gate, feed the
SPECIFIC failure back to the teacher (grounded in the patch oracle) and retry,
up to --max-attempts. Only gate-passing traces are kept; corrections salvage
near-misses so far less GPU time is wasted on discarded output.

Usage (free local teacher):
    $env:WAVE_GENERATOR_BACKEND="local"
    $env:WAVE_LOCAL_MODEL="openai/gpt-oss-20b"
    $env:WAVE_LOCAL_DTYPE="native"; $env:WAVE_LOCAL_MAX_TOKENS="3000"
    $env:WAVE_VERIFIED_LANGS="typescript,javascript,python"
    python run_verified.py --target 300 --max-attempts 3
"""
import argparse
import json
import sys
import time
from collections import Counter

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from cot.shapes import shape1_verified as S
from cot.checkpoint import CheckpointWriter
from cot.config import PILOT_DIR


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=300, help="kept records wanted")
    ap.add_argument("--max-attempts", type=int, default=3, help="generate + correction tries")
    args = ap.parse_args()

    out_path = str(PILOT_DIR / "shape1_verified.jsonl")
    tasks = S.prepare_tasks(int(args.target * 3) + 50)  # weak teacher -> inflate supply
    print(f"[verified] prepared {len(tasks)} clean patch tasks for target={args.target}")
    print(f"[verified] backend gate-feedback loop, max_attempts={args.max_attempts}\n")

    kept = attempted = total_attempts = 0
    drop_reasons = Counter()
    by_attempt = Counter()
    started = time.time()

    with CheckpointWriter(out_path) as w:
        remaining = w.skip_completed(tasks)
        done = len(tasks) - len(remaining)
        if done:
            print(f"[verified] resuming: {done} task_ids already complete.")
        for i, task in enumerate(remaining, 1):
            if kept >= args.target:
                break
            attempted += 1
            try:
                rec, n_att, fails = S.generate_verified(task, max_attempts=args.max_attempts)
            except Exception as e:
                print(f"[verified] error on {task['task_id']}: {e}")
                continue
            total_attempts += n_att
            if rec is not None:
                w.write(task["task_id"], rec)
                kept += 1
                by_attempt[n_att] += 1
            else:
                S._log_rejection(task, fails)
                drop_reasons[(fails[0].split(':')[0] if fails else '?')] += 1
            if attempted % 10 == 0:
                el = (time.time() - started) / 60
                print(f"[verified] {attempted} tried  kept={kept}  "
                      f"avg_attempts={total_attempts/attempted:.1f}  {el:.0f}m")

    print("\n" + "=" * 60)
    print(f"kept {kept} / {attempted} tried  (yield {kept*100//max(attempted,1)}%)")
    print(f"avg attempts/record: {total_attempts/max(attempted,1):.2f}")
    print(f"kept-by-attempt#: {dict(by_attempt)}  (1 = passed first try)")
    print(f"drop reasons: {dict(drop_reasons)}")
    print(f"output: {out_path}")


if __name__ == "__main__":
    main()
