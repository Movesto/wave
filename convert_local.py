"""Run Shape 1 conversion through the local Qwen model.

Pulls source records from data/sft/<source>.jsonl, builds the Shape 1 prompt
exactly the way the conversation pipeline does (cot/shapes/shape1.py), sends
each prompt to the local model, routes the response through shape1.verify(),
and appends kept records to data/cot/pilot/shape1.jsonl.

Examples:
    # 50 records from cvefixes safe subset
    python convert_local.py --source cvefixes --label safe --limit 50

    # 200 records from morefixes vuln subset
    python convert_local.py --source morefixes --label vuln --limit 200

    # All sources interleaved (uses shape1.prepare_tasks ordering)
    python convert_local.py --use-prepare-tasks --limit 100

Idempotent: task_ids already in shape1.jsonl.done are skipped.
"""
import argparse
import sys
import time
import json
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from cot.config import PILOT_DIR
from cot.checkpoint import CheckpointWriter
from cot.shapes import shape1
from cot.shapes.common import iter_jsonl, get_messages, extract_scan_code, detect_language, CWE_RE
from cot.generator import call_generator


SOURCE_FILES = {
    "morefixes":    "morefixes_pairs.jsonl",
    "cvefixes":     "cvefixes_pairs.jsonl",
    "bandit":       "bandit_vuln_pairs.jsonl",
    "cybernative":  "cybernative_vuln_pairs.jsonl",
    "kaggle":       "kaggle_vuln_pairs.jsonl",
    "claude_generated": "claude_generated_pairs.jsonl",
    "clean_code":   "clean_code_pairs.jsonl",
}


def _label_from_assistant(asst: str) -> str:
    low = asst.lower()
    if "no vulnerabilities detected" in low or "no security" in low or "looks secure" in low:
        return "safe"
    if "vulnerability detected" in low or "security issue" in low or "security flaw" in low:
        return "vuln"
    if CWE_RE.search(asst):
        return "vuln"
    return "unknown"


def _build_task_from_record(src_name: str, rec: dict, idx: int) -> dict | None:
    msg = get_messages(rec)
    if msg is None:
        return None
    user, asst = msg
    code = extract_scan_code(user)
    if not code or len(code) < 60 or len(code) > 2500:
        return None
    label = _label_from_assistant(asst)
    if label == "unknown":
        return None
    cwe_match = CWE_RE.search(asst)
    cwe = f"CWE-{cwe_match.group(1)}" if cwe_match else None
    return {
        "task_id":   f"shape1:{src_name}_local:{idx}",
        "source":    f"{src_name}_local",
        "language":  detect_language(code),
        "label":     label,
        "cwe":       cwe,
        "code":      code,
        "fixed_code": None,
    }


def iter_tasks_from_source(source: str, label_filter: str | None, limit: int):
    from cot.config import SFT_DIR
    src_file = SOURCE_FILES.get(source)
    if not src_file:
        raise SystemExit(f"Unknown source: {source}. Known: {list(SOURCE_FILES)}")
    path = SFT_DIR / src_file
    if not path.exists():
        raise SystemExit(f"Source file not found: {path}")

    yielded = 0
    for idx, rec in enumerate(iter_jsonl(src_file)):
        if yielded >= limit:
            break
        task = _build_task_from_record(source, rec, idx)
        if task is None:
            continue
        if label_filter and task["label"] != label_filter:
            continue
        yield task
        yielded += 1


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", choices=list(SOURCE_FILES), help="Pull tasks from this data/sft/ source")
    p.add_argument("--label", choices=["vuln", "safe"], default=None, help="Filter to one label")
    p.add_argument("--limit", type=int, default=20, help="How many KEPT records to produce")
    p.add_argument("--use-prepare-tasks", action="store_true",
                   help="Use shape1.prepare_tasks() instead of --source filtering")
    p.add_argument("--max-attempts", type=int, default=None,
                   help="Stop after this many model calls regardless of kept count")
    args = p.parse_args()

    if not args.source and not args.use_prepare_tasks:
        p.error("--source SRC OR --use-prepare-tasks is required")

    if args.use_prepare_tasks:
        # inflate to absorb discards
        tasks = shape1.prepare_tasks(int(args.limit * 1.5) + 10)
    else:
        tasks = list(iter_tasks_from_source(args.source, args.label, int(args.limit * 1.5) + 10))

    out_path = str(PILOT_DIR / "shape1.jsonl")
    print(f"Prepared {len(tasks)} candidate tasks")
    print(f"Output: {out_path}\n")

    stats = {"attempted": 0, "kept": 0, "discarded": 0, "errors": 0}
    started = time.time()

    max_attempts = args.max_attempts or (args.limit * 3)

    with CheckpointWriter(out_path) as w:
        remaining = w.skip_completed(tasks)
        already_done = len(tasks) - len(remaining)
        if already_done:
            print(f"Skipping {already_done} already-done task_ids\n")

        for task in remaining:
            if stats["kept"] >= args.limit:
                break
            if stats["attempted"] >= max_attempts:
                print(f"\nHit max-attempts={max_attempts}; stopping.")
                break

            stats["attempted"] += 1
            system, user = shape1.build_prompt(task)
            try:
                resp = call_generator(user, system=system)
            except Exception as e:
                stats["errors"] += 1
                print(f"  [{task['task_id']}] ERROR: {e}")
                continue

            record = shape1.verify(task, resp["text"])
            if record is None:
                stats["discarded"] += 1
                print(f"  [{task['task_id']}] DISCARDED  (label={task['label']}, lang={task['language']})")
                continue

            w.write(task["task_id"], record)
            stats["kept"] += 1
            elapsed = time.time() - started
            rate = stats["kept"] / elapsed if elapsed else 0
            print(f"  [{task['task_id']}] KEPT  ({stats['kept']}/{args.limit})  "
                  f"out_tokens={resp.get('output_tokens')}  {rate:.2f} rec/s")

    elapsed = time.time() - started
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  kept:        {stats['kept']}")
    print(f"  discarded:   {stats['discarded']}")
    print(f"  errors:      {stats['errors']}")
    print(f"  attempts:    {stats['attempted']}")
    print(f"  wall time:   {elapsed:.1f}s ({stats['attempted']/elapsed:.2f} req/s)")


if __name__ == "__main__":
    main()
