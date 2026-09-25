"""Quality gate for the distillation SFT dataset (agent/train/prepare_traces output).

Bad training DATA -- not the recipe -- is where past runs failed. This checks each prepared drive is actually
trainable BEFORE any GPU time: valid chat structure, tool-call/observation linkage, no empty assistant turns
(nothing to learn), and length sanity. Deterministic, no model/GPU. Returns per-example issues + a pass rate;
exits non-zero if anything is broken so it can gate a training script.

Run:  python -m agent.train.validate_dataset [--in data/trace_sft/train.jsonl] [--max-tokens 8000]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def _est_tokens(messages):
    return sum(len(str(m.get("content") or "")) + len(json.dumps(m.get("tool_calls") or ""))
               for m in messages) // 4                       # ~4 chars/token, good enough for a length gate


def _tc_ids(msg):
    ids = []
    for tc in msg.get("tool_calls") or []:
        if isinstance(tc, dict):
            ids.append(tc.get("id"))
    return ids


def check_example(e, max_tokens=8000):
    """Return a list of problem strings for one SFT example (empty = clean)."""
    problems = []
    msgs = e.get("messages")
    if not isinstance(msgs, list) or not msgs:
        return ["no messages"]
    if msgs[0].get("role") != "system":
        problems.append("does not start with a system message")
    if not any(m.get("role") == "assistant" for m in msgs):
        problems.append("no assistant turn (nothing to train on)")
    open_calls = set()
    for i, m in enumerate(msgs):
        role = m.get("role")
        if role == "assistant":
            has_content = bool(str(m.get("content") or "").strip())
            has_calls = bool(m.get("tool_calls"))
            if not has_content and not has_calls:
                problems.append(f"empty assistant turn at #{i} (no content, no tool_calls)")
            for cid in _tc_ids(m):
                if cid:
                    open_calls.add(cid)
        elif role == "tool":
            if not str(m.get("content") or "").strip():
                problems.append(f"empty tool result at #{i}")
            cid = m.get("tool_call_id")
            if cid and cid not in open_calls and not m.get("name"):
                problems.append(f"tool result at #{i} not linked to any prior tool_call")
    toks = _est_tokens(msgs)
    if toks > max_tokens:
        problems.append(f"~{toks} tokens > {max_tokens} (will truncate; window this drive)")
    return problems


def validate(path, max_tokens=8000):
    p = Path(path)
    examples = []
    if p.exists():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line:
                try:
                    examples.append(json.loads(line))
                except Exception:
                    examples.append({"_parse_error": True})
    total, clean, issues = len(examples), 0, []
    kinds = Counter()
    for e in examples:
        if e.get("_parse_error"):
            issues.append((None, "invalid JSON line"))
            kinds["parse_error"] += 1
            continue
        probs = check_example(e, max_tokens)
        if probs:
            issues.append((e.get("meta", {}).get("id"), "; ".join(probs)))
            for pr in probs:
                kinds[pr.split(" at ")[0].split(" (")[0][:32]] += 1
        else:
            clean += 1
    return {"total": total, "clean": clean, "bad": total - clean,
            "pass_rate": (clean / total) if total else 1.0, "issue_kinds": dict(kinds),
            "issues": issues[:50]}


def main():
    ap = argparse.ArgumentParser(prog="validate_dataset", description=__doc__)
    ap.add_argument("--in", dest="in_path", default="data/trace_sft/train.jsonl")
    ap.add_argument("--max-tokens", type=int, default=8000)
    args = ap.parse_args()
    r = validate(args.in_path, args.max_tokens)
    print(f"dataset: {r['total']} examples -> {r['clean']} clean / {r['bad']} with issues "
          f"({r['pass_rate']:.0%} pass)")
    if r["issue_kinds"]:
        print("  issue kinds:", r["issue_kinds"])
    for rid, prob in r["issues"][:20]:
        print(f"  [{rid}] {prob}")
    sys.exit(0 if r["bad"] == 0 else 1)                       # non-zero so a training script can gate on it


if __name__ == "__main__":
    main()
