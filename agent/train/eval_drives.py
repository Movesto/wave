"""Honest eval for the distillation: does a model reach the CERTIFIED verdict on held-out drives?

The gap to close is base-local-model vs. the parent (deepseek) that produced the certified drives. This is the
teacher-FORCED proxy: replay each held-out drive's investigation up to (but not including) its final conclusion,
ask the model to conclude, and compare its verdict to the harness-certified one -- per label, so you see whether
it can confirm real positives AND correctly clear negatives (the contrastive skill). No docker (it doesn't
re-run the tools -- the observations are already in the transcript); it does call the model, so run it against a
served model when you have data + GPU, not concurrently with a live scan. The scoring is deterministic + tested.

Run:  WAVE_API_BASE=... WAVE_MODEL=... python -m agent.train.eval_drives [--in data/trace_sft/eval.jsonl]
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

_VERDICTS = {"confirmed", "refuted", "believed", "blocked", "anomalous_state"}


def _conclude_verdict(msg):
    """The verdict inside an assistant `conclude` tool-call, or None."""
    for tc in (msg.get("tool_calls") or []):
        fn = tc.get("function", {}) if isinstance(tc, dict) else {}
        if fn.get("name") == "conclude":
            raw = fn.get("arguments")
            try:
                args = raw if isinstance(raw, dict) else json.loads(raw or "{}")
            except Exception:
                args = {}
            v = str(args.get("verdict", "")).lower()
            return v if v in _VERDICTS else None
    return None


def forced_case(example):
    """(prefix_messages, expected_verdict): the drive up to its final conclusion + the certified verdict to
    reproduce. Returns None if the drive has no identifiable conclusion to hold out."""
    msgs = example.get("messages") or []
    expected = (example.get("meta") or {}).get("verdict")
    cut = None
    for i in range(len(msgs) - 1, -1, -1):
        if msgs[i].get("role") == "assistant" and _conclude_verdict(msgs[i]):
            cut = i
            expected = expected or _conclude_verdict(msgs[i])
            break
    if cut is None:                                          # no explicit conclude turn -> drop last assistant
        for i in range(len(msgs) - 1, -1, -1):
            if msgs[i].get("role") == "assistant":
                cut = i
                break
    if cut is None or expected not in _VERDICTS:
        return None
    return msgs[:cut], expected


def score(pairs):
    """pairs = [(expected, got)]. Overall + per-label accuracy + a small confusion map."""
    total = len(pairs)
    correct = sum(1 for e, g in pairs if e == g)
    per = defaultdict(lambda: [0, 0])                        # label -> [correct, total]
    confusion = defaultdict(int)
    for e, g in pairs:
        per[e][1] += 1
        if e == g:
            per[e][0] += 1
        else:
            confusion[f"{e}->{g}"] += 1
    return {"total": total, "correct": correct, "accuracy": (correct / total) if total else 0.0,
            "per_label": {k: f"{c}/{t}" for k, (c, t) in per.items()}, "confusion": dict(confusion)}


def run(model, path="data/trace_sft/eval.jsonl", max_new_tokens=800):
    from agent.orchestrator.investigate import _CONCLUDE_TOOL   # reuse the enum-constrained conclude tool
    examples = []
    p = Path(path)
    if p.exists():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                try:
                    examples.append(json.loads(line))
                except Exception:
                    pass
    pairs, skipped = [], 0
    nudge = {"role": "user", "content": "Based only on what you observed above, call conclude with your verdict."}
    for e in examples:
        fc = forced_case(e)
        if fc is None:
            skipped += 1
            continue
        prefix, expected = fc
        try:
            msg = model.chat(prefix + [nudge], tools=[_CONCLUDE_TOOL], temperature=0.0)
            got = _conclude_verdict(msg) or "believed"
        except Exception:
            got = "error"
        pairs.append((expected, got))
    result = score(pairs)
    result["skipped"] = skipped
    return result


def main():
    ap = argparse.ArgumentParser(prog="eval_drives", description=__doc__)
    ap.add_argument("--in", dest="in_path", default="data/trace_sft/eval.jsonl")
    args = ap.parse_args()
    from agent.orchestrator.model import Model
    r = run(Model(), args.in_path)
    print(f"held-out drives: {r['total']} scored ({r['skipped']} skipped)")
    print(f"verdict accuracy: {r['correct']}/{r['total']} = {r['accuracy']:.0%}")
    print(f"  per label: {r['per_label']}")
    if r["confusion"]:
        print(f"  confusion: {r['confusion']}")


if __name__ == "__main__":
    main()
