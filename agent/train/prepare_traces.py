"""Turn banked certified drives (traces/wave_traces.jsonl) into SFT training data.

The trace-logger (agent/orchestrator/traces.py) banks ONLY harness-verified drives -- the parent model
(deepseek) driving the tools to a real observed effect, with the harness as the instructor that certifies
each drive. This converts those drives into chat-format SFT examples + a stratified held-out eval split, so
a local model can be fine-tuned to DRIVE THE TOOLS the same way (the distillation plan). It does NO training
and needs no model/GPU -- just clean, deduplicated, balanced data + an honest report of what you have.

Run:  python -m agent.train.prepare_traces [--in traces/wave_traces.jsonl] [--out-dir data/trace_sft]
                                            [--eval-frac 0.15] [--seed 0]
"""
from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from pathlib import Path

_ROLES = {"system", "user", "assistant", "tool"}


def load(path):
    out = []
    p = Path(path)
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def _clean_messages(messages):
    """Validate + normalize a drive's conversation into SFT chat form. Returns the message list, or None if
    it isn't a usable drive (no system prompt, or no assistant turn to learn from)."""
    if not isinstance(messages, list):
        return None
    out = []
    for m in messages:
        if not isinstance(m, dict):
            return None
        role = m.get("role")
        if role not in _ROLES:
            return None
        msg = {"role": role, "content": m.get("content") or ""}
        if role == "assistant" and m.get("tool_calls"):        # keep the tool-driving (what we teach)
            msg["tool_calls"] = m["tool_calls"]
        if role == "tool":                                     # link the observation back to its call
            for k in ("tool_call_id", "name"):
                if m.get(k):
                    msg[k] = m[k]
        out.append(msg)
    has_system = any(m["role"] == "system" for m in out)
    has_assistant = any(m["role"] == "assistant" for m in out)
    return out if (has_system and has_assistant and len(out) >= 3) else None


def _lang_of(file):
    ext = ("." + str(file).rsplit(".", 1)[-1]) if "." in str(file) else ""
    return {".py": "python", ".js": "js", ".mjs": "js", ".ts": "ts", ".tsx": "ts", ".go": "go", ".java": "java",
            ".cs": "c#", ".rb": "ruby", ".php": "php", ".rs": "rust", ".kt": "kotlin", ".swift": "swift",
            ".c": "c", ".cpp": "c++", ".ex": "elixir", ".exs": "elixir"}.get(ext, ext or "?")


def _example(rec):
    """One SFT example from a trace record, or None if unusable."""
    msgs = _clean_messages(rec.get("messages"))
    if msgs is None:
        return None
    return {
        "messages": msgs,
        "meta": {"id": rec.get("id"), "label": rec.get("label"), "verdict": rec.get("verdict"),
                 "class": rec.get("class"), "cwe": rec.get("cwe"), "lang": _lang_of(rec.get("file", "")),
                 "proof_mode": rec.get("proof_mode"), "model": rec.get("model")},
    }


def _split(examples, eval_frac, seed):
    """Stratify the held-out split by label so eval has positives AND negatives (contrastive)."""
    by_label = {}
    for e in examples:
        by_label.setdefault(e["meta"]["label"] or "?", []).append(e)
    rng = random.Random(seed)
    train, ev = [], []
    for label, group in by_label.items():
        rng.shuffle(group)
        n_eval = max(1, round(len(group) * eval_frac)) if len(group) >= 3 else 0
        ev.extend(group[:n_eval])
        train.extend(group[n_eval:])
    rng.shuffle(train)
    rng.shuffle(ev)
    return train, ev


def _stats(examples):
    return {
        "count": len(examples),
        "by_label": dict(Counter(e["meta"]["label"] for e in examples)),
        "by_cwe": dict(Counter(e["meta"]["cwe"] for e in examples)),
        "by_lang": dict(Counter(e["meta"]["lang"] for e in examples)),
        "by_model": dict(Counter(e["meta"]["model"] for e in examples)),
        "avg_turns": round(sum(len(e["messages"]) for e in examples) / len(examples), 1) if examples else 0,
    }


def prepare(in_path="traces/wave_traces.jsonl", out_dir="data/trace_sft", eval_frac=0.15, seed=0):
    recs = load(in_path)
    seen, deduped = set(), []                                  # last write per id wins (a re-proof supersedes)
    for r in reversed(recs):
        rid = r.get("id")
        if rid in seen:
            continue
        seen.add(rid)
        deduped.append(r)
    deduped.reverse()
    examples = [e for e in (_example(r) for r in deduped) if e]
    dropped = len(deduped) - len(examples)
    train, ev = _split(examples, eval_frac, seed)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for name, data in (("train.jsonl", train), ("eval.jsonl", ev)):
        with (out / name).open("w", encoding="utf-8") as f:
            for e in data:
                f.write(json.dumps(e) + "\n")
    report = {"raw": len(recs), "deduped": len(deduped), "usable": len(examples), "dropped_unusable": dropped,
              "train": len(train), "eval": len(ev), "overall": _stats(examples),
              "train_stats": _stats(train), "eval_stats": _stats(ev)}
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def _print_report(r):
    print(f"traces: {r['raw']} raw -> {r['deduped']} deduped -> {r['usable']} usable "
          f"({r['dropped_unusable']} dropped as unusable)")
    o = r["overall"]
    print(f"  labels: {o['by_label']}   (positive=confirmed, negative=refuted, review=anomalous_state)")
    print(f"  langs:  {o['by_lang']}")
    print(f"  cwes:   {o['by_cwe']}")
    print(f"  avg turns/drive: {o['avg_turns']}   models: {o['by_model']}")
    print(f"  -> train {r['train']} / eval {r['eval']}")
    pos = o["by_label"].get("positive", 0)
    neg = o["by_label"].get("negative", 0)
    if r["usable"] < 50:
        print(f"  NOTE: only {r['usable']} usable drives -- keep running with WAVE_TRACE=1 to accumulate before "
              "fine-tuning (a few hundred is a sensible floor).")
    if pos and neg and (max(pos, neg) / max(1, min(pos, neg))) > 3:
        print(f"  NOTE: label imbalance (positive {pos} vs negative {neg}) -- a contrastive mix trains better.")


def main():
    ap = argparse.ArgumentParser(prog="prepare_traces", description=__doc__)
    ap.add_argument("--in", dest="in_path", default="traces/wave_traces.jsonl")
    ap.add_argument("--out-dir", default="data/trace_sft")
    ap.add_argument("--eval-frac", type=float, default=0.15)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    _print_report(prepare(args.in_path, args.out_dir, args.eval_frac, args.seed))


if __name__ == "__main__":
    main()
