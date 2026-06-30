"""Consolidate all v8 training traces into ONE flat file for reasoning-improvement.

Each output record carries the code, the CURRENT reasoning (to be improved by a
stronger model), and the VERIFIED ground truth (label/cwe/oracle) so the rewrite
stays faithful. Feed `data/cot/all_v8_traces.jsonl` to a stronger model, have it
rewrite `current_reasoning` -> `improved_reasoning`, then rebuild_from_improved.py
turns it back into Qwen3-8B training format.
"""
import io, json
from pathlib import Path
from collections import Counter

PILOT = Path("data/cot/pilot")
# The exact shapes v8 trained on.
SHAPES = ["shape1", "shape2", "shape3", "shape4",
          "shape1_ts", "shape1_react", "shape_react_syn",
          "shape1_ts_safe", "shape1_react_safe",
          "shape1_verified", "shape1_verified_safe"]
# Quality tier — which traces most need a stronger model's help.
TIER = {
    "shape1": "expert",            # R2Vul pre-written, already strong
    "shape1_verified": "oracle",   # gate-verified, good
    "shape1_verified_safe": "oracle",
    "shape1_ts": "weak", "shape1_ts_safe": "weak",
    "shape1_react": "weak", "shape1_react_safe": "weak",
    "shape_react_syn": "synthetic",
    "shape2": "context", "shape3": "context", "shape4": "context",
}


def _iter(path):
    with io.open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def main():
    out_path = Path("data/cot/all_v8_traces.jsonl")
    n = 0
    by_shape, by_label, by_tier, by_lang = Counter(), Counter(), Counter(), Counter()
    with io.open(out_path, "w", encoding="utf-8") as out:
        for shape in SHAPES:
            p = PILOT / f"{shape}.jsonl"
            if not p.exists():
                print(f"  WARN missing {p}")
                continue
            for i, rec in enumerate(_iter(p)):
                msgs = rec.get("messages", [])
                if len(msgs) < 2:
                    continue
                meta = rec.get("_meta", {})
                cwes = meta.get("cwes") or ([meta["ground_truth_cwe"]] if meta.get("ground_truth_cwe") else [])
                flat = {
                    "id": f"{shape}:{i}",
                    "shape": shape,
                    "tier": TIER.get(shape, "other"),
                    "source": meta.get("source"),
                    "language": meta.get("language"),
                    "label": meta.get("label"),
                    "cwe": (cwes[0] if cwes else None),
                    "oracle": meta.get("oracle"),
                    "prompt": msgs[0]["content"],            # the <SCAN> code
                    "current_reasoning": msgs[1]["content"],  # what to improve
                }
                out.write(json.dumps(flat, ensure_ascii=False) + "\n")
                n += 1
                by_shape[shape] += 1
                by_label[meta.get("label")] += 1
                by_tier[TIER.get(shape, "other")] += 1
                by_lang[meta.get("language")] += 1
    print(f"\nWrote {n} traces -> {out_path}\n")
    print("by tier (which need improvement most):")
    for k, v in by_tier.most_common():
        print(f"  {k:<12}{v}")
    print("\nby label:")
    for k, v in by_label.most_common():
        print(f"  {str(k):<12}{v}")
    print("\nby language:")
    for k, v in by_lang.most_common():
        print(f"  {str(k):<12}{v}")


if __name__ == "__main__":
    main()
