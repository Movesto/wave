"""Rebuild Qwen3-8B training files from stronger-model-improved traces.

Input: a JSONL like all_v8_traces.jsonl but with an added `improved_reasoning`
field (from the stronger model). Records without it fall back to the original
reasoning, so you can improve a SUBSET (e.g. just the weak/synthetic tiers) and
still rebuild the full corpus.

Output: per-shape JSONL in data/cot/pilot_v9/ in the exact training schema
(messages + _meta). Point training at it with WAVE_PILOT_DIR or by swapping dirs.
"""
import io, json, sys
from pathlib import Path
from collections import Counter

SRC = Path(sys.argv[1] if len(sys.argv) > 1 else "data/cot/all_v8_traces.jsonl")
OUT = Path("data/cot/pilot_v9")
OUT.mkdir(parents=True, exist_ok=True)


def _iter(path):
    with io.open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def main():
    buckets, used_improved, used_original = {}, Counter(), Counter()
    for rec in _iter(SRC):
        shape = rec["shape"]
        reasoning = rec.get("improved_reasoning") or rec.get("current_reasoning")
        if rec.get("improved_reasoning"):
            used_improved[shape] += 1
        else:
            used_original[shape] += 1
        cwes = [rec["cwe"]] if rec.get("cwe") else []
        out_rec = {
            "messages": [
                {"role": "user", "content": rec["prompt"]},
                {"role": "assistant", "content": reasoning},
            ],
            "_meta": {
                "shape": "shape1" if shape.startswith("shape1") else shape,
                "source": rec.get("source"),
                "language": rec.get("language"),
                "label": rec.get("label"),
                "cwes": cwes,
                "ground_truth_cwe": rec.get("cwe"),
                "oracle": rec.get("oracle"),
                "improved": bool(rec.get("improved_reasoning")),
            },
        }
        buckets.setdefault(shape, []).append(out_rec)

    for shape, recs in buckets.items():
        p = OUT / f"{shape}.jsonl"
        with io.open(p, "w", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"  {shape:<24}{len(recs):>5}  (improved={used_improved[shape]}, original={used_original[shape]})")
    total = sum(len(v) for v in buckets.values())
    print(f"\nRebuilt {total} traces -> {OUT}/  "
          f"({sum(used_improved.values())} improved, {sum(used_original.values())} kept original)")
    print("Train on it with:  WAVE_PILOT_DIR=data/cot/pilot_v9 python train_qwen_cot.py")


if __name__ == "__main__":
    main()
