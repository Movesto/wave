"""PrimeVul pair-accuracy eval -- the AEGIS/DAGVUL headline benchmark (C/C++).

Runs our model on N sampled pairs from primevul_test_paired (a clean holdout; our model
trained on train/valid). Scores PAIR accuracy: a pair is correct only when the vulnerable
func is called vuln AND the fixed func is called safe. Compares to AEGIS's 122/435 (~28%).

HONEST: C/C++, so the JS-oriented tools don't contribute -- this measures the MODEL.

    python primevul_eval.py --n 24 --adapter data/runs/v12_1/best/qwen_cot_v12_1b_best
"""
import argparse
import json
import random
import time
from collections import defaultdict

from eval.inference import QwenLoraPredictor
from eval.parsers import parse_shape1

PV = "data/downloads/PrimeVul/primevul_test_paired.jsonl"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=24, help="number of pairs to sample")
    ap.add_argument("--adapter", default="data/runs/v12_1/best/qwen_cot_v12_1b_best")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rows = [json.loads(l) for l in open(PV, encoding="utf-8")]
    # PrimeVul paired file: adjacent records are a pair (2i target=1 vuln, 2i+1 target=0 fixed)
    pairs = []
    for i in range(0, len(rows) - 1, 2):
        a, b = rows[i], rows[i + 1]
        v = a if a["target"] == 1 else b
        s = a if a["target"] == 0 else b
        if v["target"] == 1 and s["target"] == 0:
            pairs.append((v, s))
    random.Random(args.seed).shuffle(pairs)
    pairs = pairs[:args.n]
    print(f"loaded {len(pairs)} pairs from PrimeVul test\n", flush=True)

    print(f"loading model (base Qwen3-8B + adapter {args.adapter}) ...", flush=True)
    predictor = QwenLoraPredictor(adapter_path=args.adapter)

    def predict(code):
        resp = predictor.predict(f"<SCAN>\n{code[:6000]}\n</SCAN>")
        return parse_shape1(resp).get("status")

    per, pair_ok = 0, 0
    for i, (v, s) in enumerate(pairs):
        t0 = time.time()
        pv = predict(v["func"]); ps = predict(s["func"])
        v_ok = pv in ("vuln", "confirmed")
        s_ok = ps == "safe"
        per += v_ok + s_ok
        pair_ok += (v_ok and s_ok)
        print(f"  [{i:2d}] {str(v.get('cwe'))[:14]:14s} vuln->{str(pv):9s}{'OK' if v_ok else 'XX'} "
              f"fixed->{str(ps):9s}{'OK' if s_ok else 'XX'} {'== PAIR' if v_ok and s_ok else ''} "
              f"({time.time()-t0:.0f}s)", flush=True)

    n = len(pairs)
    print(f"\nPrimeVul ({n} pairs):  per-record {per}/{2*n} ({100*per//(2*n)}%)  |  "
          f"PAIR {pair_ok}/{n} ({100*pair_ok//n}%)")
    print(f"AEGIS (full 435 test, CPG+large model): 122/435 pairwise (28%)")


if __name__ == "__main__":
    main()
