"""Cross-file smoke: held-out CodeQL cross-file traces (all vuln). Measures
whether the model CATCHES multi-file taint flows (recall) — the capability the
single-file smoke can't see. Set WAVE_ADAPTER_PATH.
"""
import os, random
from eval.inference import QwenLoraPredictor
from eval.loader import load_eval_set
from eval.parsers import parse_shape1

es = load_eval_set()
recs = es.get("shape3_codeql", [])
random.seed(7)
random.shuffle(recs)
sample = recs[:40]

p = QwenLoraPredictor()
caught = parse_ok = 0
for r in sample:
    out = p.predict(r["messages"][0]["content"])
    st = parse_shape1(out).get("status")
    parse_ok += (st is not None)
    caught += (st in ("vuln", "confirmed"))
n = len(sample)
print(f"ADAPTER={os.environ.get('WAVE_ADAPTER_PATH')}  (cross-file, all vuln)")
print(f"  n={n}  cross-file recall={caught*100//n}% ({caught}/{n})  parse={parse_ok}/{n}")
