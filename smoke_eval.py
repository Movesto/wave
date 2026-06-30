"""Quick directional smoke: 42 held-out records (seed 1), same sample across
model versions. Reports acc / FPR / FNR + parse-success. Set WAVE_ADAPTER_PATH.
"""
import os, random
from eval.inference import QwenLoraPredictor
from eval.loader import load_eval_set
from eval.parsers import parse_shape1

es = load_eval_set()
random.seed(1)
shapes = ["shape1", "shape1_ts", "shape1_react", "shape1_ts_safe",
          "shape1_react_safe", "shape1_verified", "shape1_verified_safe"]
samples = []
for s in shapes:
    recs = [r for r in es.get(s, []) if r["_meta"].get("label") in ("safe", "vuln", "confirmed")]
    random.shuffle(recs)
    samples += [(s, r) for r in recs[:6]]

p = QwenLoraPredictor()
def norm(x): return "vuln" if x in ("vuln", "confirmed") else "safe"
fp = fn = safe_n = vuln_n = correct = parse_ok = 0
for s, r in samples:
    gt = norm(r["_meta"].get("label"))
    out = p.predict(r["messages"][0]["content"])
    st = parse_shape1(out).get("status")
    parse_ok += (st is not None)
    pred = norm(st or "safe")
    correct += (pred == gt)
    if gt == "safe":
        safe_n += 1; fp += (pred == "vuln")
    else:
        vuln_n += 1; fn += (pred == "safe")
n = len(samples)
print(f"ADAPTER={os.environ.get('WAVE_ADAPTER_PATH')}")
print(f"  n={n}  acc={correct*100//n}%  FPR={fp}/{safe_n}={fp*100//max(safe_n,1)}%  "
      f"FNR={fn}/{vuln_n}={fn*100//max(vuln_n,1)}%  parse={parse_ok}/{n}")
