"""Show what the trained model ACTUALLY reasons when handed vulnerable code.

Not a benchmark -- a look at the thinking. Prints the raw `<think>` block so the
reasoning process is visible rather than just the verdict, which is the only way
to tell whether it is probing like an attacker or narrating like an auditor.

    WAVE_ADAPTER_PATH=data/qwen_cot_v12_1b_best python show_model_reasoning.py
"""
import json
import os
import sys

SAMPLES = "data/cot/staging/shape1_ts_augment_edits.jsonl"


def main():
    adapter = os.environ.get("WAVE_ADAPTER_PATH")
    if not adapter:
        print("set WAVE_ADAPTER_PATH")
        return 2
    # import AFTER the env var is set: eval.config reads it at import time, and
    # writing os.environ later is a no-op once the module is cached.
    from eval.inference import QwenLoraPredictor

    recs = [json.loads(l) for l in open(SAMPLES, encoding="utf-8") if l.strip()]
    vulns = [r for r in recs if r["_meta"]["label"] == "vuln"]
    safes = [r for r in recs if r["_meta"]["label"] == "safe"]

    # one of each interesting kind, so we can compare how it treats them
    picks = []
    for kind in ("partial_fix_vuln", "variant_vuln"):
        m = next((r for r in vulns if r["_meta"]["record_kind"] == kind), None)
        if m:
            picks.append(m)
    m = next((r for r in safes if r["_meta"]["record_kind"] == "nearmiss_safe"), None)
    if m:
        picks.append(m)

    print(f"loading adapter: {adapter}", flush=True)
    pred = QwenLoraPredictor(adapter_path=adapter)
    assert hasattr(pred.model, "peft_config"), "adapter did not load"
    print("adapter loaded\n", flush=True)

    for i, r in enumerate(picks, 1):
        meta = r["_meta"]
        code = r["messages"][0]["content"]
        print("=" * 78)
        print(f"SAMPLE {i}: {meta['ground_truth_cwe']}  kind={meta['record_kind']}  "
              f"repo={meta.get('repo','?')}")
        print(f"TRUE LABEL: {meta['label']}")
        print("=" * 78)
        out = pred.predict(code)
        print(out.strip()[:2600])
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
