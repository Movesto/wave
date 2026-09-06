"""Does a GROUNDED OUTPUT FORMAT in the prompt make the model read the code?

Context: a CHECKLIST prompt was already tried on v11 and recorded as
"prompting exhausted" -- pair accuracy 2% -> 12%, but recall collapsed 87% -> 20%
and the 12% was mostly noise (v1 and v2 agreed on only 2 of 5 correct pairs).

This is a DIFFERENT lever. A checklist instructs a METHOD and the output stays
prose, so the model narrates compliance. This constrains the OUTPUT: every field
must be copied verbatim from the input, which is mechanically checkable and cannot
be satisfied by fluent prose.

Two measurements, neither needing a human:
  GROUNDING     does the line it quotes actually occur in the code?  (string match)
  PAIR ACCURACY both sides of a contrastive pair called correctly.
                Baselines on record: 2% bare, 12% checklist-prompted.

    WAVE_ADAPTER_PATH=data/qwen_cot_v12_1b_best python exp_grounded_prompt.py
"""
import json
import os
import re
import sys
import time

FORMAT = """
Answer using EXACTLY these five lines and nothing else. Every quoted value must be
copied character-for-character from the code above -- do not paraphrase, do not
invent names.

sink: <the exact line where a value is used in a dangerous operation>
source: <the exact identifier whose value an attacker influences>
guard: <the exact line that constrains that value, or the single word none>
bypass: <the specific input that defeats the guard, or the single word none>
verdict: <one of exploitable | control_incomplete | not_exploitable | insufficient_context>
"""

FILES = ["data/cot/staging/shape1_contrastive_ts_osv.jsonl",
         "data/cot/staging/shape1_ts_augment_edits.jsonl"]
OUT = "data/eval_runs/grounded_prompt_probe.jsonl"

_F = re.compile(r"^\s*(sink|source|guard|bypass|verdict)\s*:\s*(.+?)\s*$", re.M | re.I)


def norm(s):
    return re.sub(r"\s+", " ", s or "").strip()


def parse(out):
    got = {}
    for m in _F.finditer(out):
        k = m.group(1).lower()
        if k not in got:                     # first occurrence wins
            got[k] = m.group(2).strip().strip("`")
    return got


def grounded(val, code):
    """Is this value really present in the code (not invented)?"""
    if not val:
        return False
    v = norm(val).lower()
    if v in ("none", "n/a", "-"):
        return True
    c = norm(code).lower()
    if v in c:
        return True
    # allow a token-level match for `source`, which may be an identifier
    tok = v.split("(")[0].split("[")[0].strip()
    return bool(tok) and len(tok) > 2 and tok in c


VERDICT_TO_LABEL = {
    "exploitable": "vuln",
    "control_incomplete": "vuln",
    "not_exploitable": "safe",
    "insufficient_context": "abstain",
}


def main():
    adapter = os.environ.get("WAVE_ADAPTER_PATH")
    if not adapter:
        print("set WAVE_ADAPTER_PATH")
        return 2
    from eval.inference import QwenLoraPredictor

    recs = []
    for p in FILES:
        recs += [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
    print(f"records: {len(recs)}", flush=True)

    pred = QwenLoraPredictor(adapter_path=adapter)
    assert hasattr(pred.model, "peft_config"), "adapter did not load"
    print("adapter loaded\n", flush=True)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    done = {}
    if os.path.exists(OUT):
        for l in open(OUT, encoding="utf-8"):
            r = json.loads(l)
            done[r["key"]] = r
    fh = open(OUT, "a", encoding="utf-8")

    t0 = time.time()
    for i, r in enumerate(recs, 1):
        m = r["_meta"]
        key = f"{m['pair_id']}:{m['label']}"
        if key in done:
            continue
        code = r["messages"][0]["content"]
        out = pred.predict(code + "\n" + FORMAT)
        g = parse(out)
        row = {
            "key": key, "pair_id": m["pair_id"], "label": m["label"],
            "cwe": m["ground_truth_cwe"], "kind": m.get("record_kind", "real"),
            "fields": g,
            "sink_grounded": grounded(g.get("sink"), code),
            "source_grounded": grounded(g.get("source"), code),
            "guard_grounded": grounded(g.get("guard"), code),
            "verdict": (g.get("verdict") or "").lower().strip(),
            "n_fields": len(g),
            "raw_len": len(out),
        }
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        fh.flush()
        if i % 10 == 0:
            el = time.time() - t0
            print(f"  {i}/{len(recs)}  {el/60:.1f}min  "
                  f"({el/max(1,i-len(done)):.1f}s/rec)", flush=True)
    fh.close()
    print(f"\nwrote -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
