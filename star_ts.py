"""STaR reasoning-data generation on the TS shapes.

The student (Qwen3.5-9B) generates a reasoning trace + verdict per record; keep only VERIFIED
traces. Three tiers:
  TOOL   -- the witness fires and confirms the verdict (strongest; easy/injection cases).
  SELF   -- no witness coverage, but the verdict matches the ground-truth label AND the trace
            is grounded (references real code identifiers, not hallucinated).
  REJECT -- verdict wrong or ungrounded -> trash, discarded.

Complex cases (no tool oracle) can only reach SELF tier -- judged harder, per the plan.
Kept traces are written as shape1-style records for training.

    python star_ts.py --n 4          # sample 4 TS pairs (8 records)
"""
import argparse
import json
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, "scanner")
sys.path.insert(0, ".")
from guard_witness import witness_scan
from full_model import FullModelPredictor

_CWE_KIND = {"CWE-22": "path", "CWE-23": "path", "CWE-98": "path", "CWE-73": "path",
             "CWE-59": "path", "CWE-601": "redirect", "CWE-807": "redirect",
             "CWE-78": "command", "CWE-77": "command", "CWE-88": "command",
             "CWE-918": "ssrf", "CWE-1321": "proto", "CWE-79": "xss", "CWE-80": "xss"}

GEN = ("Determine whether this code has a security vulnerability. It may be VULNERABLE or "
       "SAFE -- both are common, and many snippets are already fixed/safe, so do NOT assume "
       "a vulnerability exists. Reason step by step: identify any untrusted input and the "
       "sink it reaches; if a guard is present, check what it actually admits and whether it "
       "FULLY stops the exploit. A guard that fully stops the exploit means the code is SAFE. "
       "Keep it to 4-6 sentences, then end with exactly one line:\n"
       "status: vuln   (or)   status: safe")


def load_ts_pairs(n, seed=42):
    src = "data/cot/filtered/shape1_contrastive_ts_osv.jsonl"
    by_pair = {}
    for line in open(src, encoding="utf-8"):
        r = json.loads(line)
        m = r["_meta"]
        pid, lab = m.get("pair_id"), m.get("label")
        if not pid or lab not in ("vuln", "safe"):
            continue
        code = "".join(x["content"] for x in r["messages"] if x["role"] == "user")
        code = code.replace("<SCAN>", "").replace("</SCAN>", "").strip()
        by_pair.setdefault(pid, {})[lab] = {"code": code, "cwe": m.get("ground_truth_cwe")}
    pairs = [(pid, d["vuln"], d["safe"]) for pid, d in by_pair.items()
             if "vuln" in d and "safe" in d]
    random.Random(seed).shuffle(pairs)
    # prefer witness-covered CWEs so the TOOL tier can actually fire
    pairs.sort(key=lambda p: 0 if (p[1]["cwe"] or "").upper() in _CWE_KIND else 1)
    return pairs[:n]


def parse_verdict(text):
    hits = re.findall(r"status:\s*(vuln\w*|safe)", text, re.I)
    if hits:
        return "vuln" if hits[-1].lower().startswith("vuln") else "safe"
    tail = text[-200:].lower()
    if "not vulnerable" in tail or "is safe" in tail:
        return "safe"
    if "vulnerable" in tail:
        return "vuln"
    return "?"


def grounded(trace, code):
    """>=2 multi-char identifiers named in the trace actually appear in the code."""
    idents = {m for m in re.findall(r"\b([a-zA-Z_]\w{3,})\b", trace)
              if m.lower() not in ("vuln", "safe", "status", "code", "input", "attacker",
                                   "guard", "sink", "value", "this", "that", "would", "which")}
    real = sum(1 for i in idents if re.search(r"\b" + re.escape(i) + r"\b", code))
    return real >= 2


def verify(rec, verdict, trace):
    """Return (tier, keep_bool, note)."""
    label = rec["label"]
    if verdict != label:
        return "REJECT", False, f"verdict {verdict} != label {label}"
    kind = _CWE_KIND.get((rec["cwe"] or "").upper())
    w = witness_scan(rec["code"], kind) if kind else None
    if kind and ((label == "vuln" and w) or (label == "safe" and not w)):
        if grounded(trace, rec["code"]):
            return "TOOL", True, (f"witness {w['bypass']!r}" if w else "witness silent (safe)")
    if grounded(trace, rec["code"]):
        return "SELF", True, "verdict matches label + grounded"
    return "REJECT", False, "ungrounded (hallucinated identifiers)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=4)
    ap.add_argument("--model", default="Qwen/Qwen3.5-9B")
    ap.add_argument("--out", default="star_ts_data.jsonl")
    args = ap.parse_args()

    pairs = load_ts_pairs(args.n)
    print(f"loaded {len(pairs)} TS pairs ({2*len(pairs)} records)\n", flush=True)
    print(f"loading {args.model}...", flush=True)
    m = FullModelPredictor(args.model, max_new=1200)

    kept, tiers = [], {"TOOL": 0, "SELF": 0, "REJECT": 0}
    for pid, v, s in pairs:
        for rec in ({**v, "label": "vuln"}, {**s, "label": "safe"}):
            trace = m.predict(f"<SCAN>\n{rec['code'][:5000]}\n</SCAN>", system=GEN)
            verdict = parse_verdict(trace)
            tier, keep, note = verify(rec, verdict, trace)
            tiers[tier] += 1
            print(f"  {rec['label']:5s} {str(rec['cwe'])[:12]:12s} verdict={verdict:5s} "
                  f"-> {tier:6s} {'KEEP' if keep else 'drop'}  ({note})", flush=True)
            if keep:
                kept.append({"messages": [
                    {"role": "user", "content": f"<SCAN>\n{rec['code']}\n</SCAN>"},
                    {"role": "assistant", "content": trace.strip()}],
                    "_meta": {"label": rec["label"], "cwe": rec["cwe"], "tier": tier,
                              "source": "star_ts", "language": "typescript"}})

    with open(args.out, "w", encoding="utf-8") as f:
        for k in kept:
            f.write(json.dumps(k, ensure_ascii=False) + "\n")
    n = 2 * len(pairs)
    print(f"\ntiers: {tiers}")
    print(f"KEPT {len(kept)}/{n} verified traces ({100*len(kept)//max(n,1)}%) -> {args.out}")


if __name__ == "__main__":
    main()
