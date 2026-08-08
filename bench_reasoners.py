"""Head-to-head reasoning bench: run candidate models on the contrastive pairs our own
model fails, score PAIR accuracy (both sides right), and save each model's full reasoning
so we can read it next to the mad-lib.

Model-agnostic: talks to any OpenAI-compatible /chat/completions endpoint --
  ollama:      --base-url http://localhost:11434/v1   --model deepseek-r1-0528-qwen3-8b
  llama.cpp:   --base-url http://localhost:8080/v1     --model <served-name>
  cloud:       --base-url https://api.deepseek.com/v1  --model deepseek-reasoner  (--api-key ...)

Steps:
  python bench_reasoners.py --build-cases          # make bench_cases.jsonl (fixed test set)
  python bench_reasoners.py --selftest             # verify parsing/scoring, no model
  python bench_reasoners.py --model M --base-url U  # run a model, write bench_<M>.txt + score
"""
import argparse
import json
import os
import re
import sys
import urllib.request
from collections import defaultdict

CASES = "bench_cases.jsonl"

SYSTEM = (
    "You are a senior security code reviewer. Analyze the snippet for ONE security "
    "vulnerability. Reason step by step: identify any untrusted input, the dangerous sink "
    "it reaches, and whether a guard on that path FULLY neutralizes the specific exploit "
    "(check what the guard actually admits, not just that a guard exists). Then end your "
    "reply with exactly one final line, nothing after it:\nVERDICT: vulnerable   (or)   "
    "VERDICT: safe")


def build_cases():
    """Pick ~10 contrastive PAIRS (vuln+safe of the same code) across a few CWEs -- the
    guard-sufficiency cases our model fails. Fixed set so every model sees the same test."""
    src = "data/cot/filtered/shape1_contrastive_ts_osv.jsonl"
    by_pair = defaultdict(dict)
    for line in open(src, encoding="utf-8"):
        r = json.loads(line)
        m = r["_meta"]
        pid, lab = m.get("pair_id"), m.get("label")
        if not pid or lab not in ("vuln", "safe"):
            continue
        code = "".join(x["content"] for x in r["messages"] if x["role"] == "user")
        code = code.replace("<SCAN>", "").replace("</SCAN>", "").strip()
        by_pair[pid][lab] = {"code": code, "cwe": m.get("ground_truth_cwe"),
                             "language": m.get("language")}
    # keep whole pairs, spread across CWEs, cap ~10 pairs
    chosen, seen_cwe = [], defaultdict(int)
    for pid, sides in by_pair.items():
        if "vuln" not in sides or "safe" not in sides:
            continue
        cwe = sides["vuln"]["cwe"]
        if seen_cwe[cwe] >= 3:            # variety: at most 3 pairs per CWE
            continue
        seen_cwe[cwe] += 1
        for lab in ("vuln", "safe"):
            chosen.append({"pair_id": pid, "label": lab, **sides[lab]})
        if len(chosen) >= 20:
            break
    with open(CASES, "w", encoding="utf-8") as f:
        for c in chosen:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    print(f"wrote {len(chosen)} records ({len(chosen)//2} pairs) -> {CASES}")
    print("CWEs:", dict(seen_cwe))


def parse_verdict(text):
    """Last VERDICT: line -> 'vuln' | 'safe' | None."""
    hits = re.findall(r"VERDICT:\s*(vulnerable|safe|vuln)", text, re.I)
    if not hits:
        # fallback: a bare verdict near the end
        tail = text[-200:].lower()
        if "not vulnerable" in tail or "no vulnerability" in tail or "is safe" in tail:
            return "safe"
        if "vulnerable" in tail:
            return "vuln"
        if "safe" in tail:
            return "safe"
        return None
    v = hits[-1].lower()
    return "safe" if v == "safe" else "vuln"


def call(base_url, model, api_key, code, timeout=600):
    body = json.dumps({
        "model": model,
        "messages": [{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": code}],
        "temperature": 0.3, "max_tokens": 4096,
    }).encode()
    req = urllib.request.Request(base_url.rstrip("/") + "/chat/completions", data=body,
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {api_key or 'x'}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        out = json.loads(r.read())
    return out["choices"][0]["message"]["content"]


def score(records):
    per = sum(1 for r in records if r["correct"])
    by_pair = defaultdict(list)
    for r in records:
        by_pair[r["pair_id"]].append(r["correct"])
    pairs_ok = sum(1 for v in by_pair.values() if len(v) == 2 and all(v))
    return per, len(records), pairs_ok, len(by_pair)


def run(model, base_url, api_key):
    cases = [json.loads(l) for l in open(CASES, encoding="utf-8")]
    out_path = f"bench_{re.sub(r'[^0-9a-zA-Z]+', '_', model)}.txt"
    records = []
    with open(out_path, "w", encoding="utf-8") as out:
        for i, c in enumerate(cases):
            try:
                resp = call(base_url, model, api_key, c["code"])
            except Exception as e:
                print(f"  [{i}] CALL FAILED: {e}"); resp = ""
            verdict = parse_verdict(resp)
            correct = (verdict == c["label"])
            records.append({"pair_id": c["pair_id"], "correct": correct})
            print(f"  [{i:2d}] {c['cwe']:8s} truth={c['label']:5s} "
                  f"model={verdict or '?':5s} {'OK' if correct else 'XX'}")
            out.write(f"\n{'='*80}\nCASE {i}  CWE={c['cwe']}  truth={c['label']}  "
                      f"model={verdict}  {'CORRECT' if correct else 'WRONG'}\n"
                      f"--- code ---\n{c['code']}\n--- {model} reasoning ---\n{resp}\n")
    per, n, pok, np_ = score(records)
    print(f"\n{model}:  per-record {per}/{n}  |  PAIR accuracy {pok}/{np_}")
    print(f"full reasoning -> {out_path}")


def selftest():
    assert parse_verdict("blah\nVERDICT: safe") == "safe"
    assert parse_verdict("...\nVERDICT: vulnerable") == "vuln"
    assert parse_verdict("VERDICT: vuln\nnoise") == "vuln"
    assert parse_verdict("I think this is not vulnerable at all.") == "safe"
    recs = [{"pair_id": "a", "correct": True}, {"pair_id": "a", "correct": True},
            {"pair_id": "b", "correct": True}, {"pair_id": "b", "correct": False}]
    assert score(recs) == (3, 4, 1, 2)   # 3/4 records, 1/2 pairs
    print("selftest OK")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-cases", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--model")
    ap.add_argument("--base-url", default="http://localhost:11434/v1")
    ap.add_argument("--api-key", default=os.environ.get("OPENAI_API_KEY", ""))
    args = ap.parse_args()
    if args.build_cases:
        return build_cases()
    if args.selftest:
        return selftest()
    if not args.model:
        sys.exit("give --model (and --base-url); or --build-cases / --selftest")
    if not os.path.exists(CASES):
        build_cases()
    run(args.model, args.base_url, args.api_key)


if __name__ == "__main__":
    main()
