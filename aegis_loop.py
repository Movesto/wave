"""AEGIS-style verifier loop, evaluated offline on a saved model run.

AEGIS = Verifier Agent (the LLM's reasoning + verdict) + an independent Audit Agent that
vetoes hallucinated verdicts against a grounded evidence base. Our witness IS the Audit
Agent: it deterministically proves a present guard bypassable. So the loop is:

    final = model_verdict, UNLESS the model said 'safe' AND the witness proves the guard
            is bypassable -> VETO -> 'vuln' (with the concrete bypass as evidence).

The veto is ONE-directional by design: the witness proves INSUFFICIENCY, never safety, so
it can only overturn a false 'safe' -- which is exactly Qwen3.5-9B's failure mode (safe
bias). It cannot rescue an over-flag (false 'vuln'); we report that honestly.

Model verdicts are read from a saved bench_<model>__<cases>.txt so this needs no GPU.

    python aegis_loop.py --cases harder_cases.jsonl \
                         --run bench_Qwen_Qwen3_5_9B__harder_cases.txt
"""
import argparse
import json
import re
from collections import defaultdict

from guard_witness import witness_scan

_WK = {"CWE-22": "path", "CWE-23": "path", "CWE-98": "path", "CWE-73": "path", "CWE-59": "path",
       "CWE-78": "command", "CWE-77": "command", "CWE-88": "command",
       "CWE-918": "ssrf", "CWE-1321": "proto", "CWE-601": "redirect", "CWE-807": "redirect",
       "CWE-79": "xss", "CWE-80": "xss"}


def load_model_verdicts(run_path):
    """{case_index: 'vuln'|'safe'|None} parsed from a saved bench run."""
    txt = open(run_path, encoding="utf-8", errors="replace").read()
    out = {}
    for m in re.finditer(r"CASE (\d+)\s+CWE=\S+\s+truth=\w+\s+model=(\S+)", txt):
        v = m.group(2)
        out[int(m.group(1))] = None if v == "None" else v
    return out


def score(rows):
    per = sum(1 for r in rows if r["correct"])
    by_pair = defaultdict(list)
    for r in rows:
        by_pair[r["pair_id"]].append(r["correct"])
    pairs_ok = sum(1 for v in by_pair.values() if len(v) == 2 and all(v))
    return per, len(rows), pairs_ok, len(by_pair)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="harder_cases.jsonl")
    ap.add_argument("--run", default="bench_Qwen_Qwen3_5_9B__harder_cases.txt")
    args = ap.parse_args()

    cases = [json.loads(l) for l in open(args.cases, encoding="utf-8")]
    mv = load_model_verdicts(args.run)

    base_rows, loop_rows, vetoes = [], [], []
    for i, c in enumerate(cases):
        truth = c["label"]
        model = mv.get(i)
        # audit: witness on the code for this CWE's kind
        kind = _WK.get((c["cwe"] or "").upper())
        wit = witness_scan(c["code"], kind) if kind else None

        final = model
        veto = False
        # AEGIS audit veto: a false 'safe' overturned by a proven bypass. Also overturn a
        # non-answer (None) when the witness has hard proof -- a grounded verdict beats a
        # dropped one.
        if wit and model in ("safe", None):
            final = "vuln"
            veto = True
            vetoes.append((i, c["pair_id"], model, wit["bypass"]))

        base_rows.append({"pair_id": c["pair_id"], "correct": model == truth})
        loop_rows.append({"pair_id": c["pair_id"], "correct": final == truth})
        tag = ""
        if veto:
            tag = f"  <-- VETO ({model}->vuln, bypass {vetoes[-1][3]!r})"
        print(f"  [{i:2d}] {c['cwe']:8s} truth={truth:5s} model={str(model):5s} "
              f"final={str(final):5s} {'OK' if final==truth else 'XX'}{tag}")

    b = score(base_rows)
    l = score(loop_rows)
    print(f"\nMODEL ALONE : per-record {b[0]}/{b[1]}  |  PAIR {b[2]}/{b[3]}")
    print(f"MODEL+WITNESS: per-record {l[0]}/{l[1]}  |  PAIR {l[2]}/{l[3]}")
    print(f"vetoes fired: {len(vetoes)}  (all one-directional: false-safe -> vuln)")
    # honesty: cases the loop STILL gets wrong, and why
    wrong = [(i, cases[i]) for i, r in enumerate(loop_rows) if not r["correct"]]
    if wrong:
        print("\nstill wrong after the loop:")
        for i, c in wrong:
            k = _WK.get((c["cwe"] or "").upper())
            reason = ("over-flag: model said vuln on safe code, witness can't veto toward safe"
                      if c["label"] == "safe" and mv.get(i) == "vuln"
                      else "witness has no proof for this shape (outside battery)")
            print(f"  [{i:2d}] {c['cwe']:8s} truth={c['label']:5s} model={mv.get(i)} -- {reason}")


if __name__ == "__main__":
    main()
