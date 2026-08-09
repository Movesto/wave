"""Merged agent: agentic reasoning + witness TOOL + AEGIS witness VETO, over all cases.

Per case:
  Turn 1: model reasons on numbered code; may call TOOL: witness(kind).
  (tool)  run witness_scan, feed result back.
  Turn 2: model gives FINAL verdict + vuln line + fix.
  AUDIT : independently run the witness. If it proves a bypass but the model concluded
          'safe' (or gave no verdict), VETO -> feed the proof and force a corrected
          verdict + line + fix (turn 3). This is the AEGIS audit inside the agent.

Final answer = post-audit. Scores verdict accuracy (model-alone vs +veto) and pair accuracy,
captures the fix per case. Full transcripts -> merged_agent_transcript.txt.

    python merged_agent.py --cases harder_cases.jsonl
"""
import argparse
import json
import re
import time
from collections import defaultdict

import torch
from transformers import BitsAndBytesConfig

from guard_witness import witness_scan
from run_local_model import load_model_and_tok
from agent_prototype import SYSTEM, numbered, gen, _WK


def parse_final(text):
    vm = re.search(r"VERDICT:\s*(\w+)", text)
    vraw = vm.group(1).lower() if vm else "?"
    verdict = "vuln" if vraw.startswith("vuln") else "safe" if vraw == "safe" else "?"
    line = re.search(r"VULN_LINE:\s*(.+)", text)
    fix = re.search(r"FIX:\s*(.+)", text)
    return verdict, (line.group(1).strip()[:70] if line else "?"), \
        (fix.group(1).strip()[:100] if fix else "?")


def run_case(model, tok, decoder, eos, code, cwe, out):
    kind = _WK.get((cwe or "").upper())
    wkind = kind if kind in ("path", "command", "ssrf", "proto", "redirect", "xss") else None
    msgs = [{"role": "system", "content": SYSTEM},
            {"role": "user", "content": "```\n" + numbered(code) + "\n```"}]
    r1 = gen(model, tok, decoder, eos, msgs, max_new=1400)
    out.write("--- TURN 1 ---\n" + r1 + "\n")

    tool = re.search(r"TOOL:\s*witness\(\s*(\w+)\s*\)", r1)
    if tool:
        rk = tool.group(1).lower()
        k = rk if rk in ("path", "command", "ssrf", "proto", "redirect", "xss") else wkind
        w = witness_scan(code, k) if k else None
        res = (f"witness({k}): INSUFFICIENT -- bypass {w['bypass']!r} defeats `{w['guard']}` "
               f"({w['why']})") if w else f"witness({k}): no bypass proven"
        out.write(f"\n--- TOOL --> {res} ---\n")
        msgs += [{"role": "assistant", "content": r1},
                 {"role": "user", "content": res + "\n\nNow give your FINAL answer."}]
        final_txt = gen(model, tok, decoder, eos, msgs, max_new=1400)
        out.write("\n--- TURN 2 ---\n" + final_txt + "\n")
    else:
        final_txt = r1

    m_verdict, m_line, m_fix = parse_final(final_txt)
    model_verdict = m_verdict

    # ---- AEGIS AUDIT: independent witness veto of a false 'safe' ----
    audit = witness_scan(code, wkind) if wkind else None
    vetoed = False
    if audit and m_verdict in ("safe", "?"):
        vetoed = True
        proof = (f"AUDIT: an independent check PROVES this guard is bypassable -- input "
                 f"{audit['bypass']!r} defeats `{audit['guard']}` ({audit['why']}). Your "
                 f"'safe' verdict is wrong. Give the corrected FINAL answer (VERDICT must be "
                 f"vulnerable) with the vuln line and a fix that blocks this exact bypass.")
        msgs2 = [{"role": "system", "content": SYSTEM},
                 {"role": "user", "content": "```\n" + numbered(code) + "\n```"},
                 {"role": "assistant", "content": final_txt},
                 {"role": "user", "content": proof}]
        corr = gen(model, tok, decoder, eos, msgs2, max_new=1400)
        out.write(f"\n--- AUDIT VETO --> forcing reconsideration ---\n{corr}\n")
        m_verdict, m_line, m_fix = parse_final(corr)
        m_verdict = "vuln"    # audit is deterministic ground truth here

    return {"model_verdict": model_verdict, "final_verdict": m_verdict,
            "line": m_line, "fix": m_fix, "tool": bool(tool), "vetoed": vetoed}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen3.5-9B")
    ap.add_argument("--cases", default="harder_cases.jsonl")
    args = ap.parse_args()
    cases = [json.loads(l) for l in open(args.cases, encoding="utf-8")]

    print(f"loading {args.model} (4-bit)...", flush=True)
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.bfloat16)
    model, tok = load_model_and_tok(args.model, bnb)
    model.eval()
    decoder = getattr(tok, "tokenizer", tok)
    eos = getattr(decoder, "eos_token_id", None)

    out = open("merged_agent_transcript.txt", "w", encoding="utf-8")
    rows = []
    for i, c in enumerate(cases):
        out.write(f"\n{'='*80}\nCASE {i} CWE={c['cwe']} truth={c['label']}\nCODE:\n"
                  + numbered(c["code"]) + "\n\n")
        t0 = time.time()
        r = run_case(model, tok, decoder, eos, c["code"], c["cwe"], out)
        r.update(idx=i, cwe=c["cwe"], truth=c["label"], pair_id=c["pair_id"])
        rows.append(r)
        base_ok = r["model_verdict"] == c["label"]
        veto_ok = r["final_verdict"] == c["label"]
        print(f"  [{i:2d}] {c['cwe']:8s} truth={c['label']:5s} model={r['model_verdict']:5s}"
              f"{'OK' if base_ok else 'XX'} +veto={r['final_verdict']:5s}"
              f"{'OK' if veto_ok else 'XX'} {'[VETO]' if r['vetoed'] else '':6s} "
              f"tool={'Y' if r['tool'] else 'n'} ({time.time()-t0:.0f}s)", flush=True)
    out.close()

    def score(key):
        per = sum(1 for r in rows if r[key] == r["truth"])
        pp = defaultdict(list)
        for r in rows:
            pp[r["pair_id"]].append(r[key] == r["truth"])
        pairs = sum(1 for v in pp.values() if len(v) == 2 and all(v))
        return per, len(rows), pairs, len(pp)

    b = score("model_verdict"); v = score("final_verdict")
    print(f"\nMODEL ALONE : record {b[0]}/{b[1]}  pair {b[2]}/{b[3]}")
    print(f"AGENT+VETO  : record {v[0]}/{v[1]}  pair {v[2]}/{v[3]}")
    nfix = sum(1 for r in rows if r["final_verdict"] == "vuln" and r["fix"] not in ("?", "none"))
    nvuln = sum(1 for r in rows if r["final_verdict"] == "vuln")
    print(f"fixes produced on vuln verdicts: {nfix}/{nvuln}   vetoes fired: "
          f"{sum(1 for r in rows if r['vetoed'])}")
    print("transcripts -> merged_agent_transcript.txt")


if __name__ == "__main__":
    main()
