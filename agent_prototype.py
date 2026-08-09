"""Small-scale AGENTIC test (no training): Qwen3.5-9B reasons, CALLS the witness tool,
identifies the vulnerable line, and recommends a fix. Tests the full vision at the model's
current ceiling before committing any GPU-days to training.

Loop per case:
  Turn 1: model sees numbered code + a tool description. It reasons and either asks for the
          witness (TOOL: witness(<kind>)) or answers directly.
  Tool  : we run witness_scan deterministically and feed the result back.
  Turn 2: model gives FINAL: verdict + vuln line + concrete fix + why-the-fix-works.

We save the full transcript per case and judge quality by hand -- does it use the tool
result, point at the right line, and write a correct fix?

    python agent_prototype.py                 # 3 default cases
    python agent_prototype.py --cases harder_cases.jsonl --pick 0,10,4
"""
import argparse
import json
import re
import time

import torch
from transformers import BitsAndBytesConfig

from guard_witness import witness_scan
from run_local_model import load_model_and_tok

SYSTEM = """You are a senior security engineer analyzing a code snippet for ONE vulnerability.

You have a deterministic TOOL:
  witness(kind) -- runs a guard's actual logic against known bypass inputs and reports a
  concrete bypass if the guard is insufficient. kind is one of: path, command, ssrf, proto,
  redirect, xss. Use it when the code has a guard/filter and you want to PROVE whether it can
  be bypassed rather than guess.

First, reason step by step about untrusted input, the sink, and any guard. If a guard is
present, you MAY call the tool by writing on its own line exactly:
  TOOL: witness(<kind>)
and then STOP -- wait for the result before concluding.

When you are ready to conclude (after the tool result, or immediately if no guard), output
exactly these lines:
  VERDICT: vulnerable | safe
  VULN_LINE: <the line number and the exact vulnerable line, or 'none'>
  FIX: <the corrected code>
  WHY: <one sentence on why the fix closes the specific bypass>"""

_WK = {"CWE-22": "path", "CWE-59": "path", "CWE-78": "command", "CWE-89": "sql",
       "CWE-918": "ssrf", "CWE-1321": "proto", "CWE-601": "redirect", "CWE-79": "xss"}


def numbered(code):
    return "\n".join(f"{i+1:3d}| {ln}" for i, ln in enumerate(code.splitlines()))


def gen(model, tok, decoder, eos, messages, max_new=1800):
    prompt = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    try:
        ids = tok(prompt, return_tensors="pt").to(model.device)
    except Exception:
        ids = tok(text=prompt, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(**ids, max_new_tokens=max_new, do_sample=True,
                             temperature=0.3, top_p=0.95, pad_token_id=eos)
    return decoder.decode(out[0][ids["input_ids"].shape[1]:], skip_special_tokens=True)


def run_case(model, tok, decoder, eos, code, cwe, out):
    kind_hint = _WK.get((cwe or "").upper())
    msgs = [{"role": "system", "content": SYSTEM},
            {"role": "user", "content": "```\n" + numbered(code) + "\n```"}]
    t0 = time.time()
    r1 = gen(model, tok, decoder, eos, msgs)
    out.write("--- TURN 1 (model reasons) ---\n" + r1 + "\n")

    tool = re.search(r"TOOL:\s*witness\(\s*(\w+)\s*\)", r1)
    tool_used = bool(tool)
    if tool:
        req_kind = tool.group(1).lower()
        # honour the model's requested kind; fall back to the CWE hint if it's off-menu
        k = req_kind if req_kind in ("path", "command", "ssrf", "proto", "redirect", "xss") \
            else kind_hint
        w = witness_scan(code, k) if k else None
        result = (f"witness({k}) result: INSUFFICIENT -- bypass input {w['bypass']!r} "
                  f"defeats guard `{w['guard']}` ({w['why']})") if w else \
                 f"witness({k}) result: no bypass proven (guard not a recognised-insufficient shape)"
        out.write(f"\n--- TOOL RUN --> {result} ---\n")
        msgs += [{"role": "assistant", "content": r1},
                 {"role": "user", "content": result + "\n\nNow give your FINAL answer."}]
        r2 = gen(model, tok, decoder, eos, msgs)
        out.write("\n--- TURN 2 (after tool) ---\n" + r2 + "\n")
        final = r2
    else:
        final = r1

    vm = re.search(r"VERDICT:\s*(\w+)", final)
    vraw = vm.group(1).lower() if vm else "?"
    verdict = "vuln" if vraw.startswith("vuln") else "safe" if vraw == "safe" else "?"
    line = re.search(r"VULN_LINE:\s*(.+)", final)
    fix = re.search(r"FIX:\s*(.+)", final)
    dt = time.time() - t0
    return {"tool_used": tool_used,
            "verdict": verdict,
            "line": (line.group(1).strip()[:70] if line else "?"),
            "fix": (fix.group(1).strip()[:80] if fix else "?"),
            "secs": round(dt)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen3.5-9B")
    ap.add_argument("--cases", default="harder_cases.jsonl")
    ap.add_argument("--pick", default="0,10,4", help="comma indices of cases to run")
    args = ap.parse_args()

    cases = [json.loads(l) for l in open(args.cases, encoding="utf-8")]
    picks = [int(x) for x in args.pick.split(",")]

    print(f"loading {args.model} (4-bit)...", flush=True)
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.bfloat16)
    model, tok = load_model_and_tok(args.model, bnb)
    model.eval()
    decoder = getattr(tok, "tokenizer", tok)
    eos = getattr(decoder, "eos_token_id", None)

    out = open("agent_transcript.txt", "w", encoding="utf-8")
    summary = []
    for idx in picks:
        c = cases[idx]
        out.write(f"\n{'='*80}\nCASE {idx}  CWE={c['cwe']}  ground-truth={c['label']}\n")
        out.write("CODE:\n" + numbered(c["code"]) + "\n\n")
        r = run_case(model, tok, decoder, eos, c["code"], c["cwe"], out)
        r["idx"] = idx; r["cwe"] = c["cwe"]; r["truth"] = c["label"]
        r["correct"] = (r["verdict"] == c["label"])
        summary.append(r)
        print(f"  [{idx:2d}] {c['cwe']:8s} truth={c['label']:5s} verdict={r['verdict']:5s} "
              f"{'OK' if r['correct'] else 'XX'} | tool={'Y' if r['tool_used'] else 'n'} "
              f"| line={r['line'][:40]} ({r['secs']}s)", flush=True)
    out.close()

    print("\n=== summary ===")
    for r in summary:
        print(f"  case {r['idx']} {r['cwe']}: verdict {r['verdict']} "
              f"({'correct' if r['correct'] else 'WRONG'}), tool_used={r['tool_used']}")
        print(f"     line: {r['line']}")
        print(f"     fix : {r['fix']}")
    print("\nfull transcripts -> agent_transcript.txt")


if __name__ == "__main__":
    main()
