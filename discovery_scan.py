"""Discovery pass: the model reads the WHOLE project (cross-file) and looks for the vulns
automated tools CANNOT find -- logic flaws, missing authorization, IDOR, insecure design.

This is the model's UNIQUE job: reasoning about intent and cross-file logic, not re-doing the
dataflow tools. Findings are unverifiable by a tool, so they are tiered REVIEW (human-check),
never auto-HIGH -- they complement the tool-grounded findings, they don't replace them.

Scope handling:
  - project fits in the context budget -> feed the whole thing at once (true cross-file view).
  - project too large -> concatenate per directory/module in chunks and note that a large repo
    really needs a project MAP (routes/services/auth points) rather than raw concatenation.

    python discovery_scan.py data/dvna --model Qwen/Qwen3.5-9B
"""
import argparse
import sys
from pathlib import Path

import torch
from transformers import BitsAndBytesConfig
from run_local_model import load_model_and_tok

sys.path.insert(0, "scanner")
from flag import gather  # noqa: E402

CHAR_BUDGET = 90_000     # ~22K tokens; whole small projects fit, big ones get chunked

SYSTEM = """You are a senior application-security engineer doing a MANUAL code review that
automated tools CANNOT do. The whole project's source follows, with `// FILE:` headers.

Automated dataflow tools ALREADY cover injection, XSS, path traversal, SSRF, and
deserialization -- DO NOT report those. Report ONLY vulnerabilities that require understanding
INTENT and CROSS-FILE logic:
  - Missing or broken authorization / access control (e.g. a user can read or modify ANOTHER
    user's data -- IDOR); an endpoint that acts on an object id without an ownership check.
  - Authentication logic flaws (weak/again-usable tokens, auth that can be skipped).
  - Business-logic flaws (a workflow that can be abused: negative quantities, price tampering,
    replay, race).
  - Insecure design / trust-boundary mistakes (trusting a client-supplied role/flag).

Trace the logic ACROSS files (route -> handler -> service -> data). For each real issue:

FINDING: <one-line title>
FILE: <file:line where the flaw lives>
WHY: <the logic flaw and concretely how an attacker abuses it, referencing the cross-file path>
---
Report only genuine issues. If you find none, output exactly: NONE."""


def build_corpus(target):
    files = [f for f in gather(target) if f.suffix.lower() in (".js", ".ts", ".jsx", ".tsx")]
    chunks, cur, size = [], [], 0
    for f in sorted(files):
        try:
            code = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        block = f"\n// FILE: {f}\n{code}\n"
        if size + len(block) > CHAR_BUDGET and cur:
            chunks.append("".join(cur)); cur, size = [], 0
        cur.append(block); size += len(block)
    if cur:
        chunks.append("".join(cur))
    return chunks, len(files)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--model", default="Qwen/Qwen3.5-9B")
    ap.add_argument("--max-new", type=int, default=2500)
    args = ap.parse_args()

    chunks, nfiles = build_corpus(args.target)
    print(f"discovery: {nfiles} source files -> {len(chunks)} context chunk(s) "
          f"(budget {CHAR_BUDGET} chars)", flush=True)
    if len(chunks) > 1:
        print("  NOTE: project exceeds one context window; running per-chunk. A large repo "
              "really needs a project MAP for true whole-project reasoning.")

    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.bfloat16)
    print(f"loading {args.model} (4-bit)...", flush=True)
    model, tok = load_model_and_tok(args.model, bnb)
    model.eval()
    dec = getattr(tok, "tokenizer", tok)
    eos = getattr(dec, "eos_token_id", None)

    for i, corpus in enumerate(chunks):
        msgs = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": corpus}]
        prompt = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
        try:
            ids = tok(prompt, return_tensors="pt").to(model.device)
        except Exception:
            ids = tok(text=prompt, return_tensors="pt").to(model.device)
        print(f"\n=== discovery chunk {i+1}/{len(chunks)} ({ids['input_ids'].shape[1]} tokens) ==="
              f"  [findings tier: REVIEW / human-check]", flush=True)
        with torch.no_grad():
            out = model.generate(**ids, max_new_tokens=args.max_new, do_sample=True,
                                 temperature=0.4, top_p=0.95, pad_token_id=eos)
        print(dec.decode(out[0][ids["input_ids"].shape[1]:], skip_special_tokens=True), flush=True)


if __name__ == "__main__":
    main()
