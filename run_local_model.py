"""Run a local HF model over bench_cases.jsonl directly via transformers (4-bit), for the
reasoning head-to-head. Same prompt/scoring as bench_reasoners.py, no server needed.

    python run_local_model.py --model deepseek-ai/DeepSeek-R1-0528-Qwen3-8B
    python run_local_model.py --model <hf-id-or-path> --limit 6 --max-new 2048
"""
import argparse
import json
import re
import time

import torch
from transformers import (AutoModelForCausalLM, AutoTokenizer, AutoProcessor,
                          BitsAndBytesConfig)

from bench_reasoners import SYSTEM, parse_verdict, score


def load_model_and_tok(model_id, bnb):
    """Load as a plain causal LM; if that fails (multimodal like Qwen3.5-9B), fall back to
    the image-text-to-text class + processor. Returns (model, tok_or_processor)."""
    try:
        tok = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
        model = AutoModelForCausalLM.from_pretrained(
            model_id, quantization_config=bnb, device_map="auto",
            torch_dtype=torch.bfloat16, trust_remote_code=True)
        return model, tok
    except Exception as e:
        print(f"  causal-LM load failed ({str(e)[:80]}); trying multimodal...", flush=True)
        from transformers import AutoModelForImageTextToText
        proc = AutoProcessor.from_pretrained(model_id, trust_remote_code=True)
        model = AutoModelForImageTextToText.from_pretrained(
            model_id, quantization_config=bnb, device_map="auto",
            torch_dtype=torch.bfloat16, trust_remote_code=True)
        return model, proc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--cases", default="bench_cases.jsonl")
    ap.add_argument("--limit", type=int, default=0, help="0 = all cases")
    ap.add_argument("--max-new", type=int, default=3072)
    args = ap.parse_args()

    cases = [json.loads(l) for l in open(args.cases, encoding="utf-8")]
    if args.limit:
        cases = cases[:args.limit]

    print(f"loading {args.model} (4-bit)...", flush=True)
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.bfloat16)
    model, tok = load_model_and_tok(args.model, bnb)
    model.eval()

    decoder = getattr(tok, "tokenizer", tok)          # processor -> its .tokenizer
    eos = getattr(decoder, "eos_token_id", None)
    safe_name = re.sub(r"[^0-9a-zA-Z]+", "_", args.model)
    cases_tag = re.sub(r"[^0-9a-zA-Z]+", "_", args.cases.rsplit(".", 1)[0])
    out_path = f"bench_{safe_name}__{cases_tag}.txt"
    records = []
    with open(out_path, "w", encoding="utf-8") as out:
        for i, c in enumerate(cases):
            msgs = [{"role": "system", "content": SYSTEM},
                    {"role": "user", "content": c["code"]}]
            prompt = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
            try:
                ids = tok(prompt, return_tensors="pt").to(model.device)
            except Exception:
                ids = tok(text=prompt, return_tensors="pt").to(model.device)
            t0 = time.time()
            with torch.no_grad():
                gen = model.generate(**ids, max_new_tokens=args.max_new, do_sample=True,
                                     temperature=0.3, top_p=0.95, pad_token_id=eos)
            resp = decoder.decode(gen[0][ids["input_ids"].shape[1]:], skip_special_tokens=True)
            verdict = parse_verdict(resp)
            correct = (verdict == c["label"])
            records.append({"pair_id": c["pair_id"], "correct": correct})
            print(f"  [{i:2d}] {c['cwe']:8s} truth={c['label']:5s} model={verdict or '?':5s} "
                  f"{'OK' if correct else 'XX'}  ({time.time()-t0:.0f}s)", flush=True)
            out.write(f"\n{'='*80}\nCASE {i}  CWE={c['cwe']}  truth={c['label']}  "
                      f"model={verdict}  {'CORRECT' if correct else 'WRONG'}\n"
                      f"--- code ---\n{c['code']}\n--- reasoning ---\n{resp}\n")
            out.flush()

    per, n, pok, npairs = score(records)
    print(f"\n{args.model}\n  per-record {per}/{n}  |  PAIR accuracy {pok}/{npairs}")
    print(f"  full reasoning -> {out_path}")


if __name__ == "__main__":
    main()
