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
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

from bench_reasoners import SYSTEM, parse_verdict, score


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--limit", type=int, default=0, help="0 = all cases")
    ap.add_argument("--max-new", type=int, default=3072)
    args = ap.parse_args()

    cases = [json.loads(l) for l in open("bench_cases.jsonl", encoding="utf-8")]
    if args.limit:
        cases = cases[:args.limit]

    print(f"loading {args.model} (4-bit)...", flush=True)
    tok = AutoTokenizer.from_pretrained(args.model)
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.bfloat16)
    model = AutoModelForCausalLM.from_pretrained(args.model, quantization_config=bnb,
                                                 device_map="auto", torch_dtype=torch.bfloat16)
    model.eval()

    safe_name = re.sub(r"[^0-9a-zA-Z]+", "_", args.model)
    out_path = f"bench_{safe_name}.txt"
    records = []
    with open(out_path, "w", encoding="utf-8") as out:
        for i, c in enumerate(cases):
            msgs = [{"role": "system", "content": SYSTEM},
                    {"role": "user", "content": c["code"]}]
            prompt = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
            ids = tok(prompt, return_tensors="pt").to(model.device)
            t0 = time.time()
            with torch.no_grad():
                gen = model.generate(**ids, max_new_tokens=args.max_new, do_sample=True,
                                     temperature=0.3, top_p=0.95,
                                     pad_token_id=tok.eos_token_id)
            resp = tok.decode(gen[0][ids["input_ids"].shape[1]:], skip_special_tokens=True)
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
