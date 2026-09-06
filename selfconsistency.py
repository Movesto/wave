"""Self-consistency probe: does the model have a noisy signal, or no signal?

All four models sit near chance on paired discrimination. That has two very different
explanations and they call for different work:

  A. The signal EXISTS but is noisy -- the model reasons correctly some of the time and
     a single greedy sample lands on the wrong branch. Majority voting over K samples
     would recover it, and the fix is decoding/aggregation, not data.
  B. There is NO signal -- the model answers the same thing every time and it is simply
     wrong. Voting cannot help, because K identical samples have nothing to average.

The cheapest discriminator is not the vote itself but the DISAGREEMENT RATE. If K samples
at temperature agree unanimously on almost every record, we are in case B and no amount
of sampling helps. That is measured here alongside the vote.

Costs K generations per record, so it runs on a subset and in resumable chunks -- long
GPU jobs get killed on this box.

    python selfconsistency.py --model v12_1b --pairs 20 --k 5 --limit 12
"""
import argparse
import collections
import json
import os
import sys
from pathlib import Path

OUT_DIR = Path("data/eval_runs/selfconsistency")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="v12_1b")
    ap.add_argument("--adapter", required=True)
    ap.add_argument("--pairs", type=int, default=20)
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--temp", type=float, default=0.8)
    ap.add_argument("--limit", type=int, default=0, help="generations this invocation")
    args = ap.parse_args()

    plan = json.loads(Path("data/eval_runs/bench_plan.json").read_text(encoding="utf-8"))
    by_pair = collections.defaultdict(list)
    for r in plan["records"]:
        if r.get("pair_id"):
            by_pair[r["pair_id"]].append(r)
    full = [v for v in by_pair.values() if len(v) == 2]
    full.sort(key=lambda v: v[0]["id"])
    chosen = [r for sides in full[:args.pairs] for r in sides]

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / f"{args.model}_k{args.k}.jsonl"
    done = collections.Counter()
    if out_path.exists():
        for line in open(out_path, encoding="utf-8"):
            if line.strip():
                done[json.loads(line)["id"]] += 1

    todo = [(r, s) for r in chosen for s in range(args.k)
            if done[r["id"]] <= s]
    # keep only the samples still missing, in record order
    todo = []
    for r in chosen:
        for s in range(done[r["id"]], args.k):
            todo.append(r)
    if args.limit:
        todo = todo[:args.limit]
    print(f"{args.model}: {sum(done.values())}/{len(chosen)*args.k} samples cached, "
          f"{len(todo)} this run", flush=True)
    if not todo:
        report(out_path, chosen, args)
        return 0

    os.environ["WAVE_ADAPTER_PATH"] = args.adapter
    os.environ["WAVE_GEN_TEMPERATURE"] = str(args.temp)
    from eval.inference import QwenLoraPredictor
    from eval.parsers import parse_shape1
    import torch

    pred = QwenLoraPredictor(adapter_path=args.adapter)
    with open(out_path, "a", encoding="utf-8") as fh:
        for i, r in enumerate(todo, 1):
            # sampling, not greedy -- that is the whole point
            text = _sample(pred, r["prompt"], args.temp)
            status = parse_shape1(text).get("status")
            fh.write(json.dumps({"id": r["id"], "pair_id": r["pair_id"],
                                 "label": r["label"], "status": status}) + "\n")
            fh.flush()
            if i % 10 == 0:
                print(f"  {i}/{len(todo)}", flush=True)
                torch.cuda.empty_cache()
    report(out_path, chosen, args)
    return 0


def _sample(pred, prompt: str, temp: float) -> str:
    """One TEMPERATURE sample. eval.inference.predict is greedy by design."""
    import torch
    msgs = [{"role": "user", "content": prompt}]
    try:
        text = pred.tokenizer.apply_chat_template(msgs, tokenize=False,
                                            add_generation_prompt=True,
                                            enable_thinking=True)
    except TypeError:
        text = pred.tokenizer.apply_chat_template(msgs, tokenize=False,
                                            add_generation_prompt=True)
    ids = pred.tokenizer(text, return_tensors="pt", truncation=True,
                   max_length=1664).to(pred.model.device)
    with torch.no_grad():
        gen = pred.model.generate(**ids, max_new_tokens=320, do_sample=True,
                                  temperature=temp, top_p=0.95,
                                  pad_token_id=pred.tokenizer.pad_token_id
                                  or pred.tokenizer.eos_token_id)
    return pred.tokenizer.decode(gen[0][ids["input_ids"].shape[1]:], skip_special_tokens=True)


def report(out_path: Path, chosen, args):
    rows = [json.loads(l) for l in open(out_path, encoding="utf-8") if l.strip()]
    by_rec = collections.defaultdict(list)
    for r in rows:
        by_rec[r["id"]].append(r)
    label = {r["id"]: r["label"] for r in chosen}
    pair_of = {r["id"]: r["pair_id"] for r in chosen}

    norm = lambda s: "vuln" if s in ("vuln", "confirmed") else (
        "safe" if s == "safe" else None)
    unanimous = split = 0
    single_ok = major_ok = 0
    maj_by_rec, sing_by_rec = {}, {}
    for rid, samples in by_rec.items():
        if len(samples) < args.k:
            continue
        v = [norm(s["status"]) for s in samples]
        c = collections.Counter(x for x in v if x)
        if len(c) <= 1:
            unanimous += 1
        else:
            split += 1
        maj = c.most_common(1)[0][0] if c else None
        maj_by_rec[rid] = maj
        sing_by_rec[rid] = v[0]
        single_ok += int(v[0] == label[rid])
        major_ok += int(maj == label[rid])

    n = len(maj_by_rec)
    if not n:
        print("no complete records yet")
        return
    print(f"\n=== self-consistency: {args.model}, k={args.k}, temp={args.temp} ===")
    print(f"  records with all {args.k} samples: {n}")
    print(f"  UNANIMOUS across samples : {unanimous}/{n} ({100*unanimous//n}%)")
    print(f"  split (some disagreement): {split}/{n} ({100*split//n}%)")
    print(f"    -> if unanimity is near 100%, voting CANNOT help: the error is "
          f"deterministic, not noise")
    print(f"\n  per-record accuracy  single={100*single_ok/n:5.1f}%  "
          f"majority={100*major_ok/n:5.1f}%")

    def pair_acc(pick):
        by_pair = collections.defaultdict(list)
        for rid, p in pair_of.items():
            if rid in pick:
                by_pair[p].append(rid)
        ok = tot = 0
        for p, rids in by_pair.items():
            if len(rids) != 2:
                continue
            tot += 1
            ok += all(pick[r] == label[r] for r in rids)
        return ok, tot
    so, st = pair_acc(sing_by_rec)
    mo, mt = pair_acc(maj_by_rec)
    print(f"  PAIR accuracy        single={so}/{st}  majority={mo}/{mt}")


if __name__ == "__main__":
    sys.exit(main())
