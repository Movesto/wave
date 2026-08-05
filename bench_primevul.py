"""Score the model on the PrimeVul benchmark — a published, curated, external eval.

WHY THIS BEATS OUR HOME-GROWN EVALS
PrimeVul (arXiv:2403.18624) exists because the field's benchmarks were broken: Devign and
BigVul carry heavy label noise and duplication, so reported accuracy was inflated. PrimeVul
de-duplicates, fixes labels, and — the part that matters here — ships a PAIRED split: the
same function before and after its security fix.

That is exactly the v2p test this project invented independently, except curated by the
authors and comparable to published numbers. Using it means our results can be read against
the literature instead of only against ourselves.

THE PAIRED METRICS (from the paper) — these four partition every pair:

  P-C  Pair-wise Correct    both sides right              <- the real score
  P-V  Pair-wise Vulnerable both called vulnerable        <- flags everything
  P-B  Pair-wise Benign     both called benign            <- misses everything
  P-R  Pair-wise Reversed   both wrong, swapped

The paper's central result is that P-C is low for every model tested while P-V is high —
models detect the *topic* of vulnerable code, not the fix. That is the same conclusion this
project reached from the v2p test, which is why this benchmark is the right external check.

LEAKAGE
`build_contrastive.py` globbed "*_paired.jsonl" and pulled 53 of the 868 test records into
training. That glob is fixed, but models trained before the fix (v12 included) saw them, so
those records are EXCLUDED here by content hash. The exclusion is recomputed on every run
against the live corpus, and the count is always printed — never assume it is zero.

  python bench_primevul.py --check                 # leakage + pairing report, no GPU
  WAVE_ADAPTER_PATH=data/runs/v12/best/qwen_cot_v12_best python bench_primevul.py --label v12
  python bench_primevul.py --score --label v12     # re-score a cached run, no GPU
"""
import argparse
import glob
import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path

TEST = Path("data/downloads/PrimeVul/primevul_test_paired.jsonl")
RUNS = Path("data/eval_runs")
MAX_CHARS = 6000   # matches the corpus over-length limit; longer C funcs are skipped


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def code_hash(s: str) -> str:
    return hashlib.sha1(norm(s).encode()).hexdigest()


def training_hashes() -> set:
    """Every code block present in the training corpus, whole and per sub-block."""
    seen = set()
    for f in glob.glob("data/cot/pilot_clean/*.jsonl"):
        for line in open(f, encoding="utf-8"):
            try:
                rec = json.loads(line)
            except Exception:
                continue
            for blk in re.findall(r"<SCAN>(.*?)</SCAN>", rec["messages"][0]["content"], re.S):
                seen.add(code_hash(blk))
                for sub in blk.split("\n\n"):
                    seen.add(code_hash(sub))
    return seen


def load_pairs(verbose: bool = True) -> tuple[list[dict], dict]:
    """Adjacent records in the paired file are a (vulnerable, fixed) pair sharing a
    commit_id. Validate that rather than trusting file order blindly."""
    if not TEST.exists():
        raise SystemExit(f"missing {TEST}")
    rows = [json.loads(l) for l in open(TEST, encoding="utf-8")]
    leak = training_hashes()

    pairs, stats = [], Counter()
    for i in range(0, len(rows) - 1, 2):
        a, b = rows[i], rows[i + 1]
        if str(a.get("target")) != "1" or str(b.get("target")) != "0":
            stats["unexpected_target_order"] += 1
            continue
        if a.get("commit_id") != b.get("commit_id"):
            stats["commit_mismatch"] += 1
            continue
        if code_hash(a["func"]) in leak or code_hash(b["func"]) in leak:
            stats["excluded_leaked"] += 1
            continue
        if len(a["func"]) > MAX_CHARS or len(b["func"]) > MAX_CHARS:
            stats["excluded_too_long"] += 1
            continue
        stats["usable"] += 1
        pairs.append({
            "pair_id": f"{a.get('commit_id','')[:12]}_{a.get('idx')}",
            "cve": a.get("cve"), "cwe": a.get("cwe"), "project": a.get("project"),
            "vuln": a["func"], "fixed": b["func"],
        })

    if verbose:
        print(f"PrimeVul test: {len(rows)} records -> {len(pairs)} usable pairs")
        for k, v in stats.most_common():
            print(f"  {k:26} {v}")
        if stats["excluded_leaked"]:
            print(f"  NOTE: {stats['excluded_leaked']} pairs dropped as train-contaminated "
                  f"(the *_paired glob bug); excluding them is what makes this eval honest.")
    return pairs, stats


def run(label: str, adapter: str | None, pairs: list[dict], limit: int | None) -> Path:
    RUNS.mkdir(parents=True, exist_ok=True)
    out = RUNS / f"primevul_{label}.raw.jsonl"
    done = set()
    if out.exists():
        for line in open(out, encoding="utf-8"):
            try:
                done.add(json.loads(line)["pair_id"])
            except Exception:
                continue
    todo = [p for p in pairs if p["pair_id"] not in done]
    if limit:
        todo = todo[:limit]
    print(f"{len(done)} cached, {len(todo)} to run")
    if not todo:
        return out

    if adapter:
        os.environ["WAVE_ADAPTER_PATH"] = adapter
    from eval.inference import QwenLoraPredictor
    from eval.parsers import parse_shape1

    # Pass the adapter EXPLICITLY — do not rely on the env var reaching
    # eval.config. config binds ADAPTER_PATH at import time, so if anything at
    # module level ever imports eval.* before this line, QwenLoraPredictor()
    # silently falls back to the BASE model and every number here becomes a
    # measurement of stock Qwen3-8B. That is exactly what happened in
    # eval_bench.py (v10 and v12 produced byte-identical output).
    adapter_path = adapter or os.environ.get("WAVE_ADAPTER_PATH")
    if not adapter_path:
        raise SystemExit(
            "refusing to run: no adapter. Pass --adapter (or set WAVE_ADAPTER_PATH).\n"
            "Without one this scores base Qwen3-8B and the numbers are meaningless.")
    predictor = QwenLoraPredictor(adapter_path=adapter_path)
    # PEFT returns PeftModelForCausalLM (a PeftModel subclass), so check for the
    # adapter config rather than an exact class name.
    if not hasattr(getattr(predictor, "model", None), "peft_config"):
        raise SystemExit(f"adapter {adapter_path} did not load — got a bare base model.")
    print(f"adapter loaded: {adapter_path} "
          f"({list(predictor.model.peft_config)})")
    with open(out, "a", encoding="utf-8") as f:
        for i, p in enumerate(todo, 1):
            preds = {}
            for side in ("vuln", "fixed"):
                scan = f"<SCAN>\n{p[side]}\n</SCAN>"
                raw = predictor.predict(scan)
                st = parse_shape1(raw).get("status")
                preds[side] = "vuln" if st in ("vuln", "confirmed") else "safe"
                preds[side + "_parsed"] = st is not None
                try:
                    preds[side + "_score"] = predictor.confidence(scan)
                except Exception:
                    preds[side + "_score"] = None
            f.write(json.dumps({**{k: p[k] for k in ("pair_id", "cve", "cwe", "project")},
                                **preds}) + "\n")
            f.flush()
            if i % 20 == 0:
                print(f"  {i}/{len(todo)}", flush=True)
    return out


def score(label: str) -> None:
    path = RUNS / f"primevul_{label}.raw.jsonl"
    if not path.exists():
        raise SystemExit(f"no cached run at {path}")
    rows = [json.loads(l) for l in open(path, encoding="utf-8")]
    n = len(rows)
    if not n:
        raise SystemExit("empty run")

    pc = sum(r["vuln"] == "vuln" and r["fixed"] == "safe" for r in rows)
    pv = sum(r["vuln"] == "vuln" and r["fixed"] == "vuln" for r in rows)
    pb = sum(r["vuln"] == "safe" and r["fixed"] == "safe" for r in rows)
    pr = sum(r["vuln"] == "safe" and r["fixed"] == "vuln" for r in rows)
    recall = sum(r["vuln"] == "vuln" for r in rows)
    fp = sum(r["fixed"] == "vuln" for r in rows)
    parsed = sum(r.get("vuln_parsed", True) and r.get("fixed_parsed", True) for r in rows)

    print(f"\n=== PrimeVul paired: {label}   n={n} pairs ({n*2} functions) ===")
    print(f"  P-C  pair-wise correct    {pc*100/n:5.1f}%  ({pc}/{n})   <- the real score")
    print(f"  P-V  both called vuln     {pv*100/n:5.1f}%  ({pv}/{n})   flags everything")
    print(f"  P-B  both called benign   {pb*100/n:5.1f}%  ({pb}/{n})   misses everything")
    print(f"  P-R  reversed             {pr*100/n:5.1f}%  ({pr}/{n})")
    print(f"\n  recall (vuln side)       {recall*100/n:5.1f}%")
    print(f"  FPR (patched side)       {fp*100/n:5.1f}%")
    print(f"  parsed cleanly           {parsed}/{n}")

    dominant = max([(pc, "P-C"), (pv, "P-V"), (pb, "P-B"), (pr, "P-R")])[1]
    if dominant == "P-V":
        print("\n  READ: P-V dominates — the model calls both sides vulnerable, i.e. it "
              "\n  detects the TOPIC of vulnerable code and does not read the fix. This is "
              "\n  the exact failure mode the PrimeVul paper reports across models, and it "
              "\n  matches this project's v2p result on independent data.")
    elif dominant == "P-C":
        print("\n  READ: P-C dominates — the model genuinely distinguishes fixed from "
              "vulnerable code on an external benchmark.")

    vd_s(rows)


def vd_s(rows: list[dict], targets=(0.005, 0.01, 0.05, 0.10)) -> None:
    """VD-S: false-negative rate at a fixed low false-positive rate.

    The metric a CI gate is actually configured against ("fail the build, but wake me
    at most 1% of the time"). Needs a score, so it is skipped on runs cached before
    confidence() existed.
    """
    scored = [r for r in rows if r.get("vuln_score") is not None
              and r.get("fixed_score") is not None]
    if not scored:
        print("\n  VD-S: skipped — this run has no confidence scores. Re-run to collect them.")
        return

    pos = sorted(r["vuln_score"] for r in scored)     # vulnerable side
    neg = sorted(r["fixed_score"] for r in scored)    # patched side
    print(f"\n  VD-S — false-negative rate at a fixed false-positive rate  (n={len(scored)}):")
    for fpr in targets:
        # threshold admitting at most `fpr` of patched functions
        k = int(len(neg) * (1 - fpr))
        thr = neg[min(k, len(neg) - 1)]
        fn = sum(1 for s in pos if s <= thr)
        print(f"    FPR<={fpr*100:4.1f}%  ->  VD-S (missed vulns) {fn*100/len(pos):5.1f}%  "
              f"(threshold {thr:.3f})")
    sep = sum(1 for r in scored if r["vuln_score"] > r["fixed_score"])
    print(f"    ranks the vulnerable side above its own patch in {sep*100/len(scored):.1f}% "
          f"of pairs (50% = no signal)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="leakage + pairing report only")
    ap.add_argument("--score", action="store_true", help="score a cached run")
    ap.add_argument("--label", default="v12")
    ap.add_argument("--adapter")
    ap.add_argument("--limit", type=int)
    args = ap.parse_args()

    if args.score:
        score(args.label)
        return
    pairs, _ = load_pairs()
    if args.check:
        print(f"\nready: {len(pairs)} clean pairs. Run without --check to evaluate.")
        return
    run(args.label, args.adapter, pairs, args.limit)
    score(args.label)


if __name__ == "__main__":
    main()
