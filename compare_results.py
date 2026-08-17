"""One-look results comparison for the regen training run: base vs trained, side by side.

Reads what the runbook produces -- the two smoke_v2p raw dumps and the training metrics -- and
prints the numbers that matter without re-running the GPU:

  V2P (semantic trap): vuln-recall, patched-FPR (lower=better), pair-accuracy -- base vs trained
  eval_v2 pair-accuracy (the repo-disjoint holdout that drives best-model selection) -- trained
  patched-FPR broken down by CWE and language -- so you see WHERE the trap improved

  python compare_results.py
  python compare_results.py --base data/eval_runs/v2p_base.raw.jsonl \
                            --trained data/eval_runs/v2p_qwen_cot_best.raw.jsonl
"""
import argparse, json, os, sys
from collections import defaultdict
sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def load(path):
    if not path or not os.path.exists(path):
        return None
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


def metrics(rows):
    n = len(rows)
    recall = sum(1 for r in rows if r["vuln_verdict"] == "vuln")
    pfp = sum(1 for r in rows if r["fixed_verdict"] == "vuln")           # the trap
    pair = sum(1 for r in rows if r["vuln_verdict"] == "vuln" and r["fixed_verdict"] == "safe")
    return {"n": n, "recall": recall, "pfp": pfp, "pair": pair}


def pct(x, n):
    return f"{100*x/n:.0f}%" if n else "-"


def line(label, b, t, n_b, n_t, lower_better=False):
    bs, ts = pct(b, n_b), pct(t, n_t)
    d = (t / n_t - b / n_b) * 100 if (n_b and n_t) else 0
    arrow = ""
    if n_b and n_t:
        good = (d < 0) if lower_better else (d > 0)
        arrow = ("  ✓" if good and abs(d) >= 1 else ("  ✗" if not good and abs(d) >= 1 else "  ·"))
    return f"  {label:22s} base {bs:>5}   trained {ts:>5}   ({d:+.0f} pts){arrow}"


def breakdown(base, trained, key):
    """patched-FPR by CWE / language, base vs trained."""
    def agg(rows):
        d = defaultdict(lambda: [0, 0])
        for r in rows:
            k = r.get(key) or "?"
            d[k][0] += 1
            d[k][1] += (r["fixed_verdict"] == "vuln")
        return d
    b, t = agg(base), agg(trained)
    keys = sorted(set(b) | set(t), key=lambda k: -(b[k][0] + t[k][0]))[:8]
    print(f"  patched-FPR by {key}:")
    for k in keys:
        bn, bf = b[k]; tn, tf = t[k]
        print(f"    {str(k):14s} base {pct(bf,bn):>5} ({bf}/{bn})   trained {pct(tf,tn):>5} ({tf}/{tn})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="data/eval_runs/v2p_base.raw.jsonl")
    ap.add_argument("--trained", default="data/eval_runs/v2p_qwen_cot_best.raw.jsonl")
    ap.add_argument("--metrics", default="data/qwen_cot/train_metrics.jsonl")
    args = ap.parse_args()

    base, trained = load(args.base), load(args.trained)
    print("=" * 60)
    print("REGEN TRAINING RESULTS  (base vs trained)")
    print("=" * 60)

    if base and trained:
        mb, mt = metrics(base), metrics(trained)
        print(f"\nV2P semantic-trap  (n={mb['n']} base / {mt['n']} trained pairs)")
        print(line("vuln recall",   mb["recall"], mt["recall"], mb["n"], mt["n"]))
        print(line("patched-FPR",   mb["pfp"],    mt["pfp"],    mb["n"], mt["n"], lower_better=True))
        print(line("pair accuracy", mb["pair"],   mt["pair"],   mb["n"], mt["n"]))
        print()
        breakdown(base, trained, "cwe")
        print()
        breakdown(base, trained, "language")
    else:
        miss = [p for p, r in ((args.base, base), (args.trained, trained)) if r is None]
        print(f"\n  V2P raw file(s) not found: {miss}")
        print("  Run step 2 of the runbook first:")
        print("    $env:WAVE_ADAPTER_PATH='base';               python smoke_v2p.py")
        print("    $env:WAVE_ADAPTER_PATH='data\\qwen_cot_best'; python smoke_v2p.py")

    # eval_v2 pair-accuracy (trained) from training metrics
    rows = load(args.metrics)
    if rows:
        pe = [r for r in rows if r.get("type") == "pair_eval"]
        if pe:
            best = max(pe, key=lambda r: r["pair_acc"])
            print(f"\neval_v2 pair-accuracy (repo-disjoint holdout, TRAINED):")
            for r in pe:
                mark = "  <- best" if r is best else ""
                print(f"    epoch {r['epoch']}: {r['pair_acc']*100:.1f}%  ({r['ok']}/{r['n']}){mark}")
            print("  (compare to the v12.1b baseline recorded in project memory)")
    else:
        print(f"\n  {args.metrics} not found -- run training (step 1) to populate eval_v2 numbers.")


if __name__ == "__main__":
    main()
