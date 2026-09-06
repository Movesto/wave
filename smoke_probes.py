"""Score a model on the hand-authored guard-discrimination probes.

Reports the three numbers that matter, and the only one that can distinguish a
mechanism-reader from a confident topic-matcher is pair accuracy:

  recall     vulnerable sides called vuln    (does it still catch real bugs)
  FPR        safe sides called vuln          (alert fatigue — the headline metric)
  pair-acc   BOTH sides of a pair right      (does it actually read the guard)
  trap-FPR   safe-but-scary code called vuln (topic-matching, measured directly)

A model that flags anything resembling a vulnerability scores recall 100 / pair-acc 0.
That is not a good model with a threshold problem; it is a model that never learned the
question. The harness says so explicitly rather than leaving it to interpretation.

    python smoke_probes.py --stub                    # validate harness, no GPU
    python smoke_probes.py --stub-mode allvuln       # confirm the null model scores 0
    WAVE_ADAPTER_PATH=data/runs/v12/best/qwen_cot_v12_best python smoke_probes.py
    ... --json data/eval_runs/probes_v12.json        # save for comparison
"""
import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from probes.guard_probes import PROBES


def wrap(code: str) -> str:
    return f"<SCAN>\n{code}\n</SCAN>"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stub", action="store_true", help="no model; use --stub-mode")
    ap.add_argument("--stub-mode", default="allvuln", choices=["allvuln", "allsafe", "oracle"],
                    help="allvuln/allsafe = null models; oracle = perfect, checks the ceiling")
    ap.add_argument("--json", help="write per-probe results here")
    ap.add_argument("--show-misses", action="store_true", help="print each wrong verdict")
    args = ap.parse_args()

    pairs = [p for p in PROBES if p.get("kind") == "pair"]
    traps = [p for p in PROBES if p.get("kind") == "trap"]
    if not pairs and not traps:
        raise SystemExit("no probes defined — edit probes/guard_probes.py")

    if args.stub:
        def predict(_code: str, truth: str) -> str:
            if args.stub_mode == "allvuln":
                return "status: confirmed\ncwe: CWE-89\n"
            if args.stub_mode == "allsafe":
                return "status: safe\ncwe: none\n"
            return f"status: {'confirmed' if truth == 'vuln' else 'safe'}\n"
    else:
        from eval.inference import QwenLoraPredictor
        predictor = QwenLoraPredictor()

        def predict(code: str, _truth: str) -> str:
            return predictor.predict(wrap(code))

    from eval.parsers import parse_shape1

    def verdict(code: str, truth: str) -> tuple[str, str]:
        raw = predict(code, truth)
        status = parse_shape1(raw).get("status")
        return ("vuln" if status in ("vuln", "confirmed") else "safe"), raw

    results = []
    caught = missed_guard = both_right = 0
    for p in pairs:
        v_pred, v_raw = verdict(p["vuln"], "vuln")
        s_pred, s_raw = verdict(p["safe"], "safe")
        caught += v_pred == "vuln"
        missed_guard += s_pred == "vuln"
        ok = v_pred == "vuln" and s_pred == "safe"
        both_right += ok
        results.append({"id": p["id"], "kind": "pair", "cwe": p.get("cwe"),
                        "vuln_pred": v_pred, "safe_pred": s_pred, "pair_ok": ok,
                        "vuln_raw": v_raw, "safe_raw": s_raw})
        if args.show_misses and not ok:
            side = "flagged the PATCHED code" if s_pred == "vuln" else "missed the vuln"
            print(f"  [pair-miss] {p['id']:26} {side}   guard: {p.get('guard')}")

    trap_fp = 0
    for p in traps:
        pred, raw = verdict(p["safe"], "safe")
        trap_fp += pred == "vuln"
        results.append({"id": p["id"], "kind": "trap", "cwe": None,
                        "safe_pred": pred, "pair_ok": pred == "safe", "safe_raw": raw})
        if args.show_misses and pred == "vuln":
            print(f"  [trap-FP]   {p['id']:26} flagged safe code — {p.get('note','')[:60]}")

    np_ = len(pairs)
    label = f"stub:{args.stub_mode}" if args.stub else os.environ.get("WAVE_ADAPTER_PATH", "base")
    print(f"\n=== guard probes: {label} ===")
    print(f"  probes     {np_} pairs ({np_*2} records) + {len(traps)} traps")
    if np_:
        print(f"  recall     {caught*100//np_:3}%  ({caught}/{np_})   vulnerable side caught")
        print(f"  FPR        {missed_guard*100//np_:3}%  ({missed_guard}/{np_})   PATCHED side wrongly flagged")
        print(f"  pair-acc   {both_right*100//np_:3}%  ({both_right}/{np_})   <- reads the guard")
    if traps:
        print(f"  trap-FPR   {trap_fp*100//len(traps):3}%  ({trap_fp}/{len(traps)})   safe-but-scary code flagged")

    by_cwe = defaultdict(lambda: [0, 0])
    for r in results:
        if r["kind"] == "pair":
            by_cwe[r["cwe"]][1] += 1
            by_cwe[r["cwe"]][0] += r["pair_ok"]
    if by_cwe:
        print("\n  pair-acc by CWE:")
        for cwe, (ok, tot) in sorted(by_cwe.items(), key=lambda x: x[1][0] / x[1][1]):
            print(f"    {str(cwe):10} {ok}/{tot}")

    if np_ and both_right == 0 and caught == np_:
        print("\n  VERDICT: flags every vulnerable side and every patched side — it is not "
              "\n  reading the guard at all. Same score an always-say-vuln stub gets.")
    elif np_ and both_right * 100 // np_ >= 60:
        print("\n  VERDICT: reads the guard on most pairs — genuine mechanism discrimination.")

    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(
            {"label": label, "pairs": np_, "traps": len(traps), "recall": caught,
             "patched_fp": missed_guard, "pair_acc": both_right, "trap_fp": trap_fp,
             "results": results}, indent=1), encoding="utf-8")
        print(f"\n  -> {args.json}")


if __name__ == "__main__":
    main()
