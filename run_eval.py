"""Eval harness entrypoint.

Modes:
  python run_eval.py sanity                     # gold + perturbed stubs, no API
  python run_eval.py eval --label baseline_v1   # run real Qwen+LoRA inference
  python run_eval.py eval --stub gold --label gold_sanity
  python run_eval.py compare A.json B.json      # diff two runs

Layer 1 (deterministic) ALWAYS runs. Layer 2 (LLM judge) runs only if
ANTHROPIC_API_KEY is set and --skip-judge is not passed.
"""
import argparse
import json
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from eval.config import EVAL_SET_DIR, PREDICTIONS_DIR
from eval.loader import load_eval_set, extract_ground_truth, SHAPES
from eval.parsers import parse_for_shape
from eval.scoring import SHAPE_SCORERS
from eval.report import write_run, print_dashboard
from eval.compare import compare_runs
from eval.inference import GoldStubPredictor, PerturbedStubPredictor


# ============================================================
# core: run predictions, score, save
# ============================================================

def run_predictions(predictor, eval_set: dict[str, list[dict]], label: str = "run") -> dict[str, list[dict]]:
    """Drive the predictor over the eval set. Return per-shape prediction records.

    Each prediction record = {ground_truth, raw_text, parsed, user_input}.

    Resumable: each raw model output is appended to `<label>.raw.jsonl` (flushed
    per record) and re-loaded on restart, so a crash — or a bug in scoring — never
    forces re-running inference. Parsing happens AFTER all inference completes, so a
    parser error can't lose generation work.
    """
    import time, hashlib
    raw_path = PREDICTIONS_DIR / f"{label}.raw.jsonl"

    def _key(shape, user):
        return hashlib.sha256((shape + "\x00" + user).encode("utf-8")).hexdigest()

    cache: dict[str, str] = {}
    if raw_path.exists():
        for line in open(raw_path, encoding="utf-8"):
            try:
                d = json.loads(line)
                cache[d["key"]] = d["raw_text"]
            except Exception:
                continue
        print(f"[resume] loaded {len(cache)} cached predictions from {raw_path.name}", flush=True)

    out: dict[str, list[dict]] = {s: [] for s in SHAPES}
    total = sum(len(rs) for rs in eval_set.values())
    done = 0
    t_start = time.time()
    raw_f = open(raw_path, "a", encoding="utf-8")
    for shape, records in eval_set.items():
        print(f"\n[{shape}] {len(records)} records", flush=True)
        for r in records:
            msgs = r.get("messages", [])
            if len(msgs) < 2:
                continue
            user = msgs[0]["content"]
            gt = extract_ground_truth(r)
            k = _key(shape, user)
            done += 1
            if k in cache:
                raw = cache[k]
            else:
                t0 = time.time()
                raw = predictor.predict(user)
                t_record = time.time() - t0
                raw_f.write(json.dumps({"key": k, "shape": shape, "raw_text": raw}, ensure_ascii=False) + "\n")
                raw_f.flush()
                elapsed = time.time() - t_start
                eta = elapsed / max(done, 1) * (total - done)
                print(f"  [{done:>3}/{total}] {shape} t={t_record:.1f}s "
                      f"out_chars={len(raw)} elapsed={elapsed/60:.1f}m eta={eta/60:.1f}m",
                      flush=True)
            out[shape].append({
                "ground_truth": gt,
                "raw_text":     raw,
                "user_input":   user,
            })
    raw_f.close()

    # Parse AFTER all inference is captured, so a parser bug can't waste generation.
    for shape, preds in out.items():
        for p in preds:
            p["parsed"] = parse_for_shape(shape, p["raw_text"])
    return out


def save_predictions(label: str, predictions: dict) -> Path:
    path = PREDICTIONS_DIR / f"{label}.jsonl"
    with open(path, "w", encoding="utf-8") as f:
        for shape, preds in predictions.items():
            for p in preds:
                f.write(json.dumps({
                    "shape":  shape,
                    "gt":     p["ground_truth"],
                    "raw":    p["raw_text"],
                    "parsed": p["parsed"],
                    "user":   p["user_input"],
                }, ensure_ascii=False) + "\n")
    return path


def score_all(predictions: dict) -> dict:
    return {shape: SHAPE_SCORERS[shape](preds) for shape, preds in predictions.items()}


def run_layer2_judge(predictions: dict, max_per_shape: int = 10) -> dict:
    """Optional Layer 2 judge. Caps per-shape to avoid runaway cost."""
    try:
        from eval import judge
    except Exception as e:
        print(f"[judge] import failed: {e}")
        return {}

    scores: dict[str, dict] = {}
    for shape in ("shape1", "shape2", "shape3", "shape4"):
        preds = predictions.get(shape) or []
        if not preds:
            continue
        sample = preds[:max_per_shape]
        if shape in ("shape1", "shape3"):
            fq, rf = [], []
            for p in sample:
                gt = p["ground_truth"]
                code = p["user_input"]
                gt_label = gt.get("label") or gt.get("disposition") or "unknown"
                gt_cwe = (gt.get("cwes") or [None])[0]
                res = judge.judge_shape1_3(code, gt_label, gt_cwe, p["raw_text"])
                if not res:
                    continue
                fq.append(res.get("fix_quality", 0))
                rf.append(res.get("reasoning_faithfulness", 0))
            scores[shape] = {
                "fix_quality_mean":           (sum(fq) / len(fq)) if fq else 0.0,
                "reasoning_faithfulness_mean": (sum(rf) / len(rf)) if rf else 0.0,
                "judged_count":               len(fq),
            }
        elif shape == "shape4":
            dc, sr, si, hf = [], [], [], []
            for p in sample:
                res = judge.judge_shape4(p["user_input"], p["raw_text"])
                if not res:
                    continue
                dc.append(res.get("dedup_clustering", 0))
                sr.append(res.get("severity_ranking", 0))
                si.append(res.get("systemic_insight", 0))
                hf.append(res.get("hallucination_freedom", 0))
            n = len(dc)
            scores[shape] = {
                "dedup_clustering_mean":      (sum(dc) / n) if n else 0.0,
                "severity_ranking_mean":      (sum(sr) / n) if n else 0.0,
                "systemic_insight_mean":      (sum(si) / n) if n else 0.0,
                "hallucination_freedom_mean": (sum(hf) / n) if n else 0.0,
                "judged_count":               n,
            }
        # shape2 has no judge metric — Layer 1 fully covers it.
    return scores


# ============================================================
# modes
# ============================================================

def cmd_sanity(args):
    """Run two predictors (gold + perturbed) end-to-end. Headline FPR on gold
    should be ~0%; perturbed should show measurable degradation."""
    eval_set = load_eval_set(EVAL_SET_DIR)
    nz = {s: len(rs) for s, rs in eval_set.items()}
    if all(v == 0 for v in nz.values()):
        print("ERROR: eval set is empty. Run split_pilot_to_eval.py first.")
        sys.exit(1)
    print(f"Eval set sizes: {nz}\n")

    gold = GoldStubPredictor(eval_set)
    gold_preds = run_predictions(gold, eval_set)
    gold_l1 = score_all(gold_preds)
    save_predictions("sanity_gold", gold_preds)
    p_gold = write_run("sanity_gold", gold.name, max(nz.values()), gold_l1)
    print_dashboard("sanity_gold (predictor=gold_stub)", gold_l1)
    print(f"  Wrote: {p_gold}\n")

    perturbed = PerturbedStubPredictor(eval_set, flip_rate=args.flip_rate, seed=1)
    pert_preds = run_predictions(perturbed, eval_set)
    pert_l1 = score_all(pert_preds)
    save_predictions("sanity_perturbed", pert_preds)
    p_pert = write_run(f"sanity_perturbed_p{args.flip_rate}", perturbed.name, max(nz.values()), pert_l1)
    print_dashboard(f"sanity_perturbed (flip_rate={args.flip_rate})", pert_l1)
    print(f"  Wrote: {p_pert}\n")

    print("Sanity expectation: gold should score perfectly on Layer 1; perturbed should regress.")
    print(f"  Compare with: python run_eval.py compare {p_gold.name} {p_pert.name}")


def cmd_eval(args):
    """Run a real eval. Defaults to GoldStubPredictor if --stub is set."""
    eval_set = load_eval_set(EVAL_SET_DIR)
    if all(len(v) == 0 for v in eval_set.values()):
        print("ERROR: eval set is empty. Run split_pilot_to_eval.py first.")
        sys.exit(1)

    if args.stub == "gold":
        predictor = GoldStubPredictor(eval_set)
    elif args.stub == "perturbed":
        predictor = PerturbedStubPredictor(eval_set, flip_rate=args.flip_rate, seed=1)
    else:
        from eval.inference import QwenLoraPredictor
        predictor = QwenLoraPredictor()

    preds = run_predictions(predictor, eval_set, label=args.label)
    save_predictions(args.label, preds)
    layer1 = score_all(preds)

    layer2 = None
    if not args.skip_judge:
        layer2 = run_layer2_judge(preds, max_per_shape=args.judge_per_shape)

    nps = max(len(v) for v in eval_set.values())
    path = write_run(args.label, predictor.name, nps, layer1, layer2)
    print_dashboard(args.label, layer1, layer2)
    print(f"  Wrote run: {path}")


def cmd_compare(args):
    from eval.config import RUNS_DIR
    a = Path(args.run_a)
    b = Path(args.run_b)
    if not a.is_absolute():
        a = RUNS_DIR / a
    if not b.is_absolute():
        b = RUNS_DIR / b
    compare_runs(a, b)


# ============================================================
# CLI
# ============================================================

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="mode", required=True)

    s = sub.add_parser("sanity", help="Run gold + perturbed stub end-to-end")
    s.add_argument("--flip-rate", type=float, default=0.2)
    s.set_defaults(func=cmd_sanity)

    e = sub.add_parser("eval", help="Run a real eval (writes a run file)")
    e.add_argument("--label", required=True, help="Short run label (used in filename)")
    e.add_argument("--stub", choices=["gold", "perturbed"], default=None,
                   help="Use a stub predictor instead of Qwen+LoRA")
    e.add_argument("--flip-rate", type=float, default=0.2)
    e.add_argument("--skip-judge", action="store_true", help="Skip Layer-2 LLM judge")
    e.add_argument("--judge-per-shape", type=int, default=10,
                   help="Cap on judged examples per shape (cost control)")
    e.set_defaults(func=cmd_eval)

    c = sub.add_parser("compare", help="Diff two run files")
    c.add_argument("run_a")
    c.add_argument("run_b")
    c.set_defaults(func=cmd_compare)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
