"""Statistically honest eval bench — the instrument the 42-record smoke isn't.

The smoke samples 42 of the 1,275 held-out records. At that size the 95% CI on
accuracy is ~+/-13 points, so every version gap we've acted on (v8 66 -> v9 73 ->
v10 78) sits inside the noise band. This bench fixes three things:

  1. SIZE      — stratified sample over the whole eval set (default 400), so an
                 8-point real gap is resolvable instead of a coin flip.
  2. PAIRING   — every model scores the SAME record ids, so versions compare with
                 McNemar (paired) rather than by eyeballing two overlapping CIs.
  3. HONESTY   — Wilson CIs, balanced accuracy and MCC alongside the headline, and
                 an all-vuln-slice guard so "100% cross-file recall" can't be
                 scored as a win when the slice has no safe records to get wrong.

Predictions cache per record, so a power cut costs one record, not a run.

  python eval_bench.py plan  --n 400
  python eval_bench.py run   --label v12 --adapter data/runs/v12/best/qwen_cot_v12_best
  python eval_bench.py score --label v12
  python eval_bench.py compare --a v10 --b v12
"""
import argparse
import hashlib
import json
import math
import os
import random
from collections import Counter, defaultdict
from pathlib import Path

from eval.loader import load_eval_set

RUNS_DIR = Path("data/eval_runs")
PLAN_PATH = RUNS_DIR / "bench_plan.json"

# Shapes that carry a binary safe/vuln ground truth. shape2 (needs_context) and
# shape4 (synthesis) are judged differently and are excluded from the binary
# metrics; they get their own coverage line so their absence stays visible.
BINARY_LABELS = {"safe": "safe", "vuln": "vuln", "confirmed": "vuln"}


# ---- statistics ----

def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% CI for a proportion. Wilson, not normal-approx — at n=20 and p near 0
    or 1 the normal interval runs off the end of [0,1] and lies to you."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (100 * max(0.0, centre - half), 100 * min(1.0, centre + half))


def mcc(tp: int, tn: int, fp: int, fn: int) -> float:
    """Matthews correlation — the one binary summary that doesn't flatter a model
    for exploiting class imbalance (a flag-everything model scores ~0)."""
    num = tp * tn - fp * fn
    den = math.sqrt(float((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)))
    return num / den if den else 0.0


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value. b = A right / B wrong, c = A wrong / B
    right. Concordant records carry no information about which model is better,
    which is exactly why paired testing needs far fewer records than unpaired."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


# ---- sampling ----

def record_id(rec: dict) -> str:
    return hashlib.sha1(rec["messages"][0]["content"].encode("utf-8")).hexdigest()[:16]


def build_plan(n: int, seed: int) -> dict:
    """Stratified over shapes, balanced safe/vuln inside each shape where the
    shape has both. Sampling is by sorted record id so the plan is stable
    regardless of file order."""
    es = load_eval_set()
    rng = random.Random(seed)

    pools: dict[str, dict[str, list[dict]]] = {}
    for shape, recs in es.items():
        by_label: dict[str, list[dict]] = defaultdict(list)
        for r in recs:
            lab = BINARY_LABELS.get((r.get("_meta") or {}).get("label"))
            if lab:
                by_label[lab].append(r)
        if by_label:
            pools[shape] = by_label

    per_shape = max(1, n // max(1, len(pools)))
    plan: list[dict] = []
    for shape in sorted(pools):
        by_label = pools[shape]
        share = per_shape // len(by_label)
        for lab in sorted(by_label):
            recs = sorted(by_label[lab], key=record_id)
            rng.shuffle(recs)
            for r in recs[:share]:
                m = r.get("_meta") or {}
                plan.append({
                    "id": record_id(r),
                    "shape": shape,
                    "label": lab,
                    "cwes": m.get("cwes") or [],
                    "language": m.get("language"),
                    # carried so the scorer can compute pair accuracy and slice by
                    # capability -- without pair_id a contrastive pair is just two
                    # unrelated records and the shortcut model is invisible
                    "pair_id": m.get("pair_id"),
                    "cross_file": bool(m.get("cross_file")),
                    "counterexample": bool(m.get("weakness_class")),
                    "prompt": r["messages"][0]["content"],
                })

    # Sampling per (shape, label) can take one side of a pair and leave the other, and
    # a half-sampled pair can never be scored as a pair. Pull in every missing partner.
    have = {p["id"] for p in plan}
    want = {p["pair_id"] for p in plan if p["pair_id"]}
    for shape, recs in es.items():
        for r in recs:
            m = r.get("_meta") or {}
            lab = BINARY_LABELS.get(m.get("label"))
            if not lab or m.get("pair_id") not in want:
                continue
            rid = record_id(r)
            if rid in have:
                continue
            have.add(rid)
            plan.append({
                "id": rid, "shape": shape, "label": lab,
                "cwes": m.get("cwes") or [], "language": m.get("language"),
                "pair_id": m.get("pair_id"), "cross_file": bool(m.get("cross_file")),
                "counterexample": bool(m.get("weakness_class")),
                "prompt": r["messages"][0]["content"],
            })

    return {"seed": seed, "requested": n, "n": len(plan), "records": plan}


# ---- run ----

def run(label: str, adapter: str | None, plan: dict, limit: int | None) -> Path:
    """Generate predictions, caching each record as it completes. Re-running
    resumes: already-cached ids are skipped."""
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RUNS_DIR / f"bench_{label}.raw.jsonl"

    done: set[str] = set()
    if out_path.exists():
        with open(out_path, encoding="utf-8") as f:
            for line in f:
                try:
                    done.add(json.loads(line)["id"])
                except Exception:
                    continue
    todo = [r for r in plan["records"] if r["id"] not in done]
    if limit:
        todo = todo[:limit]
    print(f"bench_{label}: {len(done)} cached, {len(todo)} to run")
    if not todo:
        return out_path

    if adapter:
        os.environ["WAVE_ADAPTER_PATH"] = adapter
    from eval.inference import QwenLoraPredictor
    from eval.parsers import parse_shape1

    # Pass the adapter EXPLICITLY. Setting the env var above is not enough:
    # eval.config reads WAVE_ADAPTER_PATH at import time, and this module already
    # imported eval.loader (-> eval.config) at line 31, so ADAPTER_PATH was bound
    # to None long before run() executes. QwenLoraPredictor's default arg then
    # silently resolves to None and we evaluate the BASE model. That bug made
    # v10 and v12 emit byte-identical output and identical confidence scores.
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
    with open(out_path, "a", encoding="utf-8") as f:
        for i, rec in enumerate(todo, 1):
            text = predictor.predict(rec["prompt"])
            status = parse_shape1(text).get("status")
            # Collect the score in the SAME pass — it is one extra forward pass here
            # versus a whole second run over the set later.
            try:
                score_ = predictor.confidence(rec["prompt"])
            except Exception:
                score_ = None
            f.write(json.dumps({
                "id": rec["id"], "shape": rec["shape"], "label": rec["label"],
                "cwes": rec["cwes"], "language": rec["language"],
                "pair_id": rec.get("pair_id"),
                "cross_file": rec.get("cross_file", False),
                "counterexample": rec.get("counterexample", False),
                "status": status, "score": score_, "raw": text,
            }) + "\n")
            f.flush()
            if i % 25 == 0:
                print(f"  {i}/{len(todo)}", flush=True)
    return out_path


# ---- score ----

def load_run(label: str) -> list[dict]:
    path = RUNS_DIR / f"bench_{label}.raw.jsonl"
    if not path.exists():
        raise SystemExit(f"no run cached at {path} — run `eval_bench.py run --label {label}` first")
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def predicted(r: dict) -> str:
    """Verdict for one record.

    An unparsed verdict used to fall through to "safe", which is a silent failure:
    a model that rambles for 5,000 characters without emitting the fields scores as
    if it had confidently said "safe", and on a safe record it is marked CORRECT.
    Observed on v10. Where a confidence score exists, use it instead — it reflects
    what the model actually leaned toward rather than what the parser gave up on.
    """
    if r["status"] is None and r.get("score") is not None:
        return "vuln" if r["score"] >= 0.5 else "safe"
    return "vuln" if r["status"] in ("vuln", "confirmed") else "safe"


def confusion(rows: list[dict]) -> tuple[int, int, int, int, int]:
    tp = tn = fp = fn = parse_ok = 0
    for r in rows:
        gt = r["label"]
        parse_ok += r["status"] is not None
        pred = predicted(r)
        if gt == "vuln":
            tp += pred == "vuln"
            fn += pred == "safe"
        else:
            fp += pred == "vuln"
            tn += pred == "safe"
    return tp, tn, fp, fn, parse_ok


def pair_accuracy(rows: list[dict]) -> tuple[int, int]:
    """(pairs correct, pairs scored) -- a pair counts only if BOTH sides are right.

    This is the headline metric, and the reason is the failure mode the corpus was
    rebuilt to attack: a model that answers "vuln" to everything scores ~50% accuracy
    on a balanced set and looks like it learned something. Its pair accuracy is 0,
    because every pair has a safe side it got wrong. Per-record accuracy cannot tell
    a discriminator from a guesser; this can.
    """
    by_pair: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        if r.get("pair_id"):
            by_pair[r["pair_id"]].append(r)
    ok = n = 0
    for sides in by_pair.values():
        if len(sides) != 2:
            continue                    # half-sampled pair proves nothing either way
        n += 1
        ok += all(predicted(s) == s["label"] for s in sides)
    return ok, n


def _slice_line(name: str, rows: list[dict]) -> str:
    if not rows:
        return f"  {name:16s} (none)"
    tp, tn, fp, fn, _ = confusion(rows)
    ok, np_ = pair_accuracy(rows)
    acc = (tp + tn) / len(rows) * 100
    pa = f"{ok/np_*100:5.1f}% ({ok}/{np_})" if np_ else "   n/a (unpaired)"
    return (f"  {name:16s} n={len(rows):4d}  acc {acc:5.1f}%  "
            f"MCC {mcc(tp, tn, fp, fn):6.3f}  pair {pa}")


def _plan_ids() -> set[str] | None:
    """Ids in the CURRENT plan, or None if there is no plan on disk."""
    if not PLAN_PATH.exists():
        return None
    try:
        plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None
    return {r["id"] for r in plan.get("records", [])}


def score(label: str) -> None:
    rows = load_run(label)
    # Restrict to the current plan. The raw files ACCUMULATE across runs -- caching is
    # what makes them resumable -- so `bench_v12_1b.raw.jsonl` still held 369 rows from
    # the retired 369-record bench, a different eval set entirely. Scoring the whole
    # file would have mixed those in, and compared two models over different records.
    ids = _plan_ids()
    if ids:
        before = len(rows)
        rows = [r for r in rows if r["id"] in ids]
        if before != len(rows):
            print(f"  (scoring {len(rows)} of {before} cached rows — "
                  f"restricted to the current plan)")
    tp, tn, fp, fn, parse_ok = confusion(rows)
    n = len(rows)
    correct, safe_n, vuln_n = tp + tn, tn + fp, tp + fn

    acc_ci = wilson(correct, n)
    fpr_ci = wilson(fp, safe_n)
    rec_ci = wilson(tp, vuln_n)
    recall = tp / vuln_n if vuln_n else 0.0
    spec = tn / safe_n if safe_n else 0.0

    print(f"\n=== bench_{label}  n={n} ({vuln_n} vuln / {safe_n} safe) ===")
    print(f"  accuracy   {correct/n*100:5.1f}%  CI[{acc_ci[0]:.1f},{acc_ci[1]:.1f}]")
    print(f"  balanced   {(recall+spec)/2*100:5.1f}%")
    print(f"  recall     {recall*100:5.1f}%  CI[{rec_ci[0]:.1f},{rec_ci[1]:.1f}]   ({tp}/{vuln_n})")
    print(f"  FPR        {fp/max(safe_n,1)*100:5.1f}%  CI[{fpr_ci[0]:.1f},{fpr_ci[1]:.1f}]   ({fp}/{safe_n})")
    print(f"  MCC        {mcc(tp, tn, fp, fn):5.3f}   (0 = no better than guessing the base rate)")
    pok, pn = pair_accuracy(rows)
    if pn:
        p_ci = wilson(pok, pn)
        print(f"  PAIR ACC   {pok/pn*100:5.1f}%  CI[{p_ci[0]:.1f},{p_ci[1]:.1f}]   "
              f"({pok}/{pn} pairs)   <- headline: both sides right")
    print(f"  parse      {parse_ok}/{n}")

    # Capability slices. These are the point of eval_v3 -- the C/C++ PrimeVul block
    # cannot show movement in guard discrimination or cross-file reasoning.
    print("\n  by capability:")
    print(_slice_line("cross-file", [r for r in rows if r.get("cross_file")]))
    print(_slice_line("counterexample", [r for r in rows if r.get("counterexample")]))
    print(_slice_line("single-function", [r for r in rows if not r.get("cross_file")
                                          and not r.get("counterexample")]))
    print("\n  by language:")
    for lang in sorted({r.get("language") for r in rows if r.get("language")}):
        print(_slice_line(str(lang), [r for r in rows if r.get("language") == lang]))

    unparsed = [r for r in rows if r["status"] is None]
    if unparsed:
        rescued = sum(1 for r in unparsed if r.get("score") is not None)
        lucky = sum(1 for r in unparsed if r["label"] == "safe")
        print(f"  UNPARSED   {len(unparsed)} record(s) emitted no verdict — {rescued} scored "
              f"from confidence, {len(unparsed)-rescued} still defaulted to safe.")
        if lucky:
            print(f"             {lucky} of them are safe-labelled, i.e. the old harness "
                  f"would have marked them CORRECT for failing to answer.")

    print("\n  per shape:")
    by_shape: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_shape[r["shape"]].append(r)
    for shape in sorted(by_shape):
        sub = by_shape[shape]
        s_tp, s_tn, s_fp, s_fn, _ = confusion(sub)
        s_safe, s_vuln = s_tn + s_fp, s_tp + s_fn
        acc = (s_tp + s_tn) / len(sub) * 100
        flag = ""
        if s_safe == 0:
            flag = "  <- ALL VULN: recall here is unfalsifiable (no safe record to get wrong)"
        elif s_vuln == 0:
            flag = "  <- ALL SAFE: measures FPR only"
        print(f"    {shape:22} n={len(sub):4}  acc={acc:5.1f}%  "
              f"recall={s_tp}/{s_vuln}  FPR={s_fp}/{s_safe}{flag}")

    scored = [r for r in rows if r.get("score") is not None]
    if scored:
        pos = [r["score"] for r in scored if r["label"] == "vuln"]
        neg = [r["score"] for r in scored if r["label"] == "safe"]
        if pos and neg:
            # AUC via rank-sum: threshold-free, so it separates "can't rank" from
            # "ranks fine but the cut is in the wrong place".
            alls = sorted(((s, 1) for s in pos), key=lambda x: x[0])
            merged = sorted([(s, 1) for s in pos] + [(s, 0) for s in neg])
            ranks = {}
            for i, (s, _) in enumerate(merged, 1):
                ranks.setdefault(s, []).append(i)
            rsum = sum(sum(ranks[s]) / len(ranks[s]) for s in pos)
            auc = (rsum - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))
            print(f"\n  AUC        {auc:5.3f}   (0.5 = cannot rank vuln above safe at all)")
            if auc >= 0.75 and correct / n < 0.75:
                print("             ranking is better than the verdicts — the threshold is "
                      "misplaced, not the model")

    fams = Counter()
    fam_hit = Counter()
    for r in rows:
        if r["label"] != "vuln":
            continue
        for cwe in (r["cwes"] or ["untagged"]):
            fams[cwe] += 1
            fam_hit[cwe] += r["status"] in ("vuln", "confirmed")
    if fams:
        print("\n  weakest CWEs (recall, n>=5):")
        weak = [(fam_hit[c] / fams[c], c, fam_hit[c], fams[c]) for c in fams if fams[c] >= 5]
        for rate, cwe, hit, tot in sorted(weak)[:8]:
            print(f"    {cwe:14} {rate*100:5.1f}%  ({hit}/{tot})")


def compare(a: str, b: str) -> None:
    """Paired comparison on the records both runs share."""
    rows_a = {r["id"]: r for r in load_run(a)}
    rows_b = {r["id"]: r for r in load_run(b)}
    shared = sorted(set(rows_a) & set(rows_b))
    # Intersecting ids already excludes rows from a different eval set, but pin it to
    # the current plan as well so a comparison can never quietly widen to whatever two
    # accumulated raw files happen to have in common.
    ids = _plan_ids()
    if ids:
        shared = [i for i in shared if i in ids]
    if not shared:
        raise SystemExit("no shared record ids — were both runs built from the same plan?")

    def right(r: dict) -> bool:
        return predicted(r) == r["label"]

    only_a = sum(right(rows_a[i]) and not right(rows_b[i]) for i in shared)
    only_b = sum(right(rows_b[i]) and not right(rows_a[i]) for i in shared)
    both = sum(right(rows_a[i]) and right(rows_b[i]) for i in shared)
    p = mcnemar_exact(only_a, only_b)

    acc_a = (both + only_a) / len(shared) * 100
    acc_b = (both + only_b) / len(shared) * 100
    print(f"\n=== paired: {a} vs {b}  on {len(shared)} shared records ===")
    print(f"  {a:12} accuracy {acc_a:5.1f}%")
    print(f"  {b:12} accuracy {acc_b:5.1f}%   (delta {acc_b-acc_a:+.1f} pts)")
    print(f"  discordant: {only_a} only-{a} right, {only_b} only-{b} right")
    print(f"  McNemar exact p = {p:.4f}")
    if p < 0.05:
        better = b if only_b > only_a else a
        print(f"  -> the gap is real at p<0.05: {better} is genuinely better.")
    else:
        need = math.ceil((only_a + only_b) * (2.5 if p < 0.2 else 6))
        print(f"  -> NOT significant. This gap is consistent with noise; you would need "
              f"roughly {need} discordant records to call it.")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_plan = sub.add_parser("plan", help="build the stratified sample (CPU only)")
    p_plan.add_argument("--n", type=int, default=400)
    p_plan.add_argument("--seed", type=int, default=11)

    p_run = sub.add_parser("run", help="generate predictions (needs the GPU)")
    p_run.add_argument("--label", required=True)
    p_run.add_argument("--adapter")
    p_run.add_argument("--limit", type=int)

    p_score = sub.add_parser("score", help="score a cached run (CPU only)")
    p_score.add_argument("--label", required=True)

    p_cmp = sub.add_parser("compare", help="paired McNemar between two runs (CPU only)")
    p_cmp.add_argument("--a", required=True)
    p_cmp.add_argument("--b", required=True)

    args = ap.parse_args()

    if args.cmd == "plan":
        plan = build_plan(args.n, args.seed)
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        PLAN_PATH.write_text(json.dumps(plan, indent=1), encoding="utf-8")
        counts = Counter((r["shape"], r["label"]) for r in plan["records"])
        print(f"plan: {plan['n']} records -> {PLAN_PATH}")
        for shape in sorted({s for s, _ in counts}):
            v, s_ = counts[(shape, "vuln")], counts[(shape, "safe")]
            print(f"  {shape:22} vuln={v:3}  safe={s_:3}" +
                  ("   <- no safe records exist for this shape" if v and not s_ else ""))
    elif args.cmd == "run":
        if not PLAN_PATH.exists():
            raise SystemExit("no plan — run `eval_bench.py plan` first")
        run(args.label, args.adapter, json.loads(PLAN_PATH.read_text(encoding="utf-8")), args.limit)
    elif args.cmd == "score":
        score(args.label)
    elif args.cmd == "compare":
        compare(args.a, args.b)


if __name__ == "__main__":
    main()
