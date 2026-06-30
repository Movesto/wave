# ============================================================
# eval/compare.py
#
# Diff two run files. Surfaces regressions LOUDLY — the workflow
# explicitly warns about silently improving one metric while
# regressing another.
# ============================================================
import json
import sys
from pathlib import Path


# Metrics where HIGHER is better
HIGHER_IS_BETTER = {
    ("shape1", "recall_on_vuln"),
    ("shape1", "precision"),
    ("shape1", "f1"),
    ("shape1", "cwe_accuracy_when_flagged"),
    ("shape2", "ask_dont_guess_rate"),
    ("shape2", "correct_symbol_rate"),
    ("shape3", "confirm_accuracy"),
    ("shape3", "dismiss_accuracy"),
    ("shape3", "multi_hop_correct_ref_rate"),
    ("shape4", "well_formed_rate"),
    ("shape4", "severity_monotonic_rate"),
    ("shape4", "no_hallucination_rate"),
}

# Metrics where LOWER is better
LOWER_IS_BETTER = {
    ("shape1", "headline_fpr_on_safe"),
    ("shape2", "hallucination_rate"),
    ("shape2", "hallucinated_verdict"),
    ("shape1", "parse_miss"),
    ("shape2", "parse_miss"),
    ("shape3", "parse_miss"),
    ("shape4", "parse_miss"),
}


def _load(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _delta(a, b) -> float | None:
    try:
        return b - a
    except Exception:
        return None


def _direction(shape: str, metric: str, delta: float | None) -> str:
    """Return one of '+', '-', '~' relative to whether this metric improved."""
    if delta is None or delta == 0:
        return "~"
    key = (shape, metric)
    if key in HIGHER_IS_BETTER:
        return "+" if delta > 0 else "-"
    if key in LOWER_IS_BETTER:
        return "+" if delta < 0 else "-"
    return "~"


def compare_runs(run_a_path: str | Path, run_b_path: str | Path, stream=sys.stdout) -> dict:
    a = _load(Path(run_a_path))
    b = _load(Path(run_b_path))

    def w(s=""):
        stream.write(s + "\n")

    bar = "=" * 80
    w()
    w(bar)
    w(f"  COMPARE  A → B")
    w(f"    A: {a['label']}  ({a['timestamp']})  adapter={a['config'].get('adapter_path')}")
    w(f"    B: {b['label']}  ({b['timestamp']})  adapter={b['config'].get('adapter_path')}")
    w(bar)

    regressions: list[tuple[str, str, float]] = []

    for shape in ("shape1", "shape2", "shape3", "shape4"):
        a_metrics = a.get("layer1", {}).get(shape, {})
        b_metrics = b.get("layer1", {}).get(shape, {})
        if not a_metrics and not b_metrics:
            continue

        w()
        w(f"  {shape.upper()}")
        w("  " + "-" * 76)
        # Collect all top-level scalar metrics
        keys = set()
        for d in (a_metrics, b_metrics):
            for k, v in d.items():
                if isinstance(v, (int, float)):
                    keys.add(k)

        for k in sorted(keys):
            av = a_metrics.get(k)
            bv = b_metrics.get(k)
            d = _delta(av, bv)
            dirn = _direction(shape, k, d)
            marker = " "
            if dirn == "-":
                marker = "!"
                regressions.append((shape, k, d or 0))
            if d is None:
                w(f"    {marker} {k:34s}  A={av}  B={bv}")
            else:
                w(f"    {marker} {k:34s}  A={av:>10.4f}  →  B={bv:>10.4f}  Δ={d:+.4f}  {dirn}")

    if regressions:
        w()
        w("  ⚠ REGRESSIONS DETECTED ⚠")
        w("  " + "-" * 76)
        for shape, metric, d in regressions:
            w(f"    {shape}.{metric}  Δ={d:+.4f}")
    else:
        w()
        w("  No regressions on tracked metrics.")
    w()
    w(bar)
    w()

    return {
        "a_label": a["label"],
        "b_label": b["label"],
        "regressions": [{"shape": s, "metric": m, "delta": d} for s, m, d in regressions],
    }
