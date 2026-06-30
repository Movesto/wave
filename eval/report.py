# ============================================================
# eval/report.py
#
# Write a run-file (JSON) and print a top-line dashboard.
# Run-files live in data/eval_runs/<timestamp>_<label>.json and
# carry everything needed to compare runs apples-to-apples:
# model, adapter, config, git commit, metrics, slices.
# ============================================================
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from .config import (
    RUNS_DIR,
    BASE_MODEL,
    ADAPTER_PATH,
    GEN_TEMPERATURE,
    GEN_SEED,
    GEN_MAX_NEW_TOKENS,
    ENABLE_THINKING,
    JUDGE_MODEL,
    JUDGE_VERSION,
)


def _git_commit() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True, timeout=5,
        )
        return out.stdout.strip()
    except Exception:
        return None


def write_run(
    label: str,
    predictor_name: str,
    n_per_shape: int,
    layer1: dict[str, dict],
    layer2: dict[str, dict] | None = None,
) -> Path:
    """Persist a run. Returns the written path."""
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    fname = f"{ts}_{label}.json"
    path = RUNS_DIR / fname

    payload = {
        "label":     label,
        "timestamp": ts,
        "git_commit": _git_commit(),
        "config": {
            "base_model":         BASE_MODEL,
            "adapter_path":       ADAPTER_PATH,
            "predictor_name":     predictor_name,
            "gen_temperature":    GEN_TEMPERATURE,
            "gen_seed":           GEN_SEED,
            "gen_max_new_tokens": GEN_MAX_NEW_TOKENS,
            "enable_thinking":    ENABLE_THINKING,
            "judge_model":        JUDGE_MODEL,
            "judge_version":      JUDGE_VERSION,
            "n_per_shape":        n_per_shape,
        },
        "layer1": layer1,
        "layer2": layer2 or {},
    }
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


def _fmt(x, kind: str = "pct") -> str:
    if x is None:
        return "  -  "
    if kind == "pct":
        return f"{100*x:6.2f}%"
    if kind == "int":
        return f"{int(x):>5}"
    if kind == "score":
        return f"{x:.2f}"
    return str(x)


def print_dashboard(label: str, layer1: dict, layer2: dict | None = None, stream=sys.stdout) -> None:
    def w(s=""):
        stream.write(s + "\n")

    bar = "=" * 72
    w()
    w(bar)
    w(f"  EVAL RUN: {label}")
    w(bar)

    s1 = layer1.get("shape1", {})
    s2 = layer1.get("shape2", {})
    s3 = layer1.get("shape3", {})
    s4 = layer1.get("shape4", {})

    w()
    w("  TOP-LINE METRICS (Layer 1, deterministic)")
    w("  ----------------------------------------")
    w(f"    Shape 1 FPR on safe  (headline) : {_fmt(s1.get('headline_fpr_on_safe'))}")
    w(f"    Shape 1 recall on vuln          : {_fmt(s1.get('recall_on_vuln'))}")
    w(f"    Shape 1 precision               : {_fmt(s1.get('precision'))}")
    w(f"    Shape 1 F1                      : {_fmt(s1.get('f1'))}")
    w(f"    Shape 1 CWE accuracy (flagged)  : {_fmt(s1.get('cwe_accuracy_when_flagged'))}")
    w()
    w(f"    Shape 2 ask-don't-guess rate    : {_fmt(s2.get('ask_dont_guess_rate'))}")
    w(f"    Shape 2 correct-symbol rate     : {_fmt(s2.get('correct_symbol_rate'))}")
    w(f"    Shape 2 hallucinated verdicts   : {_fmt(s2.get('hallucinated_verdict'), 'int')}")
    w()
    w(f"    Shape 3 confirm accuracy        : {_fmt(s3.get('confirm_accuracy'))}")
    w(f"    Shape 3 dismiss accuracy        : {_fmt(s3.get('dismiss_accuracy'))}")
    w(f"    Shape 3 multi-hop ref rate      : {_fmt(s3.get('multi_hop_correct_ref_rate'))}")
    w()
    w(f"    Shape 4 well-formed rate        : {_fmt(s4.get('well_formed_rate'))}")
    w(f"    Shape 4 severity-monotonic rate : {_fmt(s4.get('severity_monotonic_rate'))}")
    w(f"    Shape 4 no-hallucination rate   : {_fmt(s4.get('no_hallucination_rate'))}")

    if s1.get("by_language"):
        w()
        w("  SHAPE 1 SLICES (by language)")
        w("  ----------------------------")
        for lang, c in sorted(s1["by_language"].items()):
            denom = c.get("FP", 0) + c.get("TN", 0)
            fpr = (c.get("FP", 0) / denom) if denom else None
            w(f"    {lang:12s}  FPR={_fmt(fpr)}  TP/FP/FN/TN = {c.get('TP', 0)}/{c.get('FP', 0)}/{c.get('FN', 0)}/{c.get('TN', 0)}")

    if s1.get("by_cwe"):
        w()
        w("  SHAPE 1 SLICES (by CWE, vuln subset)")
        w("  ------------------------------------")
        for cwe, c in sorted(s1["by_cwe"].items()):
            denom = c.get("TP", 0) + c.get("FN", 0)
            recall = (c.get("TP", 0) / denom) if denom else None
            w(f"    {cwe:12s}  recall={_fmt(recall)}  TP/FN = {c.get('TP', 0)}/{c.get('FN', 0)}")

    if layer2:
        w()
        w("  LAYER 2 (LLM judge, trend indicator)")
        w("  ------------------------------------")
        for shape, metrics in layer2.items():
            w(f"    {shape}:")
            for k, v in metrics.items():
                w(f"      {k:30s}  {_fmt(v, 'score')}")

    w()
    w(bar)
    w()
