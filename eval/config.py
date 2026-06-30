# ============================================================
# eval/config.py
#
# Pinned configuration. Everything that affects comparability
# across runs lives here so a metric delta is a real change,
# not noise. DO NOT change these between runs without renaming
# the eval set / bumping a version.
# ============================================================
import os
from pathlib import Path

# ---- Model under test (set per run via env or CLI) ----
BASE_MODEL = os.environ.get("WAVE_BASE_MODEL", "Qwen/Qwen3-8B")
ADAPTER_PATH = os.environ.get("WAVE_ADAPTER_PATH")  # required for real eval; None for stub

# ---- Generation (match the deployment config exactly) ----
GEN_TEMPERATURE = 0.0
GEN_SEED = 42
GEN_MAX_NEW_TOKENS = 2048
THINKING_BUDGET = 1500
ENABLE_THINKING = True

# ---- Judge (Layer 2). Pinned so judge noise doesn't show up as model deltas ----
JUDGE_MODEL = "claude-sonnet-4-6"
JUDGE_TEMPERATURE = 0.0
JUDGE_MAX_TOKENS = 800
JUDGE_VERSION = "v1"   # bump if the judge prompt changes — invalidates old run scores

# ---- Paths ----
ROOT = Path(__file__).resolve().parent.parent
COT_DIR = ROOT / "data" / "cot"
EVAL_SET_DIR = COT_DIR / "eval"
PILOT_DIR = COT_DIR / "pilot"
RUNS_DIR = ROOT / "data" / "eval_runs"
PREDICTIONS_DIR = ROOT / "data" / "eval_predictions"

for d in (RUNS_DIR, PREDICTIONS_DIR, EVAL_SET_DIR):
    d.mkdir(parents=True, exist_ok=True)


# ---- Holdout creation defaults (when splitting pilot -> eval) ----
HOLDOUT_PER_SHAPE = 150     # workflow target (150-300). Capped per shape by HOLDOUT_MAX_FRAC.
HOLDOUT_MAX_FRAC = 0.30     # never hold out more than this fraction of a shape (protects scarce shapes)
HOLDOUT_SEED = 999          # fixed so the split is reproducible


def require_anthropic_key() -> str:
    k = os.environ.get("ANTHROPIC_API_KEY")
    if not k:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. Judge (Layer 2) will be skipped; "
            "Layer 1 deterministic scoring will still run."
        )
    return k
