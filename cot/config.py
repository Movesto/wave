# ============================================================
# cot/config.py
#
# Single source of truth for: model selection, pricing, output
# paths, sampling caps. Edit here to retarget the pipeline.
# ============================================================
import os
from pathlib import Path

# ---- Generator model ----
# Sonnet 4.6 is the default — strong reasoning, ~5x cheaper than Opus 4.7 for
# the high-volume trace generation. Bump to claude-opus-4-7 if discard rates
# spike on the pilot and quality matters more than cost. Bump down to
# claude-haiku-4-5-20251001 only for cheap smoke tests.
GENERATOR_MODEL = os.environ.get("WAVE_GENERATOR_MODEL", "claude-sonnet-4-6")

# Low temperature — we want consistent traces, not creative ones. Workflow
# guidance: "Low temperature for consistency."
GENERATOR_TEMPERATURE = 0.2
GENERATOR_MAX_TOKENS = 2000  # think block + verdict; tune per shape if needed

# ---- Pricing (USD per 1M tokens) ----
# Sourced from Anthropic public pricing as of the project pivot date
# (2026-06-03). Update if model changes. Used ONLY for the up-front estimator;
# actual billing comes from the API.
PRICING_USD_PER_MTOK = {
    "claude-opus-4-7":         {"input": 15.00, "output": 75.00, "cache_read": 1.50},
    "claude-sonnet-4-6":       {"input":  3.00, "output": 15.00, "cache_read": 0.30},
    "claude-haiku-4-5-20251001": {"input":  1.00, "output":  5.00, "cache_read": 0.10},
}

# ---- Paths ----
REPO_ROOT = Path(__file__).resolve().parent.parent
SFT_DIR = REPO_ROOT / "data" / "sft"
COT_DIR = REPO_ROOT / "data" / "cot"
PILOT_DIR = COT_DIR / "pilot"
EVAL_DIR = COT_DIR / "eval"
FULL_DIR = COT_DIR / "full"
CHECKPOINT_DIR = COT_DIR / "_checkpoints"

# Make sure dirs exist
for d in (COT_DIR, PILOT_DIR, EVAL_DIR, FULL_DIR, CHECKPOINT_DIR):
    d.mkdir(parents=True, exist_ok=True)


# ---- Targets ----
# Full-run targets per the workflow. Per-shape pilot is 40.
SHAPE_TARGETS = {
    "shape1": 3000,  # local scan with trace, >=30% safe
    "shape2": 500,   # request missing context (anti-hallucination)
    "shape3": 1500,  # cross-file completion (~50/50 confirm/dismiss, ~15% multi-hop)
    "shape4": 500,   # whole-project synthesis
}
PILOT_PER_SHAPE = 40

# ---- Eval holdout ----
# Workflow: "Hold out a random 150-300 per shape into data\cot\eval\".
EVAL_HOLDOUT_PER_SHAPE = 200

# ---- Sampling caps to prevent any one CWE from dominating ----
# Workflow: "Cap any single CWE at ~20% of the set so SQLi doesn't dominate."
CWE_CAP_FRACTION = 0.20


# ---- API key check (fail fast) ----
def require_api_key():
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. Set it in your shell env before running the pipeline."
        )
    return key
