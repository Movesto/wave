# ============================================================
# cot/shapes/shape1_ts_safe.py
#
# Safe TypeScript Shape-1 traces via the safe-only generator
# (the teacher never judges vuln/safe, so it can't over-flag).
# Pairs with shape1_ts (vuln-only) to restore the safe:vuln balance.
#
# Run:  python run_pilot.py shape1_ts_safe --target 600
# Output: data/cot/pilot/shape1_ts_safe.jsonl
# ============================================================
from typing import Optional

from . import _safe_core

name = "shape1_ts_safe"


def prepare_tasks(limit: int) -> list[dict]:
    return _safe_core.prepare_safe_tasks(
        {"typescript"}, limit, id_prefix="shape1_ts_safe", seed=223
    )


def build_prompt(task: dict) -> tuple[Optional[str], str]:
    return _safe_core.build_prompt(task)


def verify(task: dict, generated_text: str) -> Optional[dict]:
    return _safe_core.verify(task, generated_text)
