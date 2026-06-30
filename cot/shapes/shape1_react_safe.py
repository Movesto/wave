# ============================================================
# cot/shapes/shape1_react_safe.py
#
# Safe React Shape-1 traces via the safe-only generator. Same
# rationale as shape1_ts_safe: the teacher over-flags safe code,
# so we never let it judge — it only explains why known-safe code
# is safe.
#
# Run:  python run_pilot.py shape1_react_safe --target 150
# Output: data/cot/pilot/shape1_react_safe.jsonl
# ============================================================
from typing import Optional

from . import _safe_core

name = "shape1_react_safe"


def prepare_tasks(limit: int) -> list[dict]:
    return _safe_core.prepare_safe_tasks(
        {"react"}, limit, id_prefix="shape1_react_safe", seed=224
    )


def build_prompt(task: dict) -> tuple[Optional[str], str]:
    return _safe_core.build_prompt(task)


def verify(task: dict, generated_text: str) -> Optional[dict]:
    return _safe_core.verify(task, generated_text)
