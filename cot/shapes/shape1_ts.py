# ============================================================
# cot/shapes/shape1_ts.py
#
# Shape 1, TypeScript-only. R2Vul (97% of the main shape1 pool)
# has zero TypeScript, so TS coverage is starved. This variant
# mines TS records from morefixes/cvefixes/clean/hand and runs
# them through the SAME shape1 prompt + verify (incl. the safe-
# verdict normalizer).
#
# Run:  python run_pilot.py shape1_ts --target 1700
# Output: data/cot/pilot/shape1_ts.jsonl
# ============================================================
from typing import Optional

from . import shape1

name = "shape1_ts"


def prepare_tasks(limit: int) -> list[dict]:
    # Vuln-only: the teacher over-flags safe TS, so safe tasks just get
    # discarded. Safe TS comes from shape1_ts_safe instead.
    return shape1.prepare_tasks_for_languages(
        {"typescript"}, limit, id_prefix="shape1_ts", only_label="vuln", seed=123
    )


def build_prompt(task: dict) -> tuple[Optional[str], str]:
    return shape1.build_prompt(task)


def verify(task: dict, generated_text: str) -> Optional[dict]:
    return shape1.verify(task, generated_text)
