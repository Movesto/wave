# ============================================================
# cot/shapes/shape1_react.py
#
# Shape 1, React-only (real code). React is the scarcest target:
# ~284 snippets exist across all sources, ~237 in morefixes. This
# variant mines every real React record it can and runs it through
# the shape1 prompt + verify. The remaining gap to JS parity is
# filled separately by shape_react_syn (synthetic).
#
# Run:  python run_pilot.py shape1_react --target 200
# Output: data/cot/pilot/shape1_react.jsonl
# ============================================================
from typing import Optional

from . import shape1

name = "shape1_react"


def prepare_tasks(limit: int) -> list[dict]:
    # Vuln-only: the teacher over-flags safe React, so safe tasks just get
    # discarded. Safe React comes from shape1_react_safe instead.
    return shape1.prepare_tasks_for_languages(
        {"react"}, limit, id_prefix="shape1_react", only_label="vuln", seed=124
    )


def build_prompt(task: dict) -> tuple[Optional[str], str]:
    return shape1.build_prompt(task)


def verify(task: dict, generated_text: str) -> Optional[dict]:
    return shape1.verify(task, generated_text)
