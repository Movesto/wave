# ============================================================
# cot/shapes/shape1_verified_safe.py
#
# Verified-SAFE counterpart to shape1_verified. The fixed-code side
# of each patch is safe by construction (it's the CVE's patch, often
# WITH the defense added) — the best low-FPR training signal: real
# code that looks risky but is defended.
#
# Reuses the safe-only generator (cot/shapes/_safe_core): the teacher
# is told the code is safe and only explains WHY (it never judges,
# so it can't over-flag). Sourced from the same patches as the vuln
# set, so it rebalances the verified vuln data and prevents the FPR
# regression vuln-only data causes.
#
# Run:  python run_verified.py is vuln-only; use run_pilot for this:
#   python run_pilot.py shape1_verified_safe --target 400
# Output: data/cot/pilot/shape1_verified_safe.jsonl
# ============================================================
import os
from typing import Optional

from . import _safe_core
from ..fix_pairs import iter_fix_pairs

name = "shape1_verified_safe"


def _target_languages() -> set[str]:
    raw = os.environ.get("WAVE_VERIFIED_LANGS", "typescript,javascript,python,react")
    return {x.strip() for x in raw.split(",") if x.strip()}


def prepare_tasks(limit: int) -> list[dict]:
    """The FIXED (patched, safe) code from each patch becomes a safe sample."""
    langs = _target_languages()
    tasks: list[dict] = []
    seen: set[str] = set()
    for fp in iter_fix_pairs(languages=langs):
        code = (fp.get("fixed_code") or "").strip()
        if not code or len(code) < 60 or len(code) > 1500:
            continue
        if code in seen:
            continue
        seen.add(code)
        tasks.append({
            "task_id": f"shape1_verified_safe:{fp['source']}:{fp['language']}:{len(tasks)}",
            "code": code,
            "language": fp["language"],
            "label": "safe",
            "source": "verified_safe",
        })
        if len(tasks) >= limit:
            break
    return tasks


def build_prompt(task: dict) -> tuple[Optional[str], str]:
    return _safe_core.build_prompt(task)


def verify(task: dict, generated_text: str) -> Optional[dict]:
    rec = _safe_core.verify(task, generated_text)
    if rec is not None:
        rec["_meta"]["source"] = "verified_safe"
    return rec
