"""Phase 5 of the investigation loop: the EDITOR -- the coordinator. It never confirms anything itself
(the rungs do that); it decides WHAT to test and IN WHAT ORDER, and when to STOP.

- Prioritization: severity x confidence x reachability. High-severity, clearly-reachable, high-
  confidence hypotheses go first; speculative ones wait (and may never run if the budget ends).
- Termination: a budget bounds the work so a large app stays tractable -- the rest are recorded as
  `deferred (budget)`, not silently dropped. (Diminishing-returns / anti-spin matter once the loop
  becomes iterative -- Reader revisits, model-proposed tests -- and attach here.)
- Refutation is first-class, and the Case File is the editorial report; both live in recorder.py.
"""
from __future__ import annotations

# rough per-CWE severity (higher = worse) -- used only to ORDER work, never to decide a verdict
_SEVERITY = {
    "CWE-78": 10, "CWE-94": 10, "CWE-95": 10, "CWE-77": 10, "CWE-89": 9, "CWE-502": 9, "CWE-943": 9,
    "CWE-918": 8, "CWE-611": 8, "CWE-90": 8, "CWE-1336": 8, "CWE-22": 7, "CWE-915": 7, "CWE-79": 6,
    "CWE-639": 6, "CWE-472": 6, "CWE-840": 6, "CWE-1284": 6, "CWE-682": 6, "CWE-620": 5, "CWE-837": 5,
    "CWE-307": 4, "CWE-1333": 4,
}
# how much we trust the SOURCE that raised the hypothesis (orders work; never a verdict)
_CONFIDENCE = {"taint": 0.9, "differential": 0.85, "behavioral": 0.8, "pattern": 0.8, "reader": 0.6}


def _subj(c):
    return f"{c.cwe} {c.route_hint or c.loc()}"


def score(candidate, reachable=False):
    sev = _SEVERITY.get(getattr(candidate, "cwe", ""), 5)
    conf = _CONFIDENCE.get(getattr(candidate, "detector", ""), 0.7)
    reach = 1.5 if reachable else 1.0                   # Rung 0 said user input provably reaches the sink
    return sev * conf * reach


def prioritize(candidates, reachable_subjects=frozenset()):
    """Highest-value first: severity x confidence x reachability."""
    return sorted(candidates, key=lambda c: score(c, _subj(c) in reachable_subjects), reverse=True)


def apply_budget(candidates, budget):
    """Split into (worked, deferred-by-budget). `candidates` must already be prioritized."""
    if budget is None or len(candidates) <= budget:
        return list(candidates), []
    return list(candidates[:budget]), list(candidates[budget:])


def summary(case, budget_deferred=0):
    return (f"[editor] {len(case.findings())} confirmed, {len(case.refuted())} refuted-safe, "
            f"{len(case.blocked())} blocked, {budget_deferred} deferred (budget)")
