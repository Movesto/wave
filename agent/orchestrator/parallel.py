"""Tiny fan-out helper for the model-heavy stages (notebook / detect / patch / reconcile).

Same shape wave's prove stage uses: run COMPUTE concurrently (parallel-safe model API + docker work), but
COMMIT on the MAIN thread only (all shared state -- jsonl appends, CaseFile, prints -- is serialized). Bounded
by `jobs`; warms on item #1 (so any one-time image/cache build happens once before the pool fans out).
"""
from __future__ import annotations


def is_cloud_model(model):
    """A remote API model (OpenRouter/GLM) is safe to call concurrently; a LOCAL model (ollama or in-process
    transformers) is single-GPU and must stay serial. Mirrors model._is_local_api."""
    if model is None:
        return False
    return bool(getattr(model, "api_base", None)) and not getattr(model, "_is_local_api", True)


def fan_out(items, compute, commit, jobs, warm=True):
    """items -> for each, compute(item, i) (parallel-safe) then commit(item, result, i) (MAIN THREAD ONLY).
    `compute` must be exception-safe (return a usable result, never raise). Serial when jobs<=1 or <=1 item."""
    items = list(items)
    if jobs <= 1 or len(items) <= 1:
        for i, it in enumerate(items, 1):
            commit(it, compute(it, i), i)
        return
    from concurrent.futures import ThreadPoolExecutor, as_completed
    start = 0
    if warm:                                                # do #1 alone to warm any one-time image/cache build
        commit(items[0], compute(items[0], 1), 1)
        start = 1
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = {ex.submit(compute, it, i): (it, i) for i, it in enumerate(items[start:], start + 1)}
        for fut in as_completed(futs):
            it, i = futs[fut]
            commit(it, fut.result(), i)
