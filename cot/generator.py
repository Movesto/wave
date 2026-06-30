# ============================================================
# cot/generator.py
#
# Unified trace-generator interface with optional quality wrappers.
#
# Backend selection:
#   WAVE_GENERATOR_BACKEND=anthropic | local   (default: local)
#
# Quality wrappers (off by default — each multiplies GPU cost):
#   WAVE_N_SAMPLES=N           generate N candidates, return best by specificity
#   WAVE_CRITIQUE_REVISE=true  generate, critique, revise (3 model calls per record)
#
# A higher-quality bulk run might use:
#   $env:WAVE_N_SAMPLES=3
#   $env:WAVE_CRITIQUE_REVISE=false
# That ~triples GPU time but tends to lift the worst 20% of records.
# ============================================================
import os
from typing import Optional


BACKEND = os.environ.get("WAVE_GENERATOR_BACKEND", "local")


def _base_call(prompt: str, system: Optional[str] = None, **kwargs) -> dict:
    if BACKEND == "anthropic":
        from .client import call_generator as anth_call
        return anth_call(prompt, system=system, **kwargs)
    if BACKEND == "local":
        from .local_client import call_generator as local_call
        return local_call(prompt, system=system, **kwargs)
    if BACKEND == "gemini":
        from .gemini_client import call_generator as gem_call
        return gem_call(prompt, system=system, **kwargs)
    raise RuntimeError(f"Unknown WAVE_GENERATOR_BACKEND: {BACKEND}")


# ---- Quality wrappers ----

def _n_samples() -> int:
    try:
        return max(1, int(os.environ.get("WAVE_N_SAMPLES", "1")))
    except ValueError:
        return 1


def _critique_revise_enabled() -> bool:
    return os.environ.get("WAVE_CRITIQUE_REVISE", "false").lower() in ("1", "true", "yes")


def _score_candidate(text: str) -> float:
    """Quick specificity proxy without needing the code (specificity.py needs
    code for the full score; this is a lightweight proxy for ranking)."""
    import re as _re
    # Long enough?
    if len(text) < 300:
        return 0.0
    # Has <think>?
    if not _re.search(r"<think>.*?</think>", text, _re.DOTALL):
        return 0.0
    # Backtick-quoted identifiers (good)
    backticks = len(_re.findall(r"`[^`]{3,40}`", text))
    # Generic-phrase count (bad)
    generic = sum(text.lower().count(p) for p in (
        "this code", "the function", "may be vulnerable", "could be vulnerable",
        "via unsanitized", "broad blast radius", "high reachability",
        "see reasoning", "in general",
    ))
    return backticks * 1.5 - generic * 2.0


_CRITIQUE_PROMPT = (
    "Review the following security trace. Did it engage with the specific code, "
    "or did it use generic security language? List exactly 3 specific things that "
    "would make it more concrete (e.g., \"name the variable that gets interpolated\", "
    "\"quote the line of code with shell=True\", \"identify the actual sink call\"). "
    "Be brief — one bullet per point.\n\n"
    "TRACE TO REVIEW:\n{trace}\n"
)

_REVISE_PROMPT = (
    "Rewrite the trace below to incorporate these improvements:\n{critique}\n\n"
    "Keep the structured fields (status:, cwe:, etc.) exactly as they were. "
    "Only deepen the reasoning content — make it more specific and code-anchored.\n\n"
    "ORIGINAL TRACE:\n{trace}\n"
)


def _critique_and_revise(prompt: str, system: Optional[str], initial: dict) -> dict:
    """3-call refinement loop: generate → critique → revise."""
    initial_text = initial["text"]
    # Step 2: critique
    crit_resp = _base_call(_CRITIQUE_PROMPT.format(trace=initial_text[:3000]), system=system)
    critique = crit_resp.get("text", "")
    if not critique.strip():
        return initial
    # Step 3: revise
    rev_prompt = _REVISE_PROMPT.format(critique=critique[:1500], trace=initial_text[:3000])
    rev_resp = _base_call(rev_prompt, system=system)
    if rev_resp.get("text", "").strip():
        return {
            "text": rev_resp["text"],
            "input_tokens":
                initial.get("input_tokens", 0)
                + crit_resp.get("input_tokens", 0)
                + rev_resp.get("input_tokens", 0),
            "output_tokens":
                initial.get("output_tokens", 0)
                + crit_resp.get("output_tokens", 0)
                + rev_resp.get("output_tokens", 0),
        }
    return initial


# ---- Public API ----

def call_generator(prompt: str, system: Optional[str] = None, **kwargs) -> dict:
    """Generate a response. Applies N-sampling + critique-revise wrappers
    based on env vars."""
    n = _n_samples()
    if n <= 1:
        result = _base_call(prompt, system=system, **kwargs)
    else:
        # Generate N candidates, keep best by specificity proxy
        candidates = [_base_call(prompt, system=system, **kwargs) for _ in range(n)]
        best = max(candidates, key=lambda r: _score_candidate(r.get("text", "")))
        result = best

    if _critique_revise_enabled():
        result = _critique_and_revise(prompt, system, result)

    return result
