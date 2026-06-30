# ============================================================
# cot/shapes/_safe_core.py
#
# Safe-only Shape-1 trace generation.
#
# The vuln-vs-safe path (shape1.build_prompt) lets the teacher
# DECIDE the verdict — and gpt-oss-20b over-flags safe TS/React
# code as vulnerable, so verify() discards ~94% of safe tasks and
# the survivors are trivial (imports-only). That destroys the
# safe:vuln balance the FPR metric depends on.
#
# This module never asks the teacher to judge. The code is known
# safe (from morefixes-fixed / cvefixes-safe / clean-by-construction
# sources), so we tell the model that and ask it to TRACE WHY —
# naming the defense (validation, parameterization, escaping,
# encoding, sandboxing) or the absence of any untrusted-input→sink
# flow. Status is fixed to `safe`; the model cannot flip it.
#
# Used by shape1_ts_safe / shape1_react_safe.
# ============================================================
from typing import Optional

from . import shape1
from .common import parse_verdict, normalize_safe_assistant
from ..code_analysis import analyze


def prepare_safe_tasks(
    languages: set[str],
    limit: int,
    *,
    id_prefix: str,
    seed: int,
) -> list[dict]:
    """All known-safe records in the target languages, deduped by code."""
    import random
    rng = random.Random(seed)
    pool = [r for r in shape1._all_source_records()
            if r["language"] in languages and r["label"] == "safe"]

    seen: set[str] = set()
    deduped = []
    for r in pool:
        key = r["code"].strip()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)

    rng.shuffle(deduped)

    counters: dict[str, int] = {}
    for t in deduped:
        n = counters.get(t["source"], 0)
        t["task_id"] = f"{id_prefix}:{t['source']}:{n}"
        counters[t["source"]] = n + 1

    return deduped[:limit]


SYSTEM = (
    "You convert verified-safe code snippets into chain-of-thought training data "
    "for a vulnerability scanner. You are told the code is SAFE (already verified). "
    "Your job is to TRACE why it is safe: identify any untrusted input, follow it, "
    "and show the specific reason it cannot reach a dangerous sink — input validation, "
    "parameterized queries, output encoding/escaping, sandboxing, an allowlist, or "
    "simply the absence of any untrusted-input-to-sink flow. NEVER invent a "
    "vulnerability; the verdict is always safe. Be concrete and code-anchored — name "
    "real identifiers from the snippet, do not just say it 'looks fine'."
)


def build_prompt(task: dict) -> tuple[Optional[str], str]:
    code = task["code"]
    lang = task["language"]

    parts = []
    hints = analyze(code, lang)
    hint_block = hints.render()
    if hint_block:
        parts.append(hint_block)

    parts.append(f"Language: {lang}")
    parts.append("GROUND TRUTH: this code is SAFE (verified). Do NOT state that you were told.")
    parts.append(f"\nCODE:\n```{lang}\n{code}\n```\n")
    parts.append(
        "Task: Write a <think> trace explaining why this code is safe. If untrusted "
        "input exists, name it and show the defense that neutralizes it before any sink. "
        "If there is no untrusted-input-to-sink flow, say so concretely, naming the "
        "relevant identifiers. Do NOT invent a vulnerability."
    )
    parts.append(
        "\nOUTPUT FORMAT — exactly this shape, nothing else:\n"
        "<think>\n"
        "[step-by-step reasoning — short, concrete, code-anchored]\n"
        "</think>\n"
        "\n"
        "status: safe\n"
        "cwe: none\n"
        "severity: none\n"
        "line: none\n"
        "trace: <one-line summary of the SAFE data flow that names a specific identifier>\n"
        "fix: none\n"
    )
    return SYSTEM, "\n".join(parts)


def verify(task: dict, generated_text: str) -> Optional[dict]:
    parsed = parse_verdict(generated_text)
    if not parsed["status"] or not parsed["think"]:
        return None
    # The verdict is fixed safe; discard if the model flipped it or rambled too thin.
    if parsed["status"] != "safe":
        return None
    if len(parsed["think"]) < 80:        # reject rubber-stamp one-liners
        return None
    if not parsed["trace"]:
        return None

    assistant_payload = normalize_safe_assistant(generated_text.strip())
    return {
        "messages": [
            {"role": "user", "content": f"<SCAN>\n{task['code']}\n</SCAN>"},
            {"role": "assistant", "content": assistant_payload},
        ],
        "_meta": {
            "shape": "shape1",
            "source": task["source"],
            "language": task["language"],
            "label": "safe",
            "cwes": [],
            "ground_truth_cwe": None,
        },
    }
