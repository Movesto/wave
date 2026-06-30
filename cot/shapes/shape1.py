# ============================================================
# cot/shapes/shape1.py
#
# Shape 1 — Local scan with trace.
#
# Input: a single code snippet.
# Output: <think> source-to-sink reasoning (or why it's safe) </think>
#         followed by a structured verdict (status, CWE, severity,
#         line, trace, fix).
#
# We give the generator the ground truth and ask it to reason
# TOWARD the verdict as if discovering it — workflow rule:
# "never just restating the label."
#
# The verifier parses status (and CWE when known) and discards
# mismatches.
# ============================================================
import random
from typing import Optional

from .common import (
    iter_jsonl,
    get_messages,
    extract_scan_code,
    detect_language,
    parse_verdict,
    normalize_safe_assistant,
    CWE_RE,
)
from .exemplars import format_shape1_exemplars
from ..code_analysis import analyze
from ..specificity import score_assistant, gate


name = "shape1"

random.seed(42)


# ---- Source readers: pull (code, ground_truth) tuples ----

def _from_morefixes() -> list[dict]:
    """morefixes: 50/50 vuln/safe by construction. Response prefix tells us."""
    out = []
    for rec in iter_jsonl("morefixes_pairs.jsonl"):
        m = get_messages(rec)
        if not m:
            continue
        user, asst = m
        code = extract_scan_code(user)
        if not code or len(code) < 80 or len(code) > 2000:
            continue
        asst_low = asst.lower()
        if "no vulnerabilities detected" in asst_low or "no security" in asst_low or "looks secure" in asst_low:
            label = "safe"
            fixed = None
        elif "vulnerability detected" in asst_low or "security issue" in asst_low or "security flaw" in asst_low:
            label = "vuln"
            # Extract fixed code from the response if present
            fixed = _extract_fixed_block(asst)
        else:
            continue
        out.append({
            "source": "morefixes",
            "code": code,
            "label": label,
            "cwe": None,  # morefixes has no per-record CWE
            "language": detect_language(code),
            "fixed_code": fixed,
        })
    return out


def _from_cvefixes() -> list[dict]:
    """cvefixes: explicit safety field upstream. Response prefix tells us."""
    out = []
    for rec in iter_jsonl("cvefixes_pairs.jsonl"):
        m = get_messages(rec)
        if not m:
            continue
        user, asst = m
        code = extract_scan_code(user)
        if not code or len(code) < 80 or len(code) > 2000:
            continue
        asst_low = asst.lower()
        if "no vulnerabilities detected" in asst_low:
            label = "safe"
        elif "vulnerability detected" in asst_low or "security flaw" in asst_low:
            label = "vuln"
        else:
            continue
        out.append({
            "source": "cvefixes",
            "code": code,
            "label": label,
            "cwe": None,
            "language": detect_language(code),
            "fixed_code": None,
        })
    return out


def _from_clean_sources() -> list[dict]:
    """clean_code_pairs, clean_python, clean_js_react, clean_code_generated,
    clean_code_mined — all 100% safe by construction."""
    out = []
    for fname in [
        "clean_code_pairs.jsonl",
        "clean_python.jsonl",
        "clean_js_react.jsonl",
        "clean_code_generated.jsonl",
        "clean_code_mined.jsonl",
    ]:
        for rec in iter_jsonl(fname):
            m = get_messages(rec)
            if not m:
                continue
            user, _ = m
            code = extract_scan_code(user)
            if not code or len(code) < 50 or len(code) > 2000:
                continue
            out.append({
                "source": fname.removesuffix(".jsonl"),
                "code": code,
                "label": "safe",
                "cwe": None,
                "language": detect_language(code),
                "fixed_code": None,
            })
    return out


def _from_hand_vulns() -> list[dict]:
    """python_vulns + js_vulns + claude_generated — small, hand-labeled,
    often has explicit CWE in the response."""
    out = []
    for fname in ["python_vulns.jsonl", "js_vulns.jsonl", "claude_generated_pairs.jsonl"]:
        for rec in iter_jsonl(fname):
            m = get_messages(rec)
            if not m:
                continue
            user, asst = m
            code = extract_scan_code(user)
            if not code or len(code) < 50 or len(code) > 2000:
                continue
            asst_low = asst.lower()
            if "no vulnerabilities detected" in asst_low or "no security issues" in asst_low:
                label = "safe"
                cwe = None
            else:
                label = "vuln"
                m_cwe = CWE_RE.search(asst)
                cwe = f"CWE-{m_cwe.group(1)}" if m_cwe else None
            out.append({
                "source": fname.removesuffix(".jsonl"),
                "code": code,
                "label": label,
                "cwe": cwe,
                "language": detect_language(code),
                "fixed_code": _extract_fixed_block(asst),
            })
    return out


def _extract_fixed_block(asst_text: str) -> Optional[str]:
    """If the assistant text has a 'Fixed code:' section, return its body."""
    low = asst_text.lower()
    idx = low.find("fixed code:")
    if idx < 0:
        return None
    return asst_text[idx + len("fixed code:") :].strip()[:1500] or None


# ---- prepare_tasks ----

def prepare_tasks(limit: int) -> list[dict]:
    """Sample `limit` tasks across sources with ≥30% safe.

    Stability invariant: prepare_tasks(N)[:M] == prepare_tasks(M) for M <= N.
    This is achieved by building a fixed-size shuffled pool with a fixed seed,
    independent of the requested limit. Earlier calls' kept records remain
    valid for later, larger calls.
    """
    rng = random.Random(42)

    morefixes = _from_morefixes()
    cvefixes = _from_cvefixes()
    clean = _from_clean_sources()
    hand = _from_hand_vulns()

    rng.shuffle(morefixes)
    rng.shuffle(cvefixes)
    rng.shuffle(clean)
    rng.shuffle(hand)

    mf_vuln = [t for t in morefixes if t["label"] == "vuln"]
    mf_safe = [t for t in morefixes if t["label"] == "safe"]
    cv_vuln = [t for t in cvefixes if t["label"] == "vuln"]
    cv_safe = [t for t in cvefixes if t["label"] == "safe"]

    # Fixed-size pool of ~200 (independent of limit) so any prefix-slice is stable.
    POOL = (
        mf_vuln[:60]
        + mf_safe[:60]
        + cv_vuln[:8]
        + cv_safe[:8]
        + clean[:32]
        + hand[:32]
    )
    rng.shuffle(POOL)

    # Stamp stable task_ids before any slicing.
    counters: dict[str, int] = {}
    for t in POOL:
        n = counters.get(t["source"], 0)
        t["task_id"] = f"shape1:{t['source']}:{n}"
        counters[t["source"]] = n + 1

    return POOL[:limit]


def _all_source_records() -> list[dict]:
    """Every candidate record from all Shape-1 sources (pre-language-filter).
    Used by the language-targeted variants (shape1_ts / shape1_react)."""
    return (
        _from_morefixes()
        + _from_cvefixes()
        + _from_clean_sources()
        + _from_hand_vulns()
    )


def prepare_tasks_for_languages(
    languages: set[str],
    limit: int,
    *,
    id_prefix: str,
    min_safe_ratio: float = 0.30,
    only_label: Optional[str] = None,
    seed: int = 123,
) -> list[dict]:
    """Language-stratified Shape-1 task picker.

    Pulls records whose detected language is in `languages` from the
    non-R2Vul sources (R2Vul has no TS/React), dedups by code, enforces at
    least `min_safe_ratio` safe records, and stamps stable task_ids under
    `id_prefix` so the checkpoint .done files never collide with the main
    shape1 R2Vul ids. Deterministic: prefix-slice stable across limits.

    `only_label` ("vuln" | "safe") restricts to one label and skips the
    safe-ratio interleaving — used by the vuln-only TS/React variants, since
    the teacher over-flags safe code and those tasks just get discarded.
    """
    rng = random.Random(seed)
    pool = [r for r in _all_source_records() if r["language"] in languages]

    # Dedup by code (morefixes has near-duplicates across commits).
    seen: set[str] = set()
    deduped = []
    for r in pool:
        key = r["code"].strip()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)

    if only_label is not None:
        single = [r for r in deduped if r["label"] == only_label]
        rng.shuffle(single)
        counters: dict[str, int] = {}
        for t in single:
            n = counters.get(t["source"], 0)
            t["task_id"] = f"{id_prefix}:{t['source']}:{n}"
            counters[t["source"]] = n + 1
        return single[:limit]

    vuln = [r for r in deduped if r["label"] == "vuln"]
    safe = [r for r in deduped if r["label"] == "safe"]
    rng.shuffle(vuln)
    rng.shuffle(safe)

    # Enforce >= min_safe_ratio safe by capping vuln if safe is scarce.
    # interleave safe/vuln so any prefix-slice keeps the ratio roughly intact.
    ordered: list[dict] = []
    si = vi = 0
    while si < len(safe) or vi < len(vuln):
        want_safe = (len([r for r in ordered if r["label"] == "safe"]) <
                     min_safe_ratio * (len(ordered) + 1))
        if want_safe and si < len(safe):
            ordered.append(safe[si]); si += 1
        elif vi < len(vuln):
            ordered.append(vuln[vi]); vi += 1
        elif si < len(safe):
            ordered.append(safe[si]); si += 1
        else:
            break

    counters: dict[str, int] = {}
    for t in ordered:
        n = counters.get(t["source"], 0)
        t["task_id"] = f"{id_prefix}:{t['source']}:{n}"
        counters[t["source"]] = n + 1

    return ordered[:limit]


# ---- build_prompt ----

SYSTEM = (
    "You convert terse code-and-verdict pairs into chain-of-thought training data "
    "for a vulnerability scanner. You will be given a code snippet and ground truth. "
    "Write a <think> reasoning block that arrives at the verdict by tracing the code "
    "as if you were discovering the answer for the first time — NEVER restate that you "
    "were told the answer. Then emit the structured verdict in the exact format requested."
)


def build_prompt(task: dict) -> tuple[Optional[str], str]:
    code = task["code"]
    label = task["label"]
    lang = task["language"]
    cwe_hint = task.get("cwe")
    fixed_hint = task.get("fixed_code")

    parts = []

    # 1) Exemplar — shows the model the specificity style we want
    parts.append(format_shape1_exemplars(count=1))

    # 2) Pre-flight code analysis — gives the model concrete elements to reference
    hints = analyze(code, lang)
    hint_block = hints.render()
    if hint_block:
        parts.append(hint_block)

    # 3) Ground truth + code
    parts.append(f"Language: {lang}")
    parts.append(f"GROUND TRUTH (do NOT name this in your output): label={label}")
    if cwe_hint:
        parts.append(f"GROUND TRUTH (do NOT name this directly): cwe={cwe_hint}")
    if fixed_hint:
        fh = fixed_hint[:800]
        parts.append(f"REFERENCE FIX (for inspiration only — do not paste verbatim):\n{fh}")

    parts.append(f"\nCODE:\n```{lang}\n{code}\n```\n")

    # 4) Task instruction (original concise form — long-form tightening confused gpt-oss)
    if label == "vuln":
        instructions = (
            "Task: Write a trace that reasons from input source(s) to the vulnerable sink. "
            "Identify the data flow step by step. Then emit the verdict. The <think> block "
            "should read like discovery — observe imports, find user-tainted inputs, follow "
            "them to dangerous calls, conclude. End with the structured fields."
        )
    else:
        instructions = (
            "Task: Write a trace that reasons about why this code is safe. Identify what "
            "could go wrong in a naive version, then show why the actual code prevents that "
            "(parameter binding, escaping, sandboxing, validation, etc.). Do NOT invent a "
            "vulnerability. End with the structured fields. Because the verdict is SAFE, set "
            "cwe: none, severity: none, line: none, and fix: none. The trace must be a "
            "one-line summary of the SAFE data flow — do NOT name a CWE in it."
        )

    parts.append(instructions)
    parts.append(
        "\nOUTPUT FORMAT — exactly this shape, nothing else:\n"
        "<think>\n"
        "[your step-by-step reasoning — short, concrete, code-anchored]\n"
        "</think>\n"
        "\n"
        "status: confirmed | safe\n"
        "cwe: CWE-XX | none\n"
        "severity: HIGH | MEDIUM | LOW | none\n"
        "line: <line number in the snippet> | none\n"
        "trace: <one-line data flow summary that names at least one specific identifier>\n"
        "fix: <short fix description or code> | none\n"
    )
    return SYSTEM, "\n".join(parts)


# ---- verify ----

def verify(task: dict, generated_text: str) -> Optional[dict]:
    """Parse the generated text, compare to ground truth, score specificity,
    return the record or None."""
    parsed = parse_verdict(generated_text)
    if not parsed["status"]:
        return None
    if not parsed["think"]:
        return None

    expected = "confirmed" if task["label"] == "vuln" else "safe"
    if parsed["status"] != expected:
        return None

    # Specificity gate — opt-in via WAVE_SPECIFICITY_GATE=true env var.
    # Off by default so existing pipelines don't break.
    import os as _os
    spec_meta = None
    if _os.environ.get("WAVE_SPECIFICITY_GATE", "false").lower() in ("1", "true", "yes"):
        spec_skip_sources = {"extra_hand", "manual", "hand"}
        if task.get("source") not in spec_skip_sources:
            spec_meta = score_assistant(generated_text, task.get("code", ""), task.get("language"))
            if not gate(spec_meta["score"]):
                return None

    assistant_payload = generated_text.strip()
    if expected == "safe":
        assistant_payload = normalize_safe_assistant(assistant_payload)
    record = {
        "messages": [
            {"role": "user", "content": f"<SCAN>\n{task['code']}\n</SCAN>"},
            {"role": "assistant", "content": assistant_payload},
        ],
        "_meta": {
            "shape": "shape1",
            "source": task["source"],
            "language": task["language"],
            "label": task["label"],
            "cwes": [parsed["cwe"]] if (parsed["cwe"] and expected != "safe") else [],
            "ground_truth_cwe": task.get("cwe"),
            "specificity": (spec_meta["score"] if spec_meta else None),
        },
    }
    return record
