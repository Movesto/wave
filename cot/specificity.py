# ============================================================
# cot/specificity.py
#
# Score how specific a generated trace is. The verifier's
# structural checks ensure the format is right; specificity
# ensures the CONTENT engages with the actual code rather than
# producing generic CWE-category reasoning.
#
# A specificity score in [0, 1] is computed from:
#   - Quoted/named identifiers from the code (function names,
#     variable names, library imports)
#   - File path references
#   - CWE references
#   - Penalty for generic phrases ("the function", "may be
#     vulnerable", "typically", etc.)
#
# A gate(score) returns True if the record is specific enough
# to keep. Threshold is tuned to reject the bottom ~20% of
# generations (the ones that pass format checks but reason
# at the CWE-category level).
# ============================================================
import re
from .code_analysis import extract_identifiers_only


GENERIC_PHRASES = (
    "this code",
    "the code",
    "the function",
    "the application",
    "the system",
    "may be vulnerable",
    "could be vulnerable",
    "potentially vulnerable",
    "an attacker can",
    "an attacker could",
    "typically",
    "in general",
    "usually",
    "for example",  # often used as filler in templated reasoning
    "broad blast radius",
    "wide blast radius",
    "high reachability",
    "via unsanitized",
    "without sanitization",
    "without validation",
    "see reasoning",
    "see above",
)

# Phrases that signal genuine engagement with the code
SPECIFIC_MARKERS = (
    "interpolat",   # interpolated, interpolation
    "concatenat",
    "f-string",
    "template literal",
    "constructed by",
    "passed to",
    "called via",
    "imported from",
)


def _count_quoted_idents(text: str, idents: list[str]) -> int:
    """Count how many code identifiers appear in the text (any form — backticked,
    quoted, or bare). Case-sensitive because identifiers are."""
    found = 0
    for ident in idents:
        if len(ident) < 3:
            continue
        # Match the identifier as a whole token
        if re.search(rf"\b{re.escape(ident)}\b", text):
            found += 1
    return found


def _count_cwe_refs(text: str) -> int:
    return len(re.findall(r"\bCWE[-‑]?\d+\b", text, re.IGNORECASE))


def _count_file_refs(text: str) -> int:
    return len(re.findall(r"\b[\w_]+/[\w_]+\.(?:py|js|ts|tsx|jsx)\b", text))


def _count_generic(text: str) -> int:
    text_low = text.lower()
    return sum(text_low.count(p) for p in GENERIC_PHRASES)


def _count_specific_markers(text: str) -> int:
    text_low = text.lower()
    return sum(text_low.count(p) for p in SPECIFIC_MARKERS)


def score(reasoning_text: str, code: str = "", language: str = None) -> dict:
    """Return a specificity score in [0, 1] plus the components for debugging."""
    if not reasoning_text or len(reasoning_text) < 100:
        return {"score": 0.0, "reason": "too_short", "components": {}}

    idents = extract_identifiers_only(code, language) if code else []
    text = reasoning_text

    quoted_idents = _count_quoted_idents(text, idents)
    cwe_refs = _count_cwe_refs(text)
    file_refs = _count_file_refs(text)
    generic = _count_generic(text)
    specific = _count_specific_markers(text)

    # Identifier coverage: fraction of code's named entities mentioned
    ident_coverage = (quoted_idents / max(len(idents), 1)) if idents else 0.0

    # Soft scoring: log-scale on counts, penalize generic
    sub = {
        "ident_coverage": min(ident_coverage, 1.0),
        "cwe_refs":       min(cwe_refs / 3.0, 1.0),
        "file_refs":      min(file_refs / 2.0, 1.0),
        "specific":       min(specific / 3.0, 1.0),
        "generic_penalty": min(generic / 6.0, 1.0),  # higher = worse
    }

    # Weighted combination
    raw = (
        0.40 * sub["ident_coverage"] +
        0.20 * sub["cwe_refs"] +
        0.15 * sub["file_refs"] +
        0.15 * sub["specific"] -
        0.30 * sub["generic_penalty"]
    )
    # Clamp to [0, 1]
    final = max(0.0, min(1.0, raw))

    return {
        "score": round(final, 3),
        "components": {**sub, **{
            "raw_quoted_idents": quoted_idents,
            "raw_idents_in_code": len(idents),
            "raw_cwe_refs": cwe_refs,
            "raw_file_refs": file_refs,
            "raw_generic": generic,
            "raw_specific": specific,
        }},
    }


def gate(score_value: float, threshold: float = 0.05) -> bool:
    """Accept gate: True = keep the record, False = discard.

    Threshold lowered to 0.05 after an 0.18-default run produced 100% discards
    on a 17-task gpt-oss batch. The previous threshold assumed scoring against
    actual code; for shape4 (synthesis) and shape3 (model-generated code),
    there's less identifier ground truth to anchor against, so the same score
    signals different things.
    """
    return score_value >= threshold


# ---- Convenience: per-shape scoring against an assistant message ----

def score_assistant(asst: str, code: str = "", language: str = None) -> dict:
    """Pull the <think> block + rationales out of an assistant message and
    score the combined reasoning content."""
    text_parts = []
    m = re.search(r"<think>(.*?)</think>", asst, re.DOTALL | re.IGNORECASE)
    if m:
        text_parts.append(m.group(1))
    # Add rationales (shape4) or trace+fix (shape1/3)
    for line in asst.splitlines():
        ln = line.strip()
        if ln.lower().startswith(("trace:", "fix:", "rationale:", "executive_summary:")):
            text_parts.append(ln)
    return score("\n".join(text_parts), code, language)
