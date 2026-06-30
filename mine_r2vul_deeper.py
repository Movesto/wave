"""Deeper mining of R2Vul's positive_reasoning, replacing the
first-sentence trace heuristic with structured extraction:

  - Specific code construct that's vulnerable
  - Attack mechanism (what an attacker can do)
  - Fix proposal (concrete suggestion)
  - Specific identifier (function/variable name) referenced

These get baked into the assistant message's `trace:` and `fix:` fields,
which then propagate to shape4 finding titles via _make_short_title.

Result: shape4 sees genuinely informative finding titles.
"""
import json
import re
import sys
from pathlib import Path
from collections import Counter

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


SRC = Path("data/cot/pilot/shape1.jsonl")


# Patterns that mark a useful sentence in R2Vul reasoning
ATTACK_PATTERNS = (
    r"(?:attacker|adversary|malicious user|exploit(?:ed|ation)?)",
    r"(?:inject(?:s|ed|ion)?|execute(?:s|d)?|gain access|bypass(?:es|ed)?)",
    r"(?:leak(?:s|ed)?|exfiltrat(?:e|ion)|expose(?:s|d)?)",
    r"(?:overwrit(?:e|ten|es)?|escalate|tamper(?:ed)?)",
)

FIX_PATTERNS = (
    r"(?:use|replace|sanitize|validate|escape|parameteriz|encode|enforce)\w*",
    r"(?:should|must|recommend(?:ed)?|fix is|patch is)",
    r"(?:bcrypt|argon|hmac\.|secrets\.|parameteriz|prepared statement|allowlist|whitelist)",
)

CONSTRUCT_PATTERNS = (
    r"`[^`]+`",                                  # backticked code
    r"\b\w+\.\w+\s*\([^)]*\)",                   # method calls
    r"\b(?:f-?string|template literal|string concatenation|interpolation)\b",
    r"\b(?:eval|exec|subprocess|os\.system|child_process|innerHTML|dangerouslySet)\w*",
    r"\b(?:pickle|yaml\.load|marshal)\b",
)


def find_first_sentence_matching(text: str, patterns: tuple) -> str | None:
    """Return the first sentence in `text` that matches any of the regex patterns."""
    sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z])", text)
    for sent in sentences:
        for pat in patterns:
            if re.search(pat, sent, re.IGNORECASE):
                # Strip markdown bullet markers from start
                clean = re.sub(r"^[\s\d\.\)\*\-•]+", "", sent).strip()
                if 30 <= len(clean) <= 240:
                    return clean
    return None


def find_construct(text: str) -> str | None:
    """Find a specific code construct mentioned in the reasoning."""
    for pat in CONSTRUCT_PATTERNS:
        m = re.search(pat, text)
        if m:
            return m.group(0)
    return None


def derive_richer_trace(reasoning: str, cwe: str | None, lang: str | None,
                        is_vulnerable: bool) -> str:
    """Build a trace summary that names a specific construct + attack/defense.

    Format target: "<construct> → <CWE> via <attack>"
    Falls back gracefully if any piece is missing.
    """
    if not reasoning or len(reasoning) < 80:
        return f"{cwe or 'CWE-UNK'} in {lang or 'code'}" if is_vulnerable else "safe code pattern"

    construct = find_construct(reasoning)
    attack = find_first_sentence_matching(reasoning, ATTACK_PATTERNS) if is_vulnerable else None

    if construct and attack:
        return f"{construct} — {attack[:130]}"
    if attack:
        return attack[:170]
    if construct:
        return f"{cwe or 'CWE-UNK'} in {construct}"

    # Final fallback: first non-trivial sentence
    t = re.sub(r"^[\s\d\.\)\*\-•]+", "", reasoning).strip()
    parts = re.split(r"[.!?]\s+", t, maxsplit=1)
    head = parts[0].strip()
    if 30 <= len(head) <= 200:
        return head
    return f"{cwe or 'CWE-UNK'} in {lang or 'code'}" if is_vulnerable else "safe code pattern"


def derive_richer_fix(reasoning: str, is_vulnerable: bool) -> str:
    if not is_vulnerable:
        return "none"
    if not reasoning:
        return "consult security guidance for this CWE class"

    fix_sent = find_first_sentence_matching(reasoning, FIX_PATTERNS)
    if fix_sent and len(fix_sent) <= 250:
        return fix_sent
    # Fallback to scanning for any sentence containing 'should' or 'recommend'
    m = re.search(r"([A-Z][^.!?]*?\b(?:should|recommend|fix|patch)\b[^.!?]*[.!?])", reasoning)
    if m and len(m.group(1)) <= 250:
        return m.group(1).strip()
    return "remediate at the dangerous sink (see reasoning for details)"


def upgrade_assistant(asst: str, meta: dict) -> tuple[str, bool]:
    think_m = re.search(r"<think>(.*?)</think>", asst, re.DOTALL | re.IGNORECASE)
    if not think_m:
        return asst, False
    reasoning = think_m.group(1).strip()

    cwes = meta.get("cwes") or []
    cwe = cwes[0] if cwes else meta.get("ground_truth_cwe")
    lang = meta.get("language")
    is_vuln = meta.get("label") == "vuln"

    trace_m = re.search(r"^trace\s*:\s*(.*)$", asst, re.MULTILINE | re.IGNORECASE)
    fix_m = re.search(r"^fix\s*:\s*(.*)$", asst, re.MULTILINE | re.IGNORECASE)
    if not trace_m:
        return asst, False

    new_trace = derive_richer_trace(reasoning, cwe, lang, is_vuln)
    new_fix = derive_richer_fix(reasoning, is_vuln)

    out = re.sub(
        r"^trace\s*:.*$",
        lambda _: f"trace: {new_trace}",
        asst, count=1, flags=re.MULTILINE | re.IGNORECASE,
    )
    if fix_m and is_vuln:
        out = re.sub(
            r"^fix\s*:.*$",
            lambda _: f"fix: {new_fix}",
            out, count=1, flags=re.MULTILINE | re.IGNORECASE,
        )
    return out, True


def main():
    if not SRC.exists():
        print(f"ERROR: {SRC} not found")
        sys.exit(1)

    print(f"Reading {SRC}...")
    lines = SRC.read_text(encoding="utf-8").splitlines()
    print(f"  {len(lines)} total records")

    upgraded = 0
    skipped = 0
    out_lines = []
    quality_signals = Counter()

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            out_lines.append(line)
            continue
        meta = rec.get("_meta") or {}
        if meta.get("source") != "r2vul":
            out_lines.append(line)
            skipped += 1
            continue
        msgs = rec.get("messages") or []
        if len(msgs) < 2:
            out_lines.append(line)
            continue
        new_asst, changed = upgrade_assistant(msgs[1].get("content", ""), meta)
        if changed:
            # measure improvement
            old_trace = re.search(r"^trace\s*:\s*(.*)$", msgs[1]["content"], re.MULTILINE | re.IGNORECASE)
            new_trace = re.search(r"^trace\s*:\s*(.*)$", new_asst, re.MULTILINE | re.IGNORECASE)
            if old_trace and new_trace and old_trace.group(1) != new_trace.group(1):
                quality_signals["trace_changed"] += 1
            msgs[1]["content"] = new_asst
            rec["messages"] = msgs
            upgraded += 1
        out_lines.append(json.dumps(rec, ensure_ascii=False))

    backup = SRC.with_suffix(SRC.suffix + ".pre_deep_mine.bak")
    if not backup.exists():
        backup.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Backup written to {backup}")

    SRC.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    print(f"\nUpgraded {upgraded} R2Vul records")
    print(f"  trace changes: {quality_signals['trace_changed']}")
    print(f"  skipped (non-r2vul): {skipped}")
    print(f"Wrote {SRC}")


if __name__ == "__main__":
    main()
