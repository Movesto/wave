# ============================================================
# cot/gates.py
#
# Verification gates for regenerated VULN traces (Trellis-style:
# substantiveness / correspondence / soundness). A trace is kept
# only if it passes all gates against the oracle Region; otherwise
# the record is dropped (or retried). This replaces the "keep every
# trace, clean up later" treadmill.
#
# Pure logic, no model — unit-tested in tests/test_oracle_gates.py.
# ============================================================
import re
from typing import Optional

from .oracle import Region, identifiers
from .shapes.common import parse_verdict

# Speculative / hedged language = teacher hypothesizing a vuln it can't see.
_HEDGE = re.compile(
    r"\bcould be (?:vulnerable|exploited|abused|injected)\b"
    r"|\bif (?:it|this|that|the value|the input|the data|rendered|inserted|they)\b[^.]{0,60}\b(?:were|was|is|are|comes|came|untrusted|user|attacker|unsanitized)\b"
    r"|\bif an attacker\b"
    r"|\bpresumably\b|\bnot shown\b|\blikely (?:to be|contains?)\b"
    r"|\bmay be (?:vulnerable|exploited)\b"
    r"|\bif .{0,40}without (?:escap|sanitiz|validat)",
    re.I,
)
# A concrete data-flow indicator (source -> sink).
_FLOW = re.compile(
    r"→|->|=>|\bflows? (?:into|to|through)\b|\bpassed (?:to|into)\b|\breaches\b"
    r"|\bforwarded to\b|\binterpolat|\bconcatenat|\bsink\b",
    re.I,
)


def _trace_line(text: str) -> str:
    m = re.search(r"^\s*trace:\s*(.+)$", text, re.I | re.M)
    return m.group(1).strip() if m else ""


def correspondence(text: str, vuln_code: str) -> tuple[bool, str]:
    """Identifiers the trace names must actually appear in the code (kills
    hallucinated sinks on fragments)."""
    trace = _trace_line(text)
    ids = identifiers(trace)
    if not ids:
        return False, "trace names no concrete identifier"
    code_ids = identifiers(vuln_code)
    missing = [i for i in ids if i not in code_ids and i not in vuln_code]
    if len(missing) > max(1, len(ids) // 2):
        return False, f"trace cites identifiers absent from code: {missing[:4]}"
    return True, "ok"


def localization(text: str, region: Region) -> tuple[bool, str]:
    """The trace's sink must land on/near the patched lines (±2) or name a
    patched identifier. Unverifiable (no oracle) passes but is flagged."""
    if not region.known():
        return True, "no-oracle(unverified)"
    parsed = parse_verdict(text)
    line = parsed.get("line")
    if line and str(line).strip().isdigit():
        ln = int(str(line).strip())
        if any(abs(ln - rl) <= 2 for rl in region.lines):
            return True, "line-in-region"
    if identifiers(_trace_line(text)) & region.identifiers:
        return True, "sink-identifier-in-region"
    return False, f"sink not near patched lines {sorted(region.lines)[:5]}"


def cwe_consistency(text: str, region: Region) -> tuple[bool, str]:
    """Predicted CWE must match ground truth (number-level) when known."""
    if not region.cwe:
        return True, "no-ground-truth-cwe"
    parsed = parse_verdict(text)
    pc = parsed.get("cwe")
    if not pc:
        return False, "no cwe predicted"
    a = re.search(r"\d+", pc)
    b = re.search(r"\d+", region.cwe)
    if a and b and a.group() == b.group():
        return True, "cwe-match"
    return False, f"cwe {pc} != ground-truth {region.cwe}"


def substantiveness(text: str) -> tuple[bool, str]:
    """No hedging; must trace a concrete source->sink flow."""
    m = re.search(r"<think>(.*?)</think>", text, re.S | re.I)
    body = m.group(1) if m else text
    trace = _trace_line(text)
    blob = body + "\n" + trace
    if _HEDGE.search(blob):
        return False, "hedged/speculative language"
    if not _FLOW.search(blob):
        return False, "no concrete source->sink flow"
    return True, "ok"


GATES = {
    "correspondence": lambda text, code, region: correspondence(text, code),
    "localization":   lambda text, code, region: localization(text, region),
    "cwe":            lambda text, code, region: cwe_consistency(text, region),
    "substantiveness": lambda text, code, region: substantiveness(text),
}


def all_gates_pass(text: str, vuln_code: str, region: Region) -> tuple[bool, list[str], dict]:
    """Run every gate. Returns (passed_all, failure_reasons, full_results)."""
    results: dict[str, tuple[bool, str]] = {}
    for name, fn in GATES.items():
        results[name] = fn(text, vuln_code, region)
    fails = [f"{n}: {r}" for n, (ok, r) in results.items() if not ok]
    return (len(fails) == 0), fails, results
