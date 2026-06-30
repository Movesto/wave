"""Deterministic trace assembler — contract + oracle, NO model.

Given (vuln_code, fixed_code, cwe), build a structured CoT trace whose <think>
is grounded in the patch oracle (real changed lines/identifiers) and the per-CWE
contract (sink phrase, rationale, control). Consistent and hallucination-proof.
"""
import re
from .oracle import locate_from_diff, locate_vuln, identifiers
from .cwe_contracts import family_of, CONTRACTS

_SEV = {
    "sql": "HIGH", "command": "HIGH", "code_injection": "HIGH", "deserialization": "HIGH",
    "xxe": "HIGH", "ssrf": "HIGH", "path": "HIGH", "auth": "HIGH",
    "xss": "MEDIUM", "redirect": "MEDIUM", "csrf": "MEDIUM", "crypto": "MEDIUM",
    "dos": "MEDIUM", "info_exposure": "MEDIUM", "input_validation": "MEDIUM",
}
# tokens that look like an untrusted source
_SRC = re.compile(r"req|request|param|input|user|body|query|args?|form|filename|"
                  r"file_name|url|data|value|payload|name|id|token|path|cmd", re.I)
# type-string -> CWE (for sources that ship a type name, not a CWE)
_TYPE2CWE = {
    "sql injection": "CWE-89", "command injection": "CWE-78", "os command injection": "CWE-78",
    "cross-site scripting (xss)": "CWE-79", "xss": "CWE-79", "path traversal": "CWE-22",
    "ssrf": "CWE-918", "insecure deserialization": "CWE-502", "deserialization": "CWE-502",
    "code injection": "CWE-94", "xxe injection": "CWE-611", "xxe": "CWE-611",
    "authentication bypass": "CWE-287", "open redirect": "CWE-601", "csrf": "CWE-352",
    "buffer overflow": "CWE-120", "weak cryptography": "CWE-327",
}


def type_to_cwe(vuln_type):
    return _TYPE2CWE.get((vuln_type or "").strip().lower())


def _find_sink(vuln_code, markers, region_lines):
    """Locate the ACTUAL sink in the vuln code via contract markers; prefer a
    match on a patched line. Returns (sink_token, line) or (None, None)."""
    low = vuln_code.lower()
    lines = vuln_code.split("\n")
    best = None  # (score, token, lineno)
    for mk in markers:
        pos = low.find(mk)
        if pos < 0:
            continue
        lineno = vuln_code[:pos].count("\n") + 1
        line_text = lines[lineno - 1] if lineno <= len(lines) else ""
        m = re.search(r"([A-Za-z_][\w.]*)\s*\(", line_text)        # a call on that line
        tok = (m.group(1) if m else mk).strip()
        score = 2 if lineno in region_lines else 1
        if best is None or score > best[0]:
            best = (score, tok, lineno)
    return (best[1], best[2]) if best else (None, None)


def _find_source(vuln_code, fixed_code, region):
    """Pick the untrusted source from VULN-side identifiers (prefer removed/changed)."""
    vids = identifiers(vuln_code)
    fids = identifiers(fixed_code) if fixed_code else set()
    on_change = [i for i in region.identifiers if i in vids and _SRC.search(i)]
    removed = [i for i in on_change if i not in fids]          # vuln-only tokens
    pool = removed or on_change or [i for i in sorted(vids) if _SRC.search(i)]
    return pool[0] if pool else "untrusted input"


def build_vuln_trace(vuln_code, fixed_code, cwe):
    """Assemble a confirmed-vuln trace. Returns (trace_text, ok)."""
    region = locate_from_diff(vuln_code, fixed_code) if fixed_code else locate_vuln(vuln_code)
    fam = family_of(cwe)
    if fam is None:
        return "", False
    c = CONTRACTS[fam]
    sink, sink_line = _find_sink(vuln_code, c["markers"], region.lines)
    source = _find_source(vuln_code, fixed_code, region)
    if sink is None:                       # no recognizable sink in code -> can't ground it
        return "", False
    if sink == source:
        source = "untrusted input"
    line = sink_line or (min(region.lines) if region.lines else None)
    sev = _SEV.get(fam, "MEDIUM")

    think = (
        f"<think>\n"
        f"1. `{source}` is untrusted input entering this code"
        + (f" (near line {line})" if line else "") + ".\n"
        f"2. It flows to `{sink}`, which is {c['sink']}.\n"
        f"3. The fix adds a control the vulnerable code lacks: {c['control']}.\n"
        f"4. An attacker controlling `{source}` can therefore exploit it — this is {cwe}.\n"
        f"</think>"
    )
    fix_hint = c["control"][0].upper() + c["control"][1:]
    fields = (
        f"status: confirmed\n"
        f"cwe: {cwe}\n"
        f"severity: {sev}\n"
        f"line: {line if line else 'none'}\n"
        f"trace: {source} -> {sink}\n"
        f"fix: {fix_hint}"
    )
    return think + "\n" + fields, True


def build_safe_trace(fixed_code, cwe_hint=None):
    """Assemble a safe trace from FIXED code (explains the control that neutralizes it)."""
    fam = family_of(cwe_hint) if cwe_hint else None
    control = CONTRACTS[fam]["control"] if fam else "the untrusted input is validated/neutralized before any sink"
    think = (
        f"<think>\n"
        f"1. Untrusted input is present, but it does not reach a dangerous sink unguarded.\n"
        f"2. The code applies a control: {control}.\n"
        f"3. Because that control neutralizes the risk on the path to the sink, the code is safe.\n"
        f"</think>"
    )
    fields = (
        f"status: safe\ncwe: none\nseverity: none\nline: none\n"
        f"trace: input is neutralized by {control.split(';')[0].strip()} before any sink\n"
        f"fix: none"
    )
    return think + "\n" + fields, True
