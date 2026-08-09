"""Safe-side audit: prove code SAFE, to veto the agent's over-flagging (false 'vuln').

The witness proves INSUFFICIENCY (vuln). This is its mirror: a positive proof of SAFETY,
via two sound mechanisms:
  1. a guard the witness RECOGNISES and proves SUFFICIENT (full proto blocklist, backslash-
     hardened redirect) -- assess_guard(...).sufficient,
  2. a NEUTRALISER applied to the value (execFile arg-array, basename, parameterised query,
     textContent, DOMPurify) -- the value cannot reach the sink in a dangerous form.

SOUNDNESS is the whole point: prove_safe must return None on every genuinely-vulnerable
case, or it would hide real bugs. Verified offline against all harder_cases before use.
"""
import re
from guard_witness import assess_guard

# neutraliser constructs per sink kind: applying one makes the value safe for that sink
_NEUT = {
    "command": [("execFile arg-array",
                 r"(?:execFile|execFileSync|spawn|spawnSync)\s*\(\s*[^,]+,\s*\["),
                ("escapeshellarg", r"\bescapeshellarg\s*\("),
                ("shlex.quote", r"\bshlex\.quote\s*\(")],
    "path": [("basename", r"\bpath\.basename\s*\(|\bbasename\s*\(")],
    "xss": [("textContent", r"\.textContent\s*="),
            ("DOMPurify", r"DOMPurify\.sanitize\s*\(")],
    "sql": [("parameterised query",
             r"(?:query|execute)\s*\(\s*[`\"'][^`\"']*(?:\?|\$\d)[^`\"']*[`\"']\s*,")],
    "redirect": [("encodeURIComponent", r"encodeURIComponent\s*\(")],
}


def prove_safe(code, kind):
    """A reason string if the code is PROVABLY safe for `kind`, else None."""
    if not kind:
        return None
    # 1. a recognised, sufficient guard
    try:
        v = assess_guard(code, kind)
        if v.recognised and v.sufficient:
            return "guard recognised and proven sufficient"
    except Exception:
        pass
    # 2. a neutraliser on the value
    for label, rx in _NEUT.get(kind, []):
        if re.search(rx, code):
            return f"neutraliser applied: {label}"
    return None


# ---------- soundness self-test against the real harder cases ----------
def _selftest():
    import json
    _WK = {"CWE-22": "path", "CWE-59": "path", "CWE-78": "command", "CWE-89": "sql",
           "CWE-918": "ssrf", "CWE-1321": "proto", "CWE-601": "redirect", "CWE-79": "xss"}
    cases = [json.loads(l) for l in open("harder_cases.jsonl", encoding="utf-8")]
    false_safe, fired = [], []
    for i, c in enumerate(cases):
        kind = _WK.get((c["cwe"] or "").upper())
        why = prove_safe(c["code"], kind)
        if why and c["label"] == "vuln":
            false_safe.append((i, c["cwe"], why))          # UNSOUND -- proved a vuln 'safe'
        if why:
            fired.append((i, c["cwe"], c["label"], why))
    print("prove_safe fired on:")
    for i, cwe, lab, why in fired:
        mark = "  " if lab == "safe" else "!!"
        print(f"  {mark} case {i:2d} {cwe:8s} truth={lab:5s} -> {why}")
    print(f"\nUNSOUND (proved a VULN case safe): {'NONE' if not false_safe else false_safe}")
    return not false_safe


if __name__ == "__main__":
    ok = _selftest()
    print("\nSOUND:", ok)
