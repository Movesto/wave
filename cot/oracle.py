# ============================================================
# cot/oracle.py
#
# Verified-regeneration oracle: locate WHERE a vulnerability lives
# in a snippet, so a generated trace can be checked against it.
#
# Security has no Lean kernel, but fix-pair data has a strong partial
# oracle: the patch. diff(vuln_code, fixed_code) marks the lines the
# fix removed/changed = where the vuln was. A correct trace's sink
# must land there. When no diff is available, fall back to a static
# analyzer (Bandit for Python) for line+CWE.
#
# Pure logic, no model — unit-tested in tests/test_oracle_gates.py.
# ============================================================
import re
import difflib
from dataclasses import dataclass, field
from typing import Optional

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Common keywords / noise tokens to ignore when comparing identifiers.
_STOP = {
    "if", "else", "for", "while", "return", "function", "const", "let", "var",
    "def", "class", "import", "from", "export", "type", "interface", "new",
    "this", "self", "true", "false", "null", "none", "await", "async", "yield",
    "public", "private", "static", "void", "string", "number", "boolean", "int",
    "and", "or", "not", "in", "is", "the", "of", "to", "with", "as",
}


def identifiers(text: str) -> set[str]:
    """Identifier-like tokens worth comparing (len>2, not a keyword)."""
    return {t for t in _IDENT_RE.findall(text) if len(t) > 2 and t.lower() not in _STOP}


@dataclass
class Region:
    """Where the vulnerability is, per the oracle."""
    lines: set[int] = field(default_factory=set)        # 1-indexed lines in vuln_code
    identifiers: set[str] = field(default_factory=set)  # tokens the patch touched
    cwe: Optional[str] = None                           # ground-truth CWE if known
    source: str = "none"                                # "diff" | "analyzer" | "none"

    def known(self) -> bool:
        return self.source != "none" and bool(self.lines or self.identifiers)


def locate_from_diff(vuln_code: str, fixed_code: str) -> Region:
    """Lines in vuln_code that the fix removed/changed = the vulnerable region.

    Handles two cases:
      - full-method fixed_code  -> reliable line-level diff (replace/delete ops).
      - partial fixed snippet (morefixes "Fixed code:" is just the changed region)
        -> a line diff would over-mark, so if it marks >60% of the file we fall
        back to a token-level signal: the identifiers that actually changed
        between vuln and fixed, and the lines containing them.
    """
    vlines = vuln_code.splitlines()
    flines = fixed_code.splitlines()
    sm = difflib.SequenceMatcher(a=vlines, b=flines, autojunk=False)
    del_repl: set[int] = set()      # genuinely changed/removed vuln lines
    ins_ctx: set[int] = set()       # context adjacent to a pure insertion
    idents: set[str] = set()
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("replace", "delete"):
            for i in range(i1, i2):
                del_repl.add(i + 1)
                idents |= identifiers(vlines[i])
        elif tag == "insert":
            # Pure-insertion fix (a missing control was added). The vuln is the
            # ABSENCE near the insertion — mark adjacent old context, and learn
            # the identifiers the fix introduced.
            for i in (i1 - 1, i1):
                if 0 <= i < len(vlines):
                    ins_ctx.add(i + 1)
                    idents |= identifiers(vlines[i])
            for j in range(j1, j2):
                if 0 <= j < len(flines):
                    idents |= identifiers(flines[j])

    # Partial-fixed guard: only delete/replace dominance signals an unreliable
    # diff (fixed_code was a partial snippet). Insert-context marks don't count.
    if vlines and len(del_repl) > 0.6 * len(vlines):
        vset, fset = identifiers(vuln_code), identifiers(fixed_code)
        changed = (vset - fset) | (fset - vset)
        if changed:
            lines = {i + 1 for i, l in enumerate(vlines) if identifiers(l) & changed}
            return Region(lines=lines, identifiers=changed,
                          source="diff" if lines else "none")

    lines = del_repl | ins_ctx
    return Region(lines=lines, identifiers=idents,
                  source="diff" if lines else "none")


def locate_with_bandit(vuln_code: str) -> Region:
    """Best-effort Python fallback: run Bandit, take its finding lines + CWE.
    Returns an empty (source='none') Region if Bandit isn't available or finds
    nothing — never raises."""
    import json as _json
    import subprocess as _sp
    import tempfile as _tf
    import os as _os
    path = None
    try:
        with _tf.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write(vuln_code)
            path = f.name
        proc = _sp.run(["bandit", "-f", "json", "-q", path],
                       capture_output=True, text=True, timeout=30)
        data = _json.loads(proc.stdout or "{}")
        lines, idents, cwe = set(), set(), None
        vlines = vuln_code.splitlines()
        for res in data.get("results", []):
            ln = res.get("line_number")
            if isinstance(ln, int):
                lines.add(ln)
                if 1 <= ln <= len(vlines):
                    idents |= identifiers(vlines[ln - 1])
            c = (res.get("issue_cwe") or {}).get("id")
            if c and not cwe:
                cwe = f"CWE-{c}"
        return Region(lines=lines, identifiers=idents, cwe=cwe,
                      source="analyzer" if lines else "none")
    except Exception:
        return Region(source="none")
    finally:
        if path:
            try:
                _os.unlink(path)
            except Exception:
                pass


def locate_vuln(vuln_code: str, fixed_code: Optional[str] = None,
                cwe: Optional[str] = None, language: Optional[str] = None) -> Region:
    """Locate the vuln region. Prefer the patch diff; fall back to a static
    analyzer for Python. `cwe` (ground truth) is attached when provided."""
    region = Region(cwe=cwe)
    if fixed_code and fixed_code.strip() and fixed_code.strip() != vuln_code.strip():
        r = locate_from_diff(vuln_code, fixed_code)
        if r.known():
            region.lines, region.identifiers, region.source = r.lines, r.identifiers, "diff"
    if not region.known() and (language or "").lower().startswith("py"):
        r = locate_with_bandit(vuln_code)
        if r.known():
            region.lines, region.identifiers, region.source = r.lines, r.identifiers, "analyzer"
            region.cwe = region.cwe or r.cwe
    return region
