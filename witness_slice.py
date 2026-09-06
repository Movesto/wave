"""Prototype: witness on the DATAFLOW SLICE, not the whole function.

The current witness scans a whole function for guard shapes. That over-flags when an
insufficient-LOOKING guard appears early but a proper NEUTRALISER is applied to the value
before it reaches the sink (order-of-operations), and it can attribute a guard to the wrong
variable. A CPG (Joern) fixes this generally; here we approximate the idea cheaply with a
backward slice on the sink's tainted argument, using only regex on single-function JS/TS.

slice_verdict():
  1. find the variable(s) feeding the sink,
  2. backward-resolve them through `x = f(y)` assignments to the ORDERED transform chain
     from source to sink,
  3. if a NEUTRALISER for the sink kind is on that chain -> SAFE (the effective transform
     wins over any earlier guard-shaped line),
  4. otherwise fall back to the existing whole-function witness_scan.

This demonstrates the PRINCIPLE (slice > whole-function) before committing to Joern.
"""
import re
from guard_witness import witness_scan

# a construct that, applied to a value, neutralises the sink kind
NEUTRALISERS = {
    "path": [r"\bbasename\s*\(", r"path\.basename\s*\("],
    "command": [r"\bescapeshellarg\s*\(", r"\bshlex\.quote\s*\(",
                r"(?:execFile|execFileSync|spawn|spawnSync)\s*\(\s*[^,]+,\s*\["],
    "xss": [r"\.textContent\b", r"DOMPurify\.sanitize\s*\("],
    "redirect": [r"encodeURIComponent\s*\("],
}
_ASSIGN = re.compile(r"(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)")
_IDENT = re.compile(r"[A-Za-z_$][\w$]*")


def _assign_map(code):
    m = {}
    for a in _ASSIGN.finditer(code):
        m.setdefault(a.group(1), a.group(2).strip())     # first assignment wins
    return m


def backward_chain(code, sink_arg):
    """Ordered list of RHS expressions from the sink arg back toward the source."""
    amap = _assign_map(code)
    seen, chain, frontier = set(), [], list(_IDENT.findall(sink_arg))
    # walk the assignment graph backward, recording each transforming RHS
    while frontier:
        v = frontier.pop(0)
        if v in seen or v not in amap:
            continue
        seen.add(v)
        rhs = amap[v]
        chain.append(rhs)
        frontier.extend(_IDENT.findall(rhs))
    return chain


def slice_verdict(code, sink_arg, kind):
    """(verdict, why) where verdict in {'safe','vuln','unknown'} using the slice."""
    chain_text = " ".join(backward_chain(code, sink_arg)) + " " + sink_arg
    for rx in NEUTRALISERS.get(kind, []):
        if re.search(rx, chain_text):
            return "safe", f"neutraliser on the sink path: {rx}"
    w = witness_scan(code, kind)
    if w:
        return "vuln", f"witness: {w['bypass']} ({w['guard']})"
    return "unknown", "no neutraliser on path, no witness proof"


def whole_verdict(code, kind):
    """What the CURRENT whole-function witness concludes (vuln if it fires, else unknown)."""
    w = witness_scan(code, kind)
    return ("vuln", f"witness: {w['bypass']}") if w else ("unknown", "witness silent")


# ---- test cases: sink_arg names the tainted expression passed to the sink ----
CASES = [
 ("A insufficient-then-neutralised (whole should OVER-FLAG, slice SAFE)", "safe", "path",
  "path.join(BASE, safe)",
  "function serve(raw){\n"
  "  if (raw.includes('..')) throw new Error('bad');\n"     # insufficient-LOOKING
  "  const safe = path.basename(raw);\n"                     # but neutralised after
  "  return fs.readFileSync(path.join(BASE, safe));\n}"),

 ("B genuinely insufficient (both VULN)", "vuln", "path",
  "BASE + raw",
  "function serve(raw){\n"
  "  if (raw.includes('..')) throw new Error('bad');\n"
  "  return fs.readFileSync(BASE + raw);\n}"),

 ("C neutraliser only (both SAFE)", "safe", "path",
  "path.join(BASE, path.basename(raw))",
  "function serve(raw){\n"
  "  return fs.readFileSync(path.join(BASE, path.basename(raw)));\n}"),

 ("D command: escaped-then-used (whole silent, slice SAFE)", "safe", "command",
  "cmd",
  "function run(file){\n"
  "  const safe = escapeshellarg(file);\n"
  "  const cmd = 'convert ' + safe;\n"
  "  return execSync(cmd);\n}"),

 ("E xss: textContent (both SAFE)", "safe", "xss",
  "input",
  "function render(el, input){\n  el.textContent = input;\n}"),
]


def main():
    print(f"{'case':56s} {'truth':5s} {'WHOLE':8s} {'SLICE':8s}")
    wl = sl = 0
    for name, truth, kind, sink_arg, code in CASES:
        wv, _ = whole_verdict(code, kind)
        sv, swhy = slice_verdict(code, sink_arg, kind)
        # map 'unknown' to 'safe' for scoring the safe cases (no proof of vuln == not flagged)
        w_final = "vuln" if wv == "vuln" else "safe"
        s_final = "vuln" if sv == "vuln" else "safe"
        wl += (w_final == truth); sl += (s_final == truth)
        wmark = "OK" if w_final == truth else "XX"
        smark = "OK" if s_final == truth else "XX"
        print(f"{name:56s} {truth:5s} {w_final:5s}{wmark:3s} {s_final:5s}{smark:3s}")
    print(f"\nWHOLE-function witness : {wl}/{len(CASES)}")
    print(f"SLICE-aware witness    : {sl}/{len(CASES)}")


if __name__ == "__main__":
    main()
