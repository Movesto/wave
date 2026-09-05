"""Intra-function value taint -- does the SPECIFIC untrusted value reach the sink? (Python, v1)

reachability.py answers "is the sink reachable from an entry"; this answers "does the untrusted VALUE get
there, and was it sanitized on the way". A lightweight, deterministic, INTRA-function backward trace:
  sources  = the enclosing function's parameters + common request objects (request/req/body/...)
  propagate: `x = <expr referencing a tainted name>` taints x; a strong cast/sanitizer (int()/escape()/
             quote()/a validate*/clean* call) marks x source-derived-but-CLEAN instead; a pure literal
             makes x a CONST
  at the sink line: are the sink-argument identifiers still tainted?
    flows      -> a source value reaches the sink unsanitized   (keep/strengthen the finding)
    sanitized  -> a source value reaches it but was cleaned      (precision signal)
    unrelated  -> the sink args are constants/literals only      (likely a mislabel -- eval-runner shape)
    unknown    -> non-Python / parse fail / a value from an unresolved call (could be CROSS-function taint)

Honest limits: intra-function only (cross-function flow stays the model's job on the slice -- and is
deliberately reported `unknown`, never `unrelated`, so we never gate away a real cross-function vuln),
name-based (no alias/type resolution), heuristic sanitizer list, Python only in v1. A PRECISION signal,
never a soundness proof -- the safe direction on any doubt is `unknown` (no effect).
"""
from __future__ import annotations

from pathlib import Path

# framework request objects whose attributes/items are untrusted (in addition to the function's own params)
_REQUEST_SOURCES = {"request", "req", "body", "params", "query", "form", "args", "data", "event", "payload"}
# strong casts/sanitizers that neutralize injection when they WRAP the tainted value (short name, lowercased)
_SANITIZERS = {"int", "float", "bool", "parseint", "number", "escape", "quote", "sanitize", "clean",
               "validate", "encode", "escapehtml", "encodeuricomponent", "secure_filename", "bleach",
               "uuid", "abs", "len"}


def _lang(path):
    return "python" if (path or "").lower().endswith(".py") else ""


def _walk(node):
    yield node
    for c in node.children:
        yield from _walk(c)


def _txt(node, src):
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _idents(node, src):
    return {_txt(n, src) for n in _walk(node) if n.type == "identifier"}


def _under_sanitizer(id_node, root, src):
    """True if this identifier occurrence sits inside a sanitizer/cast call within `root`."""
    p = id_node.parent
    while p is not None:
        if p.type == "call":
            f = p.child_by_field_name("function")
            if f is not None:
                nm = _txt(f, src).lower()
                if nm in _SANITIZERS or nm.split(".")[-1] in _SANITIZERS:
                    return True
        if p == root:
            break
        p = p.parent
    return False


def _taint_in_expr(node, src, tainted):
    """How the tainted set appears in `node`: 'raw' (a tainted id not under a sanitizer), 'clean' (tainted
    ids only under sanitizers), or 'none'."""
    raw = clean = False
    for n in _walk(node):
        if n.type == "identifier" and _txt(n, src) in tainted:
            if _under_sanitizer(n, node, src):
                clean = True
            else:
                raw = True
    if raw:
        return "raw"
    return "clean" if clean else "none"


def _enclosing_func(root, line):
    best = None
    for n in _walk(root):
        if n.type in ("function_definition",) and n.start_point[0] + 1 <= line <= n.end_point[0] + 1:
            span = n.end_point[0] - n.start_point[0]
            if best is None or span < best[0]:
                best = (span, n)
    return best[1] if best else None


def _param_names(fn, src):
    out = set()
    p = fn.child_by_field_name("parameters")
    if p is not None:
        for c in p.children:
            if c.type == "identifier":
                out.add(_txt(c, src))
            elif c.type in ("typed_parameter", "default_parameter", "typed_default_parameter"):
                for cc in _walk(c):
                    if cc.type == "identifier":
                        out.add(_txt(cc, src))
                        break
    out.discard("self")
    out.discard("cls")
    return out


def _classify_right(right, src, tainted, clean):
    """What does the RHS of an assignment carry? tainted / clean / const / opaque."""
    t = _taint_in_expr(right, src, tainted)
    if t == "raw":
        return "tainted"
    if t == "clean":
        return "clean"
    rids = _idents(right, src)
    if rids & clean:                                         # derived from an already-cleaned source value
        return "clean"
    has_call = any(n.type == "call" for n in _walk(right))
    if not rids and not has_call:                            # pure literal -> a constant, not user input
        return "const"
    return "opaque"                                          # from an unresolved call/name -> unknown provenance


def _call_at_line(fn, line, src):
    cands = [n for n in _walk(fn)
             if n.type == "call" and n.start_point[0] + 1 <= line <= n.end_point[0] + 1]
    if not cands:
        return None
    cands.sort(key=lambda n: (n.start_byte, -n.end_byte))   # outermost call covering the line = the sink
    return cands[0]


def analyze(candidate):
    """Return (status, note). status in flows | sanitized | unrelated | unknown. Never raises."""
    path = getattr(candidate, "file", "") or ""
    if _lang(path) != "python":
        return "unknown", ""
    line = int(getattr(candidate, "line", 0) or 0)
    if line <= 0:
        return "unknown", ""
    try:
        src = Path(path).read_bytes()
        from tree_sitter_language_pack import get_parser
        tree = get_parser("python").parse(src)
    except Exception:
        return "unknown", ""
    fn = _enclosing_func(tree.root_node, line)
    if fn is None:
        return "unknown", ""

    tainted = _param_names(fn, src) | _REQUEST_SOURCES
    clean, const = set(), set()
    for n in _walk(fn):
        if n.start_point[0] + 1 >= line:                    # stop at/after the sink line
            break
        if n.type not in ("assignment", "augmented_assignment"):
            continue
        left = n.child_by_field_name("left")
        right = n.child_by_field_name("right")
        if left is None or right is None:
            continue
        targets = _idents(left, src)
        kind = _classify_right(right, src, tainted, clean)
        if n.type == "augmented_assignment":                # x += ... : additive, never CLEARS existing taint
            if kind == "tainted":
                tainted |= targets
            continue
        for tgt in targets:
            tainted.discard(tgt); clean.discard(tgt); const.discard(tgt)
            if kind == "tainted":
                tainted.add(tgt)
            elif kind == "clean":
                clean.add(tgt)
            elif kind == "const":
                const.add(tgt)
            # opaque -> in no set (unknown provenance)

    sink = _call_at_line(fn, line, src)
    if sink is None:
        return "unknown", ""
    args = sink.child_by_field_name("arguments") or sink
    t = _taint_in_expr(args, src, tainted)
    if t == "raw":
        return "flows", "an untrusted value reaches the sink unsanitized (this function)"
    if t == "clean":
        return "sanitized", "the untrusted value is wrapped in a cast/sanitizer before the sink"
    sink_ids = _idents(args, src)
    if sink_ids & clean:
        return "sanitized", "the value reaching the sink was sanitized/reassigned upstream"
    if not sink_ids or sink_ids <= const:                   # literals / local constants only
        return "unrelated", "the sink arguments are constants/literals, not untrusted input (this function)"
    return "unknown", ""                                    # opaque local (maybe cross-function) -> don't gate
