"""Cross-function taint -- trace an untrusted value from its SOURCE to the sink ACROSS function calls.

`taint.py` answers "does the untrusted value reach the sink WITHIN this function". Most real vulns span
functions: input enters a route handler, is passed to a helper, and reaches a dangerous call two hops down.
This module walks BACKWARD from the sink's function: which of its parameters reach the sink, then which
CALLERS pass an untrusted value (a request source, or -- transitively -- their own parameter) into that
parameter position. When the chain reaches a request source (or an external/entry boundary parameter), the
flow is proven deterministically and we return the SOURCE -> ... -> SINK path (which the proof brief cites).

Scope (first cut, per the review's "same-file chains first"): SAME-FILE chains, Python + JS/TS, depth <= 5,
CONSERVATIVE -- anything ambiguous (cross-file, opaque arg, unsupported lang) yields None (never a false
chain). It only ADDS a deterministic path where it can prove one; it never downgrades a finding.
"""
from __future__ import annotations

from pathlib import Path

from . import taint as _t

_MAX_DEPTH = 5


def _positional_params(fn, src, cfg):
    """Ordered parameter names as they map to POSITIONAL call arguments (implicit self/cls dropped, so a
    method's first real arg lines up with index 0). One name per slot; "" for a slot with no plain id."""
    p = None
    for fld in cfg["params_field"]:
        p = fn.child_by_field_name(fld)
        if p is not None:
            break
    if p is None:
        for c in fn.children:
            if c.type in _t._PARAM_CONTAINERS:
                p = c
                break
    names = []
    if p is None:                                              # arrow fn with a single bare param: x => ...
        for c in fn.children:
            if c.type == "identifier":
                names.append(_t._txt(c, src))
        return names
    for c in p.named_children:
        if c.type == "comment":
            continue
        if c.type in _t._ID_TYPES:
            names.append(_t._txt(c, src))
        else:
            nm = ""
            for n in _t._walk(c):
                if n.type in _t._ID_TYPES:
                    nm = _t._txt(n, src)
                    break
            names.append(nm)
    while names and names[0] in ("self", "cls"):              # implicit receiver -> not a positional arg
        names.pop(0)
    return names


def _propagate(fn, before_line, sources, src, cfg):
    """Intra-function taint propagation (same rules as taint.analyze) seeded with `sources`, up to but not
    including `before_line`. Returns the tainted variable set at that point."""
    tainted, clean, const = set(sources), set(), set()
    assign_types = set(cfg["assign"]) | set(cfg["decl"])
    for n in _t._walk(fn):
        if n.start_point[0] + 1 >= before_line:
            break
        if n.type not in assign_types:
            continue
        left, right = _t._assign_sides(n, cfg)
        if left is None or right is None:
            continue
        targets = _t._idents(left, src)
        kind = _t._classify_right(right, src, tainted, clean, cfg)
        if n.type in cfg["aug"]:
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
    return tainted


def _reaches(fn, sink_line, sources, src, cfg):
    """Does any name in `sources` reach the SINK CALL at `sink_line`? 'raw' | 'clean' | 'none'."""
    tainted = _propagate(fn, sink_line, sources, src, cfg)
    raw = cleanf = False
    for call in _t._calls_at_line(fn, sink_line, cfg):
        args = call.child_by_field_name(cfg["call_args"]) or call
        tt = _t._taint_in_expr(args, src, tainted, cfg)
        if tt == "raw":
            raw = True
        elif tt == "clean":
            cleanf = True
    return "raw" if raw else ("clean" if cleanf else "none")


def _expr_taint(fn, before_line, expr, sources, src, cfg):
    """Is `expr` (an argument at a call site) carrying taint from `sources`, given propagation up to
    `before_line` within `fn`? 'raw' | 'clean' | 'none'."""
    tainted = _propagate(fn, before_line, sources, src, cfg)
    return _t._taint_in_expr(expr, src, tainted, cfg)


def _func_defs(root, cfg, src):
    """(name, node) for every function/method def in the file."""
    out = []
    for n in _t._walk(root):
        if n.type in cfg["func"]:
            nm = n.child_by_field_name("name")
            if nm is None:                                     # arrow/anon assigned to a var: `const f = () =>`
                par = n.parent
                nm = par.child_by_field_name("name") if par is not None else None
            out.append((_t._txt(nm, src) if nm is not None else "", n))
    return out


def _positional_args(call, cfg):
    """Positional argument nodes of a call, in order (skips punctuation / keyword args)."""
    a = call.child_by_field_name(cfg["call_args"])
    if a is None:
        return []
    out = []
    for c in a.named_children:
        if c.type in ("comment", "keyword_argument"):         # kwargs don't map positionally (conservative)
            continue
        out.append(c)
    return out


def _callee_name(call, src, cfg):
    f = call.child_by_field_name(cfg["call_fn"])
    return _t._txt(f, src).split(".")[-1] if f is not None else ""


def _calls_to(fn, name, src, cfg):
    return [n for n in _t._walk(fn) if n.type in cfg["call"] and _callee_name(n, src, cfg) == name]


def analyze(candidate, max_depth=_MAX_DEPTH):
    """Trace a cross-function source->sink chain for `candidate`. Returns a dict
    {status:'flows'|'flows_intra', source, chain:[{func,line}...], note} or None. Never raises."""
    path = getattr(candidate, "file", "") or ""
    lang = _t._lang(path)
    line = int(getattr(candidate, "line", 0) or 0)
    if lang not in _t._LANGS or line <= 0:
        return None
    cfg = _t._LANGS[lang]
    try:
        src = Path(path).read_bytes()
        from tree_sitter_language_pack import get_parser
        root = get_parser(cfg["parser"]).parse(src).root_node
    except Exception:
        return None
    defs = _func_defs(root, cfg, src)
    sink_fn = _t._enclosing_func(root, line, cfg)
    if sink_fn is None:
        return None
    sink_name = next((nm for nm, node in defs if node == sink_fn), "")

    # in-function request source already reaches the sink -> intra-function (taint.py covers it; note it).
    if _reaches(sink_fn, line, set(_t._REQUEST_SOURCES), src, cfg) == "raw":
        return {"status": "flows_intra", "source": "a request object in this function",
                "chain": [{"func": sink_name, "line": line}],
                "note": f"untrusted request input reaches the sink in {sink_name}"}

    positional = _positional_params(sink_fn, src, cfg)
    reaching = [i for i, nm in enumerate(positional) if nm and _reaches(sink_fn, line, {nm}, src, cfg) == "raw"]
    if not reaching:
        return None                                            # sink args are constants/opaque -> nothing to trace

    def walk(fn_name, fn_node, positions, depth, seen):
        """Find a caller (same file) that feeds an untrusted value into one of `positions` of fn_name."""
        if depth > max_depth or not fn_name:
            return None
        callers = [(nm, node) for nm, node in defs if node != fn_node and _calls_to(node, fn_name, src, cfg)]
        for cname, cnode in callers:
            if (cname, cnode.start_byte) in seen:
                continue
            for call in _calls_to(cnode, fn_name, src, cfg):
                args = _positional_args(call, cfg)
                cline = call.start_point[0] + 1
                for pos in positions:
                    if pos >= len(args):
                        continue
                    arg = args[pos]
                    # (a) the arg carries a REQUEST source in the caller (directly, or via a tainted local)
                    if _expr_taint(cnode, cline, arg, set(_t._REQUEST_SOURCES), src, cfg) == "raw":
                        return [{"func": cname, "line": cline, "source": _t._txt(arg, src)[:80]}]
                    # (b) the arg traces to a PARAMETER of the caller -> recurse up to that param's callers
                    cparams = _positional_params(cnode, src, cfg)
                    fed_params = [i for i, nm in enumerate(cparams)
                                  if nm and _expr_taint(cnode, cline, arg, {nm}, src, cfg) == "raw"]
                    if fed_params:
                        deeper = walk(cname, cnode, fed_params, depth + 1, seen | {(cname, cnode.start_byte)})
                        if deeper is not None:
                            return deeper + [{"func": cname, "line": cline}]
                        # no in-file caller feeds it -> the caller's param is the external/entry boundary
                        if not [1 for nm, node in defs if node != cnode and _calls_to(node, cname, src, cfg)]:
                            pname = cparams[fed_params[0]]
                            return [{"func": cname, "line": cline, "source": f"parameter '{pname}' (external input)"}]
        return None

    chain = walk(sink_name, sink_fn, reaching, 1, {(sink_name, sink_fn.start_byte)})
    if chain is None:
        return None
    full = chain + [{"func": sink_name, "line": line}]
    entry = full[0]
    hops = " -> ".join(h["func"] for h in full)
    return {"status": "flows", "source": entry.get("source", "untrusted input"),
            "chain": full, "note": f"untrusted input ({entry.get('source', '?')}) in {entry['func']} "
                                   f"flows to the sink via {hops}"}
