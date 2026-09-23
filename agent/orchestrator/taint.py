"""Value taint -- does the SPECIFIC untrusted value reach the sink? (Python + JS/TS)

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
    unknown    -> unsupported lang / parse fail / a value from an unresolved call (maybe CROSS-function)

Honest limits: intra-function only (cross-function flow stays the model's job on the slice -- and is
deliberately reported `unknown`, never `unrelated`, so we never gate away a real cross-function vuln),
name-based (no alias/type resolution), heuristic sanitizer list. Now Python + JS/TS (other langs -> unknown).
A PRECISION signal, never a soundness proof -- the safe direction on any doubt is `unknown` (no effect).
"""
from __future__ import annotations

from pathlib import Path

# framework request objects whose attributes/items are untrusted (in addition to the function's own params)
_REQUEST_SOURCES = {"request", "req", "body", "params", "query", "form", "args", "data", "event", "payload",
                    "ctx", "context", "params_", "searchparams"}
# strong casts/sanitizers that neutralize injection when they WRAP the tainted value (short name, lowercased)
_SANITIZERS = {"int", "float", "bool", "parseint", "parsefloat", "number", "escape", "quote", "sanitize",
               "clean", "validate", "encode", "escapehtml", "encodeuricomponent", "encodeuri",
               "secure_filename", "bleach", "uuid", "abs", "len", "tostring", "json", "stringify"}

# per-language tree-sitter node vocabulary -- the algorithm is identical, only the node names differ.
_LANGS = {
    "python": {
        "parser": "python",
        "func": ("function_definition",),
        "params_field": ("parameters",),
        "param_wrap": ("typed_parameter", "default_parameter", "typed_default_parameter"),
        "assign": ("assignment",),
        "aug": ("augmented_assignment",),
        "decl": (),                                          # python uses `assignment` for x = ...
        "call": ("call",),
        "call_fn": "function",
        "call_args": "arguments",
    },
    "javascript": {
        "parser": "javascript",
        "func": ("function_declaration", "function_expression", "arrow_function", "method_definition",
                 "generator_function_declaration"),
        "params_field": ("formal_parameters", "parameters"),
        "param_wrap": ("required_parameter", "optional_parameter", "rest_pattern", "assignment_pattern"),
        "assign": ("assignment_expression", "augmented_assignment_expression"),
        "aug": ("augmented_assignment_expression",),
        "decl": ("variable_declarator",),                   # const/let/var x = ...
        "call": ("call_expression",),
        "call_fn": "function",
        "call_args": "arguments",
    },
}
_LANGS["typescript"] = {**_LANGS["javascript"], "parser": "typescript"}
_LANGS["tsx"] = {**_LANGS["javascript"], "parser": "tsx"}
_LANGS["go"] = {
    "parser": "go", "func": ("function_declaration", "method_declaration"),
    "params_field": ("parameters",), "param_wrap": ("parameter_declaration", "variadic_parameter_declaration"),
    "assign": ("assignment_statement",), "aug": (), "decl": ("short_var_declaration",),
    "call": ("call_expression",), "call_fn": "function", "call_args": "arguments",
}
_LANGS["java"] = {
    "parser": "java", "func": ("method_declaration", "constructor_declaration"),
    "params_field": ("parameters",), "param_wrap": ("formal_parameter", "spread_parameter"),
    "assign": ("assignment_expression",), "aug": (), "decl": ("variable_declarator",),
    "call": ("method_invocation",), "call_fn": "name", "call_args": "arguments",
}
_LANGS["csharp"] = {
    "parser": "csharp", "func": ("method_declaration", "constructor_declaration", "local_function_statement"),
    "params_field": ("parameters",), "param_wrap": ("parameter",),
    "assign": ("assignment_expression",), "aug": (), "decl": ("variable_declarator",),
    "call": ("invocation_expression",), "call_fn": "function", "call_args": "arguments",
}
_LANGS["ruby"] = {
    "parser": "ruby", "func": ("method", "singleton_method"),
    "params_field": ("parameters", "method_parameters"), "param_wrap": ("optional_parameter", "keyword_parameter",
                                                                        "splat_parameter"),
    "assign": ("assignment",), "aug": ("operator_assignment",), "decl": (),
    "call": ("call", "method_call"), "call_fn": "method", "call_args": "arguments",
}
_LANGS["php"] = {
    "parser": "php", "func": ("function_definition", "method_declaration"),
    "params_field": ("parameters", "formal_parameters"), "param_wrap": ("simple_parameter",
                                                                        "property_promotion_parameter"),
    "assign": ("assignment_expression",), "aug": ("augmented_assignment_expression",), "decl": (),
    "call": ("function_call_expression", "member_call_expression", "scoped_call_expression"),
    "call_fn": "function", "call_args": "arguments",
}
_LANGS["rust"] = {
    "parser": "rust", "func": ("function_item",),
    "params_field": ("parameters",), "param_wrap": ("parameter",),
    "assign": ("assignment_expression",), "aug": ("compound_assignment_expr",), "decl": ("let_declaration",),
    "call": ("call_expression", "macro_invocation"), "call_fn": "function", "call_args": "arguments",
}

# containers whose descendant identifiers are parameter names (over-including a type name is recall-safe)
_PARAM_CONTAINERS = {"parameters", "formal_parameters", "parameter_list", "method_parameters",
                     "function_value_parameters"}
_ID_TYPES = ("identifier", "property_identifier", "shorthand_property_identifier",
             "shorthand_property_identifier_pattern", "variable_name")


_EXT = {".py": "python", ".ts": "typescript", ".tsx": "tsx", ".js": "javascript", ".mjs": "javascript",
        ".cjs": "javascript", ".jsx": "javascript", ".go": "go", ".java": "java", ".cs": "csharp",
        ".rb": "ruby", ".php": "php", ".rs": "rust"}


def _lang(path):
    p = (path or "").lower()
    for ext, lang in _EXT.items():
        if p.endswith(ext):
            return lang
    return ""


def _walk(node):
    yield node
    for c in node.children:
        yield from _walk(c)


def _txt(node, src):
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _idents(node, src):
    return {_txt(n, src) for n in _walk(node) if n.type in _ID_TYPES}


def _under_sanitizer(id_node, root, src, cfg):
    """True if this identifier occurrence sits inside a sanitizer/cast call within `root`."""
    p = id_node.parent
    while p is not None:
        if p.type in cfg["call"]:
            f = p.child_by_field_name(cfg["call_fn"])
            if f is not None:
                nm = _txt(f, src).lower()
                if nm in _SANITIZERS or nm.split(".")[-1] in _SANITIZERS:
                    return True
        if p == root:
            break
        p = p.parent
    return False


def _taint_in_expr(node, src, tainted, cfg):
    """How the tainted set appears in `node`: 'raw' (a tainted id not under a sanitizer), 'clean' (tainted
    ids only under sanitizers), or 'none'."""
    raw = clean = False
    for n in _walk(node):
        if n.type in _ID_TYPES and _txt(n, src) in tainted:
            if _under_sanitizer(n, node, src, cfg):
                clean = True
            else:
                raw = True
    if raw:
        return "raw"
    return "clean" if clean else "none"


def _enclosing_func(root, line, cfg):
    best = None
    for n in _walk(root):
        if n.type in cfg["func"] and n.start_point[0] + 1 <= line <= n.end_point[0] + 1:
            span = n.end_point[0] - n.start_point[0]
            if best is None or span < best[0]:
                best = (span, n)
    return best[1] if best else None


def _param_names(fn, src, cfg):
    """Every identifier in the parameter list is treated as an untrusted source. Over-including a type name
    (e.g. Java `String id` -> {String, id}) is RECALL-SAFE: it can only add taint, never gate a real flow."""
    out = set()
    p = None
    for fld in cfg["params_field"]:                          # the params as a named field
        p = fn.child_by_field_name(fld)
        if p is not None:
            break
    if p is None:                                            # else a direct child of a param-container type
        for c in fn.children:
            if c.type in _PARAM_CONTAINERS:
                p = c
                break
    if p is None:                                            # arrow fn with a single bare param: x => ...
        for c in fn.children:
            if c.type == "identifier":
                out.add(_txt(c, src))
        return out - {"self", "cls"}
    for n in _walk(p):
        if n.type in _ID_TYPES:
            out.add(_txt(n, src))
    out.discard("self")
    out.discard("cls")
    return out


def _classify_right(right, src, tainted, clean, cfg):
    """What does the RHS of an assignment carry? tainted / clean / const / opaque."""
    t = _taint_in_expr(right, src, tainted, cfg)
    if t == "raw":
        return "tainted"
    if t == "clean":
        return "clean"
    rids = _idents(right, src)
    if rids & clean:                                         # derived from an already-cleaned source value
        return "clean"
    has_call = any(n.type in cfg["call"] for n in _walk(right))
    if not rids and not has_call:                            # pure literal -> a constant, not user input
        return "const"
    return "opaque"                                          # from an unresolved call/name -> unknown provenance


def _assign_sides(n, cfg):
    """(left, right) for an assignment/declaration, across python (left/right) and js (left/right or
    name/value for a variable_declarator)."""
    left = (n.child_by_field_name("left") or n.child_by_field_name("name")
            or n.child_by_field_name("pattern"))            # rust `let x = ...` uses pattern/value
    right = n.child_by_field_name("right") or n.child_by_field_name("value")
    if left is not None and right is not None:
        return left, right
    kids = list(n.children)                                  # fallback: positional around '=' (c#/php: no fields)
    for i, c in enumerate(kids):
        if c.type == "=" and i + 1 < len(kids):
            return (left or (kids[i - 1] if i > 0 else None)), kids[i + 1]
    return left, right


def _calls_at_line(fn, line, cfg):
    """EVERY call node covering `line` (outermost first). A chained sink like
    `subprocess.run(<tainted>).decode('utf-8')` is TWO calls on one line -- taint must consider both, not
    only the outermost (whose args here are constants), or the real sink's tainted args are missed."""
    cands = [n for n in _walk(fn)
             if n.type in cfg["call"] and n.start_point[0] + 1 <= line <= n.end_point[0] + 1]
    cands.sort(key=lambda n: (n.start_byte, -n.end_byte))
    return cands


def analyze(candidate):
    """Return (status, note). status in flows | sanitized | unrelated | unknown. Never raises."""
    path = getattr(candidate, "file", "") or ""
    lang = _lang(path)
    if lang not in _LANGS:
        return "unknown", ""
    cfg = _LANGS[lang]
    line = int(getattr(candidate, "line", 0) or 0)
    if line <= 0:
        return "unknown", ""
    try:
        src = Path(path).read_bytes()
        from tree_sitter_language_pack import get_parser
        tree = get_parser(cfg["parser"]).parse(src)
    except Exception:
        return "unknown", ""
    fn = _enclosing_func(tree.root_node, line, cfg)
    if fn is None:
        return "unknown", ""

    tainted = _param_names(fn, src, cfg) | _REQUEST_SOURCES
    clean, const = set(), set()
    assign_types = set(cfg["assign"]) | set(cfg["decl"])
    for n in _walk(fn):
        if n.start_point[0] + 1 >= line:                    # stop at/after the sink line
            break
        if n.type not in assign_types:
            continue
        left, right = _assign_sides(n, cfg)
        if left is None or right is None:
            continue
        targets = _idents(left, src)
        kind = _classify_right(right, src, tainted, clean, cfg)
        if n.type in cfg["aug"]:                             # x += ... : additive, never CLEARS existing taint
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

    calls = _calls_at_line(fn, line, cfg)
    if not calls:
        return "unknown", ""
    # Aggregate taint across EVERY call covering the line: a chained sink `subprocess.run(<tainted>).decode(
    # 'utf-8')` must not read 'unrelated' just because the OUTER call's args are constants -- the inner
    # (real) sink's args carry the taint. raw on ANY call -> flows; else clean -> sanitized; else the union
    # of all args decides const/opaque.
    agg_raw = agg_clean = False
    sink_ids = set()
    for call in calls:
        args = call.child_by_field_name(cfg["call_args"]) or call
        tt = _taint_in_expr(args, src, tainted, cfg)
        if tt == "raw":
            agg_raw = True
        elif tt == "clean":
            agg_clean = True
        sink_ids |= _idents(args, src)
    if agg_raw:
        return "flows", "an untrusted value reaches the sink unsanitized (this function)"
    if agg_clean or (sink_ids & clean):
        return "sanitized", "the untrusted value is wrapped in a cast/sanitizer before the sink"
    if not sink_ids or sink_ids <= const:                   # literals / local constants only
        return "unrelated", "the sink arguments are constants/literals, not untrusted input (this function)"
    return "unknown", ""                                    # opaque local (maybe cross-function) -> don't gate
