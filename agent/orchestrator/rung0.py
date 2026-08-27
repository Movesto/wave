"""Rung 0 of the confirmation ladder (investigation-loop plan §3.4): STATIC reachability + sanitization.
No execution. For a discovered candidate it answers, from the code alone:

  - SAFE      -- the tainted input provably does NOT reach the sink as raw text (parameterized SQL,
                 a constant/literal-derived argument, or a recognized sanitizer). -> REFUTE (proven-safe).
  - REACHABLE -- user input provably flows into the sink unsanitized. -> ELEVATE (a strong lead).
  - UNKNOWN   -- can't prove either way. -> hand to a higher rung (NEVER cleared).

SOUNDNESS (the rung's whole job): it may only DEFER-SAFE or ELEVATE, never emit a finding on its own,
and when unsure it does NOT clear. Scope is intra-procedural + known-sanitizer recognition (Python AST);
non-Python / unparseable / anything uncertain -> UNKNOWN. Conservative by construction.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass

_SQL_CALLS = {"execute", "executemany", "executescript", "text", "query", "raw", "mogrify"}
_UNWRAP = {"text", "query"}                              # execute(text("..."), ...) -> analyze the inner string
_USER_ROOTS = {"request", "req", "flask"}               # attribute roots that are user input
_USER_ATTRS = {"args", "form", "values", "json", "data", "params", "query_params", "path_params",
               "cookies", "headers", "GET", "POST"}
# recognized sanitizers by the CWE they neutralize. ONLY functions that genuinely neutralize the class
# belong here -- a false clear is a missed vuln (the cardinal Rung-0 sin). CWE-918 has NO entry: urlparse
# does NOT sanitize SSRF (an allow-list does, which we don't yet detect), so SSRF is never Rung-0-cleared.
_SANITIZERS = {
    "CWE-79": {"escape", "clean", "bleach", "markupsafe", "escape_html"},
    "CWE-22": {"secure_filename", "basename", "safe_join"},
}


@dataclass
class Assessment:
    verdict: str            # "safe" | "reachable" | "unknown"
    reason: str
    rung: int = 0


def _seg(node):
    return (getattr(node, "lineno", 0), getattr(node, "end_lineno", getattr(node, "lineno", 0)))


def _enclosing_func(tree, line):
    best = None
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            lo, hi = _seg(n)
            if lo <= line <= hi and (best is None or lo >= _seg(best)[0]):
                best = n
    return best


def _user_names(func):
    """Names that are user input inside a handler: its parameters (minus self/cls)."""
    if func is None:
        return set()
    a = func.args
    names = [p.arg for p in (a.posonlyargs + a.args + a.kwonlyargs)]
    if a.vararg:
        names.append(a.vararg.arg)
    if a.kwarg:
        names.append(a.kwarg.arg)
    return {n for n in names if n not in ("self", "cls")}


def _is_user_expr(node, users):
    """Direct reference to a user source: a handler param, or request.args / req.form / etc."""
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and n.id in users:
            return True
        if isinstance(n, ast.Attribute):
            root = n
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id in _USER_ROOTS:
                return True
            if isinstance(n.value, ast.Name) and n.value.id in _USER_ROOTS and n.attr in _USER_ATTRS:
                return True
    return False


def _assignments(name, func):
    """Every value that flows into `name` in `func`: assigns, aug-assigns, and list .append()s."""
    vals = []
    for n in ast.walk(func):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    vals.append(n.value)
        elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and n.target.id == name:
            vals.append(n.value)
        elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
              and n.func.attr in ("append", "extend", "insert") and isinstance(n.func.value, ast.Name)
              and n.func.value.id == name):
            vals.extend(a for a in n.args if not isinstance(a, ast.Starred))
    return vals


def _traces_to_user(name, func, users, seen):
    if name in seen:
        return False
    seen = seen | {name}
    for v in _assignments(name, func):
        if _is_user_expr(v, users):
            return True
        for sub in ast.walk(v):
            if isinstance(sub, ast.Name) and sub.id != name and _traces_to_user(sub.id, func, users, seen):
                return True
    return False


def _literalish(node, func, users, seen):
    """True only if `node` is PROVABLY built from string/number literals (no user input, no unknowns)."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (str, int, float, bool)) or node.value is None
    if isinstance(node, ast.JoinedStr):
        return all(_literalish(v.value, func, users, seen) for v in node.values
                   if isinstance(v, ast.FormattedValue))
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _literalish(node.left, func, users, seen) and _literalish(node.right, func, users, seen)
    if isinstance(node, ast.IfExp):
        return _literalish(node.body, func, users, seen) and _literalish(node.orelse, func, users, seen)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_literalish(e, func, users, seen) for e in node.elts)
    if isinstance(node, ast.Call):                       # sep.join(x)  or  "..".format(..)
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("join", "format"):
            parts = [node.func.value] + list(node.args)
            return all(_literalish(p, func, users, seen) for p in parts)
        return False
    if isinstance(node, ast.Name):
        return _literal_derived(node.id, func, users, seen)
    return False


def _literal_derived(name, func, users, seen):
    if name in users:
        return False
    if name in seen:
        return False
    seen = seen | {name}
    vals = _assignments(name, func)
    if not vals:                                         # free/undefined here -> can't prove safe
        return False
    return all(_literalish(v, func, users, seen) for v in vals)


def _query_interps(node):
    """Sub-expressions interpolated into a query string (f-string parts, + operands, .format args)."""
    out = []
    if isinstance(node, ast.JoinedStr):
        out += [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
    elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        out += _query_interps(node.left) + _query_interps(node.right)
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        out += list(node.args)
    elif isinstance(node, ast.Name) or isinstance(node, (ast.Attribute, ast.Subscript)):
        out.append(node)
    return out


def _find_sql_call(func, line):
    best = None
    for n in ast.walk(func):
        if isinstance(n, ast.Call):
            f = n.func
            nm = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else None)
            if nm in _SQL_CALLS:
                d = abs(_seg(n)[0] - line)
                if best is None or d < best[0]:
                    best = (d, n)
    return best[1] if best else None


def _assess_sql(func, call, users):
    query = call.args[0] if call.args else None
    if query is None:
        return None
    if isinstance(query, ast.Call) and isinstance(query.func, (ast.Name, ast.Attribute)):
        nm = query.func.attr if isinstance(query.func, ast.Attribute) else query.func.id
        if nm in _UNWRAP and query.args:                # execute(text("..."), ...) -> the inner string
            query = query.args[0]
    if isinstance(query, ast.Constant):
        return Assessment("safe", "query is a constant string (no interpolation)")
    interps = _query_interps(query)
    if not interps:
        return Assessment("safe", "query has no interpolated values")
    reachable = safe = unknown = 0
    for it in interps:
        if _is_user_expr(it, users) or (isinstance(it, ast.Name) and _traces_to_user(it.id, func, users, set())):
            reachable += 1
        elif _literalish(it, func, users, set()):
            safe += 1
        else:
            unknown += 1
    if reachable:
        return Assessment("reachable", "user input is interpolated into the SQL string (not parameterized)")
    if unknown == 0:
        return Assessment("safe", "SQL string is built only from constant clauses; user values are parameterized")
    return None                                          # unsure -> hand up


def _assess_sanitizer(func, line, cwe):
    """Best-effort: the tainted arg at the sink is wrapped in a recognized sanitizer for this CWE."""
    names = _SANITIZERS.get(cwe) or set()
    if not names:
        return None
    for n in ast.walk(func):
        if isinstance(n, ast.Call) and abs(_seg(n)[0] - line) <= 2:
            for sub in ast.walk(n):
                if isinstance(sub, ast.Call):
                    f = sub.func
                    nm = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
                    if nm in names:
                        return Assessment("safe", f"argument passes through sanitizer {nm}() for {cwe}")
    return None


def assess(candidate) -> Assessment:
    """Static Rung-0 verdict for a candidate. Conservative: unknown unless it can prove safe/reachable."""
    path = getattr(candidate, "file", "")
    if not path.endswith(".py"):
        return Assessment("unknown", "non-Python source -- Rung 0 not applicable (scoped to Python AST)")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            tree = ast.parse(fh.read())
    except (OSError, SyntaxError) as e:
        return Assessment("unknown", f"could not parse source: {e}")
    line = getattr(candidate, "line", 0) or 0
    func = _enclosing_func(tree, line)
    if func is None:
        return Assessment("unknown", "no enclosing function found for the sink")
    users = _user_names(func)
    cwe = getattr(candidate, "cwe", "")
    if cwe == "CWE-89":
        call = _find_sql_call(func, line)
        if call is not None:
            a = _assess_sql(func, call, users)
            if a is not None:
                return a
    a = _assess_sanitizer(func, line, cwe)
    if a is not None:
        return a
    return Assessment("unknown", "no static proof of safe/reachable -- hand to a higher rung")
