"""The reachability gate -- does UNTRUSTED input actually reach a proven sink?

Proving a sink FIRES (Stage 3) is not proving it is a VULN. An eval-runner executes code by design; a
dangerous helper reached only by trusted internal code is not attacker-exploitable. This gate walks the
Stage-1 call graph BACKWARD from the sink's enclosing function to an UNTRUSTED-FACING entry -- a decorated
HTTP route, or a main/handler/consumer. Found -> the confirmation stands (and we cite the path). Not found
-> the finding is DOWNGRADED to `anomalous_state` (human-review): the sink is real, but no untrusted path
was established (it may be internal/intended). The finding is never DROPPED -- only re-categorized -- because
the name-based call graph can miss edges.

Honest limits: this is FUNCTION-level reachability over codemap's name-matched call graph, NOT value-level
taint (whether the specific tainted argument flows to the sink) -- the architecture's open §10.4. It is a
coarse precision gate, not a soundness proof; the safe direction on uncertainty is human-review, not silence.
"""
import re
from collections import deque

# --- Execution-context gate: server-side sink classes cannot occur in BROWSER/frontend code. A client-side
# `fetch(url)` is not server-side SSRF; browser code has no SQL, filesystem, or shell. So a server-only sink
# proven in frontend code is a mislabel, not a vuln (the client/server analogue of the reachability gate). ---

# server-side classes that make no sense in the browser (xss + redirect DO occur client-side, so not here)
SERVER_ONLY_CLASSES = {"ssrf", "sqli", "nosqli", "cmd", "path", "deser"}
SERVER_ONLY_CWE = {"CWE-918", "CWE-89", "CWE-943", "CWE-78", "CWE-22", "CWE-502", "CWE-95"}

# browser-only globals -- their presence in the source is a reliable "this runs in a browser" signal (Node
# has no window/document/localStorage), and catches a plain .js util that no path/suffix rule would.
_BROWSER_SIGNAL = re.compile(r"\bwindow\.|\bdocument\.|\blocalStorage\b|\bsessionStorage\b|\bnavigator\.|"
                             r"import\.meta\.env|\baddEventListener\s*\(|\bdispatchEvent\s*\(")
_FRONTEND_IMPORT = re.compile(r"\b(react|next|vue|svelte|@angular|solid-js|preact|@remix-run|react-router)\b", re.I)
# only UNAMBIGUOUS frontend dirs -- "components"/"pages"/"views" also occur server-side (MVC templates),
# and misclassifying a backend file there would SUPPRESS a real vuln (the dangerous direction); the
# browser-global signal + JSX + framework-import catch real frontend robustly without them.
_FRONTEND_DIRS = {"frontend", "client", "public", "webapp", "www"}


def is_frontend(path, source="", imports=()):
    """Best-effort: does this file run in the BROWSER (not the server)? JSX suffix, a frontend directory, a
    frontend-framework import, or a browser-only global in the source. Python is virtually never frontend."""
    p = str(path).replace("\\", "/").lower()
    if p.rsplit(".", 1)[-1] in ("tsx", "jsx"):
        return True
    if p.endswith(".py"):                                   # server language -- never browser code
        return False
    if set(p.split("/")) & _FRONTEND_DIRS:
        return True
    if any(_FRONTEND_IMPORT.search(str(i)) for i in (imports or ())):
        return True
    return bool(source and _BROWSER_SIGNAL.search(source))

# decorator / name signals that a function receives external, attacker-controllable input DIRECTLY
_ROUTE_HINTS = ("route", ".get(", ".post(", ".put(", ".delete(", ".patch(", "app.", "router.", "blueprint",
                "@get", "@post", "@put", "@delete", "@patch", "endpoint", "api_route", "websocket", "on_event")
_ENTRY_NAMES = {"main", "handler", "handle", "lambda_handler", "handle_request", "on_message", "on_request"}


def is_untrusted_entry(func):
    """True if `func` takes external/attacker input directly: a decorated HTTP route, or a
    main/handler/consumer entry. (Merely being `exported` is NOT enough -- a library's public API is called
    by trusted code; that is exactly the eval-runner false positive.)"""
    decs = " ".join(getattr(func, "decorators", None) or []).lower()
    if any(h in decs for h in _ROUTE_HINTS):
        return True
    return (getattr(func, "name", "") or "").lower() in _ENTRY_NAMES


def reaches_untrusted_entry(cmap, sink_name, max_hops=12):
    """BFS BACKWARD over the call graph from `sink_name` to an untrusted-facing entry.
    Returns (entry_func, path) where path is [entry, ..., sink] names; or (None, None) if none is reached."""
    if not sink_name:
        return None, None
    for f in cmap.funcs.get(sink_name, []):                 # the sink function is itself an entry?
        if is_untrusted_entry(f):
            return f, [sink_name]
    seen = {sink_name}
    q = deque([[sink_name]])
    while q:
        path = q.popleft()
        if len(path) > max_hops:
            continue
        for caller in cmap.callers_of(path[0]):
            if caller in seen:
                continue
            seen.add(caller)
            for f in cmap.funcs.get(caller, []):
                if is_untrusted_entry(f):
                    return f, [caller] + path
            q.append([caller] + path)
    return None, None


def _ambiguous_names(cmap, path):
    """Names in the chain that are defined in MORE THAN ONE place -- a name-based call edge to such a name is
    a GUESS (the graph matched on name, not binding), e.g. `decode`/`load`/`run`. A chain that leans on one
    is low-confidence (open question 10.1: false name-based edges)."""
    return [n for n in path if len(cmap.funcs.get(n, [])) > 1]


def gate(cmap, sink_func_name):
    """Classify a proven sink by reachability. Returns (reachable: bool, confidence: str, note: str).
    confidence 'high' = a clean chain with no ambiguous (common-name) edges; 'low' = the ONLY path relies on
    an ambiguous name-based edge (likely a false chain -- caller of the intrinsic-sink bar in prove)."""
    entry, path = reaches_untrusted_entry(cmap, (sink_func_name or "").split("(")[0].strip())
    if entry is None:
        return False, "high", (
            "sink PROVEN to fire, but no path from an untrusted-facing entry (route / CLI / handler) reaches "
            "it -- may be internal/intended; needs human review (function-level, name-based)")
    ambig = _ambiguous_names(cmap, path)
    conf = "low" if ambig else "high"
    note = f"reachable from untrusted entry {entry.name} via {'->'.join(path)}"
    if conf == "low":
        note += (f"  [LOW confidence: {sorted(set(ambig))} is defined in multiple places -- this name-based "
                 f"call edge may be false (open Q 10.1)]")
    return True, conf, note
