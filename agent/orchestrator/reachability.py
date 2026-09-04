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
from collections import deque

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


def gate(cmap, sink_func_name):
    """Classify a proven sink by reachability. Returns (reachable: bool, note: str)."""
    entry, path = reaches_untrusted_entry(cmap, (sink_func_name or "").split("(")[0].strip())
    if entry is not None:
        return True, f"reachable from untrusted entry {entry.name} via {'->'.join(path)}"
    return False, ("sink PROVEN to fire, but no path from an untrusted-facing entry (route / CLI / handler) "
                   "reaches it -- may be internal/intended; needs human review (function-level, name-based)")
