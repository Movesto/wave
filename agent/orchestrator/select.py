"""Surface selection -- WHICH files the model deep-reads / the detector proves, and in what order.

The pins (repomap) say a file *contains* a route or a sink-shaped line. That is "looks exploitable", and on
a real repo it over-weights test/fixture files (they are full of `fetch`/`eval`/hardcoded-key fixtures) and
under-weights the real backend. This module re-ranks the pinned set by REACHABILITY -- a file matters to the
degree untrusted input can actually reach a sink in it -- and, on the PARTIAL-scan depths, drops the
low-priority (test/fixture/infra) files that are not the attack surface (they are covered by --all-files).

Two signals the pin-density order misses:
  * a file is an untrusted ENTRY if it has a route decorator OR its (server-side) code reads a request object
    directly (`req.url`, `searchParams`, `request.args`, ...). Modern JS apps register handlers with no
    decorator (`middlewares.use('/x', (req,res)=>...)`), so decorator-only entry detection misses the real
    surface -- the direct-request-access signal catches it. (gods-eye-view: 97 provider handlers, 0 decorated.)
  * a sink is high-priority when the call graph reaches it from an untrusted entry in few hops
    (reachability.reaches_untrusted_entry_bound), low when no entry reaches it (it would be gated at prove).

Fail-safe (mirrors reachability.py): the dangerous direction is SUPPRESSING a real bug, so a non-low-priority
server file is NEVER dropped on uncertainty -- only ranked lower. Only test/fixture/infra files are dropped,
and only on a partial scan.
"""
from __future__ import annotations

import re
from pathlib import Path

from . import reachability, repomap

# A function that reads an HTTP/request object DIRECTLY is an untrusted entry even with no route decorator.
# Server-side only -- a browser `new URL()`/`searchParams` is not an entry (gated by is_frontend below).
_REQUEST_ACCESS_RE = re.compile(
    r"\breq\.(url|query|params|body|headers|cookies|rawHeaders|path)\b"                 # express/connect/node http
    r"|\brequest\.(url|query|params|body|headers|cookies|args|form|json|values|data|GET|POST)\b"  # flask/django/fastapi
    r"|\.searchParams\b|new\s+URL\s*\(\s*req|new\s+URL\s*\(\s*request"                   # WHATWG URL from a request
    r"|\bctx\.(request|query|params)\b|\bc\.(Query|Param|FormValue|PostForm)\s*\("        # koa / gin / echo
    r"|\bevent\.(queryStringParameters|body|pathParameters|headers|rawQueryString)\b"     # aws lambda proxy event
    r"|\bHttpServletRequest\b|request\.getParameter\s*\("                                 # java servlet
    r"|\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b"                                        # php superglobals
    r"|\br\.URL\.Query\s*\(|\br\.FormValue\s*\(|mux\.Vars\s*\(",                           # go net/http + gorilla
    re.I)

# Sink-class severity (higher = prove first). Mirrors the detector's ordering intent; a local copy so this
# module does not import the heavier detector. Unknown class -> 1.
_SEV = {"cmd": 6, "eval": 6, "sqli": 6, "deser": 6,
        "ssrf": 5, "path": 5, "ssti": 5, "nosqli": 5, "authz": 5, "idor": 5, "access": 5, "bola": 5,
        "protopollution": 4, "xss": 4, "redirect": 4,
        "redos": 3, "memory": 3, "format": 3}


def reads_request(source):
    """Does this source read an HTTP request object directly (an undecorated untrusted entry)?"""
    return bool(source and _REQUEST_ACCESS_RE.search(source))


def _read_source(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _sink_fn_names(cmap, per_file, path):
    """The enclosing function name of each sink pinned in `path` -- the start node for reachability."""
    finfo = cmap.files.get(path)
    if finfo is None:
        return []
    _routes, sinks, _dyn = per_file.get(path, ([], [], []))
    names = []
    for (ln, _label, _code) in sinks:
        try:
            fn = repomap._enclosing(finfo, ln)
        except Exception:
            fn = None
        if fn is not None and getattr(fn, "name", ""):
            names.append(fn.name)
    return names


def file_priority(cmap, per_file, path, source=None):
    """Return (priority_tuple, signals). Higher tuple = read/prove first. `signals` carries the booleans the
    caller uses for the drop decision. All signals come from existing machinery (routes, reachability)."""
    finfo = cmap.files.get(path)
    imports = getattr(finfo, "imports", ()) if finfo is not None else ()
    if source is None:
        source = _read_source(path)
    frontend = reachability.is_frontend(path, source, imports)
    routes, sinks, _dyn = per_file.get(path, ([], [], []))
    has_route = bool(routes)
    req_entry = (not frontend) and reads_request(source)
    entry_bearing = has_route or req_entry
    has_sink = bool(sinks)

    reaches_remote = reaches_any = False
    for fn in _sink_fn_names(cmap, per_file, path):
        try:
            entry, _p, trust = reachability.reaches_untrusted_entry_bound(cmap, fn, path)
        except Exception:
            entry, trust = None, None
        if entry is not None:
            reaches_any = True
            if trust == "remote":
                reaches_remote = True
            if reaches_remote:
                break

    sev = max((_SEV.get(str(lbl).lower(), 1) for (_l, lbl, _c) in sinks), default=0)
    lowpri = repomap.is_low_priority_path(path)

    prio = (
        1 if (entry_bearing and has_sink) else 0,   # an entry file WITH a sink = the real surface
        1 if reaches_remote else 0,                 # a sink the call graph reaches from a REMOTE entry
        1 if reaches_any else 0,                    # ... or any (local) entry
        1 if entry_bearing else 0,                  # an entry file (even if its sink is elsewhere)
        0 if frontend else 1,                       # server code above browser code (server-only sinks)
        sev,                                        # sink severity
        0 if lowpri else 1,                         # infra/test last
    )
    signals = {"has_route": has_route, "req_entry": req_entry, "entry_bearing": entry_bearing,
               "has_sink": has_sink, "frontend": frontend, "lowpri": lowpri,
               "reaches_remote": reaches_remote, "reaches_any": reaches_any}
    return prio, signals


def partition_surface(cmap, per_file, files, partial=True):
    """Rank `files` by reachability priority (highest first). On a PARTIAL scan, drop the low-priority
    (test/fixture/infra) files -- they are not the attack surface and belong to --all-files. A file that
    defines a real ROUTE is never dropped (safety). Returns (kept_ranked, dropped)."""
    scored, dropped = [], []
    for p in files:
        src = _read_source(p)
        prio, sig = file_priority(cmap, per_file, p, src)
        if partial and sig["lowpri"] and not sig["has_route"]:
            dropped.append(p)
            continue
        scored.append((prio, p))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [p for _prio, p in scored], dropped
