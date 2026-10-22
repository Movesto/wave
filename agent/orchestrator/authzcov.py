"""Reach x guard composition -- the UNAUTHENTICATED dangerous sink (CWE-306 / CWE-862).

Injection detection asks "does tainted input reach a dangerous call?". It structurally CANNOT ask the
question that makes an *intended-exec* endpoint a CVE: "is that route guarded by any authentication?".
Absence of a control has no sink to pin -- that is why the access-control family (authz/idor/access/bola)
lives only in the behavioral/advisory tiers (see controls.py, idor.py), never as a tier-1 source pin.

BUT when a remote route REACHES a high-severity sink (cmd/deser/sqli/path/ssrf/...), the reachable sink
supplies the very signal an authz check normally has to GUESS: this path MUST be guarded. So here the
absence becomes safely raisable -- a remote-reachable sev>=5 sink whose route->sink path crosses NO
authentication/authorization guard is a real needs-review lead (the opencode `/session/:id/shell` ->
`spawn` shape: wave pinned the cmd sink and reached it, but never said "...and nothing authenticated it").

This composes two things wave ALREADY computes -- reachability (route->sink) and guard detection -- in the
RAISING direction (guardmap only ever CLEARED false IDOR leads). Conservative + caveated by design:
NEEDS-REVIEW, never a confirm; fires only on remote + sev>=5; one lead per entry; and each finding states
that an auth layer a framework-unaware scan cannot see would void it. The SAFE direction here is to STAY
SILENT, so the "is this route authed?" test is deliberately generous (any auth-ish signal clears it).
"""
from __future__ import annotations

import re
from pathlib import Path

from . import reachability, repomap, select

# High-severity SERVER-ONLY injection sinks where "this route has no auth" is a meaningful finding. The
# access-control classes themselves (authz/idor/access/bola) are NOT here -- they are not sinks you reach.
_DANGEROUS = {"cmd", "eval", "deser", "sqli", "nosqli", "ssti", "codegen", "path", "ssrf", "xxe", "ldap", "xpath"}

# A function body / decorators that AUTHENTICATE or AUTHORIZE the caller. Generous on purpose: matching here
# SUPPRESSES a finding, which is the safe direction, so we would rather miss a gap than cry wolf on a guarded
# route. Covers Nest/Express/FastAPI/Flask/Django/passport/Hono-ish idioms.
# Kept STRONG only: weak tokens like a bare `session` (session IDs are everywhere -- `sessionID`,
# `SessionPrompt`) wrongly suppressed the real opencode shell route, so they are excluded.
_AUTHN = re.compile(
    r"require[_ ]?auth|login_required|is_authenticated|isauthenticated|ensureloggedin|\bauthenticate\b"
    r"|authoriz|verify(token|jwt|auth)|getcurrentuser|current_user|\breq\.user\b|\brequest\.user\b"
    r"|@useguards|canactivate|\bdepends\s*\(|\bpermission|\bpolicy\b|\bcan\s*\(|forbidden|unauthorized"
    r"|abort\s*\(\s*40[13]|status\s*\(\s*40[13]|passport\.authenticate|checkauth|require[_ ]?user"
    r"|\bjwt\b|bearerauth|\bbearer\b|apikey|api_key|x-api-key|@requirerole|@roles?\b|accesscontrol"
    r"|assertauth|ensureauth|verifyauth", re.I)

# HTTP route signals ONLY -- a classic web route that an auth middleware/guard would protect. Deliberately
# NARROWER than reachability._ROUTE_HINTS, which also tags event-bus/queue/socket/GraphQL handlers (the
# `wave:event-handler` tag) as untrusted entries: those are not HTTP routes, and flagging opencode's event
# handlers for "missing auth" was noise (the uninstall.ts/spawn.ts false-positives).
_HTTP_ROUTE_HINTS = ("route", ".get(", ".post(", ".put(", ".delete(", ".patch(", "@get", "@post", "@put",
                     "@delete", "@patch", "endpoint", "api_route", "blueprint", "requestmapping",
                     "getmapping", "postmapping", "putmapping", "deletemapping", "patchmapping",
                     "[httpget", "[httppost", "[httpput", "[httpdelete", "[httppatch", "[route(",
                     "#[get", "#[post", "#[put", "#[delete", "#[patch", "#[route")

# GLOBAL / app-wide auth application -- a guard that covers EVERY route (so no per-route check is needed).
_GLOBAL_AUTH = re.compile(
    r"useglobalguards\s*\(|app_guard"
    r"|app\.use\s*\([^)]*(auth|jwt|bearer|passport|session|guard|clerk|login)"
    r"|\.use\s*\(\s*(requireauth|authmiddleware|isauthenticated|bearerauth|jwt|passport|requireuser)\b"
    r"|fastapi\s*\([^)]*dependencies\s*=\s*\[[^\]]*depends"
    r"|add_middleware\s*\([^)]*auth"
    r"|@app\.before_request", re.I)


def _is_web_route_entry(fn):
    """A STRICT 'this is an HTTP route' test: a route-decorator, an HTTP-method export (App-Router/SvelteKit
    GET/POST...), or an exported framework entry (loader/action/getServerSideProps). Deliberately EXCLUDES
    the generic remote NAMES reachability also trusts (handler/handle/on_message/...), because a CLI tool's
    yargs `handler` is NOT a web route -- trusting it was the uninstall.ts/spawn.ts false-positive."""
    decs = " ".join(getattr(fn, "decorators", None) or []).lower()
    if any(h in decs for h in _HTTP_ROUTE_HINTS):
        return True
    raw = getattr(fn, "name", "") or ""
    if raw in reachability._HTTP_METHOD_EXPORTS:
        return True
    return bool(getattr(fn, "exported", False) and raw in reachability._FRAMEWORK_ENTRY_EXPORTS)


def _authed_window(lines, lo, hi, global_authed):
    """True if a guard covers this span: a global auth layer, or an auth-ish signal within [lo, hi)."""
    if global_authed:
        return True
    return bool(_AUTHN.search("\n".join(lines[max(0, lo):hi])))


def _read(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _lines(path):
    return _read(path).splitlines()


def _handler_authed(entry_fn, global_authed):
    """A NAMED handler is guarded if a global layer covers it or its OWN body shows an auth check. Scoped to
    the handler's body (line..end) so a sibling handler's check can't bleed onto it."""
    lines = _lines(getattr(entry_fn, "file", "") or "")
    if not lines:
        return global_authed
    ln = getattr(entry_fn, "line", None)
    end = getattr(entry_fn, "end", 0) or 0
    if isinstance(ln, int) and ln > 0:
        last = end if end and end >= ln else ln + 25
        return _authed_window(lines, ln - 4, last, global_authed)
    return _authed_window(lines, 0, len(lines), global_authed)


def _global_authed(target):
    """Does the repo apply an authentication guard app-wide? Short-circuits on the first hit."""
    try:
        from . import controls
        for f in controls._code_files(target):
            try:
                t = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if _GLOBAL_AUTH.search(t):
                return True
    except Exception:
        pass
    return False


def _server_endpoint_file(path, per_file_entry, source):
    """True if this file is an HTTP endpoint surface -- it declares routes, or its (server-side) code reads a
    request object directly. The anchor for inline route callbacks the codemap can't name as functions."""
    routes = per_file_entry[0] if per_file_entry else []
    if routes:
        return True
    if reachability.is_frontend(path, source):
        return False
    return select.reads_request(source)


def _mk(sev, lbl, ename, efile, sink_loc, path_str, inline):
    how = (f"an inline route handler in {Path(efile).name}" if inline
           else f"the route handler {ename} ({Path(efile).name})")
    chain = f" (via {path_str})" if path_str else ""
    return {
        "control": "unauth-exec", "severity": "high", "_sev": sev,
        "title": (f"Remote route reaches a {lbl} sink with no authentication "
                  f"({'inline @ ' + sink_loc if inline else ename})"),
        "detail": (
            f"{how[0].upper()}{how[1:]} is remote-reachable and reaches a high-severity {lbl} sink at "
            f"{sink_loc}{chain}, but NO authentication/authorization guard was found on that route. If the "
            f"dangerous operation is INTENDED (e.g. a shell/exec endpoint), the absence of auth makes it "
            f"attacker-invokable -- the CWE-306/862 shape, which injection detection does not flag. CAVEAT: "
            f"if auth is enforced by a framework layer this scan does not recognize, disregard."),
        "file": efile, "cwe": "CWE-306",
        "fix": ("Require authentication/authorization on this route BEFORE the sensitive operation "
                "(a middleware/guard or an inline check); do not rely on the operation being 'internal'.")}


def scan(target, cmap, per_file, max_leads=15, per_file_cap=2):
    """High-severity sinks on an UNAUTHENTICATED remote route. Two anchors, because route handlers come in
    two shapes: (A) a NAMED handler -> walk the call graph back to it (catches cross-file sinks, Flask/Nest/
    FastAPI); (B) an INLINE route callback the codemap can't name as a function (the Hono/opencode shell
    route: the sink's enclosing fn is None) -> anchor on the sink being pinned in a SERVER-ENDPOINT file.
    Returns controls-shaped finding dicts. Pure except for reading source; never raises on a bad cmap."""
    if cmap is None or per_file is None:
        return []
    try:
        global_authed = _global_authed(target)
    except Exception:
        global_authed = False

    best = {}        # dedup key -> finding (keep the highest-severity sink as exemplar)
    per_file_count = {}

    def consider(key, finding):
        f = finding["file"]
        prev = best.get(key)
        if prev is not None and prev["_sev"] >= finding["_sev"]:
            return
        if prev is None and per_file_count.get(f, 0) >= per_file_cap:
            return
        if prev is None:
            per_file_count[f] = per_file_count.get(f, 0) + 1
        best[key] = finding

    for path, entry_pf in per_file.items():
        sinks = entry_pf[1] if entry_pf else []
        dangerous = [(ln, str(lbl).lower()) for (ln, lbl, _c) in sinks if str(lbl).lower() in _DANGEROUS]
        if not dangerous:
            continue
        finfo = cmap.files.get(path)
        if finfo is None:
            continue
        source = _read(path)
        is_server_file = _server_endpoint_file(path, entry_pf, source)
        lines = source.splitlines()
        for (ln, lbl) in dangerous:
            sev = select._SEV.get(lbl, 1)
            sink_loc = f"{Path(path).name}:{ln}"
            try:
                fn = repomap._enclosing(finfo, ln)
            except Exception:
                fn = None
            name = getattr(fn, "name", "") if fn else ""

            # (A) named handler: backward reach to a genuine WEB-ROUTE entry (not a CLI handler name)
            handled = False
            if name:
                try:
                    entry, chain, _t = reachability.reaches_untrusted_entry_bound(cmap, name, path)
                except Exception:
                    entry, chain = None, None
                if entry is not None and _is_web_route_entry(entry) and not _handler_authed(entry, global_authed):
                    ename = getattr(entry, "name", "") or "<handler>"
                    consider((getattr(entry, "file", ""), ename),
                             _mk(sev, lbl, ename, getattr(entry, "file", "") or path, sink_loc,
                                 "->".join(chain) if chain else name, inline=False))
                    handled = True

            # (B) inline route callback (no nameable enclosing fn) pinned in a server-endpoint file
            if not handled and is_server_file:
                # look just ABOVE the sink for the route callback + any inline guard
                if _authed_window(lines, ln - 30, ln + 4, global_authed):
                    continue
                consider((path, f"inline:{ln}"),
                         _mk(sev, lbl, "<inline>", path, sink_loc, "", inline=True))

    out = sorted(best.values(), key=lambda d: -d["_sev"])[:max_leads]
    for d in out:
        d.pop("_sev", None)
    return out
