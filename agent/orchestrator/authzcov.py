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
_AUTHN = re.compile(
    r"require[_ ]?auth|login_required|is_authenticated|isauthenticated|ensureloggedin|\bauthenticate\b"
    r"|authoriz|verify(token|jwt|auth|session)|getcurrentuser|current_user|\breq\.user\b|\brequest\.user\b"
    r"|@useguards|canactivate|\bdepends\s*\(|\bpermission|\bpolicy\b|\bcan\s*\(|forbidden|unauthorized"
    r"|abort\s*\(\s*40[13]|status\s*\(\s*40[13]|passport\.authenticate|checkauth|require[_ ]?user"
    r"|\bjwt\b|bearerauth|\bbearer\b|apikey|api_key|x-api-key|\bsession\b|\bprincipal\b|@requirerole"
    r"|@roles?\b|accesscontrol|getsession|assertauth", re.I)

# GLOBAL / app-wide auth application -- a guard that covers EVERY route (so no per-route check is needed).
_GLOBAL_AUTH = re.compile(
    r"useglobalguards\s*\(|app_guard"
    r"|app\.use\s*\([^)]*(auth|jwt|bearer|passport|session|guard|clerk|login)"
    r"|\.use\s*\(\s*(requireauth|authmiddleware|isauthenticated|bearerauth|jwt|passport|requireuser)\b"
    r"|fastapi\s*\([^)]*dependencies\s*=\s*\[[^\]]*depends"
    r"|add_middleware\s*\([^)]*auth"
    r"|@app\.before_request", re.I)


def _entry_authed(entry_fn, global_authed):
    """True if the route is guarded: a global auth layer covers it, OR an auth-ish signal appears in/around
    the handler. Reads a window around the handler's def; falls back to the whole file when the line is
    unknown (safe direction -- suppress rather than over-flag)."""
    if global_authed:
        return True
    f = getattr(entry_fn, "file", "") or ""
    try:
        lines = Path(f).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False
    ln = getattr(entry_fn, "line", None)
    end = getattr(entry_fn, "end", 0) or 0
    if isinstance(ln, int) and ln > 0:
        # the handler's OWN body only (decorators above through its last line) -- a WIDE window would let a
        # sibling handler's auth check bleed onto this one in a small file.
        last = end if end and end >= ln else ln + 25
        body = "\n".join(lines[max(0, ln - 4):last])
        return bool(_AUTHN.search(body))
    return bool(_AUTHN.search("\n".join(lines)))


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


def scan(target, cmap, per_file, max_leads=15):
    """Remote-reachable high-severity sinks whose route is NOT behind any auth guard. Returns finding dicts
    shaped like controls.scan's (control/severity/title/detail/fix/file/cwe), so they render in the same
    'Missing security controls' section. Pure except for reading source. Never raises on a bad cmap."""
    if cmap is None or per_file is None:
        return []
    try:
        global_authed = _global_authed(target)
    except Exception:
        global_authed = False

    best = {}        # (entry_file, entry_name) -> finding (keep the highest-severity sink as exemplar)
    for path, (_routes, sinks, _dyn) in per_file.items():
        if not sinks:
            continue
        dangerous = [(ln, str(lbl).lower(), code) for (ln, lbl, code) in sinks
                     if str(lbl).lower() in _DANGEROUS]
        if not dangerous:
            continue
        finfo = cmap.files.get(path)
        if finfo is None:
            continue
        for (ln, lbl, code) in dangerous:
            try:
                fn = repomap._enclosing(finfo, ln)
            except Exception:
                fn = None
            name = getattr(fn, "name", "") if fn else ""
            if not name:
                continue
            try:
                entry, chain, trust = reachability.reaches_untrusted_entry_bound(cmap, name, path)
            except Exception:
                entry, chain, trust = None, None, None
            if entry is None or trust != "remote":           # only remote-reachable routes qualify
                continue
            if _entry_authed(entry, global_authed):          # a guard covers it -> not a gap
                continue
            ekey = (getattr(entry, "file", ""), getattr(entry, "name", ""))
            sev = select._SEV.get(lbl, 1)
            prev = best.get(ekey)
            if prev is not None and prev["_sev"] >= sev:
                continue
            ename = getattr(entry, "name", "") or "<handler>"
            sink_loc = f"{Path(path).name}:{ln}"
            path_str = "->".join(chain) if chain else name
            best[ekey] = {
                "control": "unauth-exec", "severity": "high", "_sev": sev,
                "title": f"Remote route reaches a {lbl} sink with no authentication ({ename})",
                "detail": (
                    f"The route handler {ename} ({Path(getattr(entry, 'file', '') or path).name}) is "
                    f"remote-reachable and its call path reaches a high-severity {lbl} sink at {sink_loc} "
                    f"(via {path_str}), but NO authentication/authorization guard was found on that path. "
                    f"If the dangerous operation is INTENDED (e.g. a shell/exec endpoint), the absence of "
                    f"auth makes it attacker-invokable -- the CWE-306/862 shape, which injection detection "
                    f"does not flag. CAVEAT: if auth is enforced by a framework layer this scan does not "
                    f"recognize, disregard."),
                "file": getattr(entry, "file", "") or path, "cwe": "CWE-306",
                "fix": ("Require authentication/authorization on this route BEFORE the sensitive operation "
                        "(a middleware/guard or an inline check); do not rely on the operation being 'internal'.")}
    out = sorted(best.values(), key=lambda d: -d["_sev"])[:max_leads]
    for d in out:
        d.pop("_sev", None)
    return out
