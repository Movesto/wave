"""Missing-control detection -- the ABSENCE of security code that should be present.

wave's other stages find dangerous code that EXISTS; this finds code that should exist and doesn't:
  - state-changing routes (POST/PUT/DELETE/PATCH) with no CSRF mechanism anywhere in the repo,
  - auth routes (login/token/password/...) with no rate limiting anywhere,
  - cookies set without the httpOnly / secure / sameSite flags.

Deterministic (no model), built on the codemap's route extraction. These are ADVISORIES (review-tier), not
tool-witnessed confirms -- absence is inherently context-dependent (a token-auth JSON API needs no CSRF; a
header may be set at the proxy), so each finding states its caveat and they are reported repo-level (not
per-route spam) to stay low-noise.
"""
from __future__ import annotations

import re
from pathlib import Path

from . import routes as _routes

_SKIP = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "vendor", "target", ".next"}
_CODE_EXTS = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".java", ".cs", ".rb", ".php", ".rs"}

_CSRF_SIGNS = ("csrf", "csurf", "xsrf", "anti-forgery", "antiforgery", "samesite")
_RATELIMIT_SIGNS = ("ratelimit", "rate_limit", "rate-limit", "flask_limiter", "flask-limiter", "slowapi",
                    "express-rate-limit", "expressrate", "throttle", "limiter", "@throttl", "bucket4j",
                    "rack-attack", "rack_attack")
_SESSION_COOKIE_SIGNS = ("session", "set_cookie", "set-cookie", "setcookie", ".cookie(", "httponly")
_AUTH_PATH = re.compile(r"login|signin|sign-in|logon|auth|token|password|passwd|register|signup|sign-up|otp|"
                        r"mfa|2fa|session|oauth|sso", re.I)
_COOKIE_SET = re.compile(r"set_cookie\s*\(|\.set_cookie\s*\(|res\.cookie\s*\(|response\.cookie\s*\(|"
                         r"\.cookies\.set\s*\(|new\s+Cookie\s*\(|Set-Cookie", re.I)

# ---- missing ownership/access check (IDOR comparison, sast-improvement plan 3) --------------------
# A handler that takes an id-like object parameter but -- unlike MOST id-handlers in the same repo --
# has no visible ownership/auth check is a likely broken-object-level-authorization (IDOR) gap. This is
# a COMPARISON: it flags the odd one out only when the repo's norm is to check, so a codebase that never
# checks anywhere isn't spammed per-route.
_ID_PARAM = re.compile(r"[:{]([A-Za-z_]\w*)\}?")
_ID_NAME = re.compile(r"(id$|(^|_)(id|user|account|owner|order|invoice|doc|file|record|key|uuid|slug))", re.I)
_OWNERSHIP = re.compile(
    r"user_id|current_user|currentuser|request\.user|req\.user|\bg\.user|get_?current_?user"
    r"|\bowner\b|owned_by|belongs_to|filter_by\s*\([^)]*user|\.where\s*\([^)]*user|\.filter\s*\([^)]*user"
    r"|require[_ ]?auth|login_required|authorize|authoriz|\bpolicy\b|permission|can\s*\("
    r"|forbidden|unauthorized|abort\s*\(\s*40[13]|raise\s+PermissionError|Depends\s*\(|scope_"
    r"|==\s*current_user|session\[", re.I)


def _has_ownership_guard(body):
    """True if the handler body (or its decorators) shows an ownership / access check. Pure."""
    return bool(_OWNERSHIP.search(body or ""))


def _func_body(path, func, span=45):
    """The handler's source window (a few lines before the def, for decorators, through ~span lines). Coarse."""
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if not func or func in ("<handler>", "<module>"):
        return "\n".join(lines[:span])
    pat = re.compile(r"\b" + re.escape(func) + r"\b\s*[\(=:]")
    for i, ln in enumerate(lines):
        if pat.search(ln):
            return "\n".join(lines[max(0, i - 3):i + span])
    return ""


def _id_handlers(target, routes, gm=None):
    """id-param route handlers + whether each shows an ownership guard (the IDOR surface). A handler counts
    as guarded if its own body checks ownership OR a framework-level scoping guard covers it (guardmap, #2) --
    the latter fixes the false IDOR lead on routes behind a global/class guard (e.g. NestJS APP_GUARD)."""
    out, seen = [], set()
    for r in routes:
        m = _ID_PARAM.search(r.path or "")
        if not (m and _ID_NAME.search(m.group(1))):
            continue
        key = (r.method, r.path, r.function)
        if key in seen:
            continue
        seen.add(key)
        framework = bool(gm and gm.covers_idor(r.file))
        out.append({"method": r.method, "path": r.path, "file": r.file, "function": r.function,
                    "has_guard": _has_ownership_guard(_func_body(r.file, r.function)) or framework,
                    "framework_guard": framework})
    return out


def _ownership_gaps(handlers, min_group=3, norm=0.6):
    """The handlers lacking a guard, flagged ONLY when the repo's norm is to check (>= `norm` of >= `min_group`
    id-handlers are guarded) -- the odd-one-out, not a codebase that never checks anywhere. Pure."""
    if len(handlers) < min_group:
        return []
    guarded = [h for h in handlers if h["has_guard"]]
    gaps = [h for h in handlers if not h["has_guard"]]
    if not guarded or len(guarded) < len(handlers) * norm:
        return []
    return gaps


def _code_files(target, cap=4000):
    p = Path(target)
    if p.is_file():
        if p.suffix.lower() in _CODE_EXTS:
            yield p
        return
    n = 0
    for f in p.rglob("*"):
        if n >= cap:
            return
        if f.suffix.lower() in _CODE_EXTS and not any(s in f.parts for s in _SKIP):
            n += 1
            yield f


def _present(target, patterns):
    """True if ANY code file contains ANY of `patterns` (case-insensitive). Short-circuits on first hit."""
    pats = tuple(p.lower() for p in patterns)
    for f in _code_files(target):
        try:
            t = f.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        if any(p in t for p in pats):
            return True
    return False


def _is_auth_route(r):
    return bool(_AUTH_PATH.search(r.path or "") or _AUTH_PATH.search(r.function or ""))


def _cookie_sites(target, cap=50):
    """Cookies set without httpOnly / secure / sameSite. Checks the set-cookie call line + a small window.
    Skips test/fixture files -- a cookie set inside a `.spec.ts` is test scaffolding, not a production
    control gap (these were ~3/4 of the cookie-flags noise on OpenWA)."""
    from .repomap import is_low_priority_path
    out = []
    for f in _code_files(target):
        if is_low_priority_path(str(f)):
            continue
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines):
            if not _COOKIE_SET.search(line):
                continue
            window = " ".join(lines[i:i + 3]).lower()            # multi-line cookie option objects
            missing = [flag for flag, key in (("httpOnly", "httponly"), ("secure", "secure"),
                                              ("sameSite", "samesite")) if key not in window]
            if missing:
                out.append({"file": str(f), "line": i + 1, "missing": missing,
                            "snippet": line.strip()[:120]})
            if len(out) >= cap:
                return out
    return out


def scan(target):
    """Deterministic missing-control advisories. Returns a list of finding dicts."""
    target = str(target)
    try:
        routes = _routes.extract_routes(target)
    except Exception:
        routes = []
    findings = []

    state_routes = [r for r in routes if (r.method or "").upper() in ("POST", "PUT", "DELETE", "PATCH", "ANY")]
    if state_routes and not _present(target, _CSRF_SIGNS):
        sample = ", ".join(f"{r.method} {r.path}" for r in state_routes[:5])
        findings.append({
            "control": "csrf", "severity": "medium",
            "title": "No CSRF protection found for state-changing routes",
            "detail": (f"{len(state_routes)} state-changing route(s) exist (e.g. {sample}) but no CSRF / "
                       f"anti-forgery / SameSite mechanism was found anywhere in the source. Real if the app "
                       f"uses COOKIE-based sessions (a token/bearer-auth API does not need CSRF)."),
            "fix": "Enable the framework's CSRF protection (or set SameSite=strict/lax on session cookies)."})

    auth_routes = [r for r in routes if _is_auth_route(r)]
    if auth_routes and not _present(target, _RATELIMIT_SIGNS):
        sample = ", ".join(f"{r.method} {r.path}" for r in auth_routes[:5])
        findings.append({
            "control": "rate-limit", "severity": "medium",
            "title": "No rate limiting found for authentication routes",
            "detail": (f"{len(auth_routes)} auth-related route(s) exist (e.g. {sample}) but no rate-limiting / "
                       f"throttling mechanism was found anywhere in the source -- brute-force / credential-"
                       f"stuffing exposure."),
            "fix": "Add per-IP/per-account rate limiting on login, token, and password-reset routes."})

    try:
        from . import guardmap
        gm = guardmap.build(target)
    except Exception:
        gm = None
    for h in _ownership_gaps(_id_handlers(target, routes, gm=gm)):
        findings.append({
            "control": "authz", "severity": "high",
            "title": f"No ownership/access check on {h['method']} {h['path']}",
            "detail": (f"{h['function'] or '<handler>'} ({Path(h['file']).name}) takes an id-like parameter "
                       f"but -- unlike most id-handlers in this repo -- shows no visible ownership/auth check "
                       f"(user-id scoping, current-user compare, authorize/403). Possible IDOR / broken "
                       f"object-level authorization; confirm whether the caller may access the object."),
            "file": h["file"], "cwe": "CWE-639",
            "fix": "Verify the authenticated caller owns or may access the object BEFORE returning/mutating it."})

    for c in _cookie_sites(target):
        findings.append({
            "control": "cookie-flags", "severity": "low",
            "title": f"Cookie set without {', '.join(c['missing'])}",
            "detail": f"{Path(c['file']).name}:{c['line']} -- {c['snippet']}",
            "file": c["file"], "line": c["line"], "missing": c["missing"],
            "fix": "Set httpOnly (block JS access), secure (HTTPS-only), and sameSite (CSRF defense) on cookies."})

    return findings


def render(findings):
    """Markdown section for the report."""
    if not findings:
        return "## Missing security controls\n\nNo missing-control advisories.\n"
    lines = [f"## Missing security controls  ({len(findings)})", "",
             "The ABSENCE of expected security code (advisory / review-tier, not tool-witnessed). "
             "Each notes its caveat.", ""]
    for f in findings:
        lines.append(f"- **[{f['control']}]** {f['title']}  _[{f['severity']}]_")
        lines.append(f"  - {f['detail']}")
        lines.append(f"  - fix: {f['fix']}")
    return "\n".join(lines) + "\n"
