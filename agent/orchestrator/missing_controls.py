"""Missing-controls oracle -- the 'negative space' intuition (§18 #2), built as TESTS, not prompts.

A senior pentester asks not just 'is this code vulnerable' but 'what control is MISSING' -- no rate
limit on login, no old-password check on reset, no session invalidation. These have no sink; they are
proven BEHAVIORALLY. First control: brute-force / rate limiting (CWE-307) -- fire N rapid requests at
a credential-sensitive route; if nothing throttles (429/423/lockout), the control is missing.

Soundness note (like IDOR, §5.2): the behavior is deterministic, but 'this route SHOULD be rate-
limited' is a judgment -> findings are flagged 'control-judgment: needs confirm' (not pure Tier-1).
"""
import re

from . import exploit
from .models import Candidate

_SENSITIVE = re.compile(
    r"login|signin|log-in|auth|token|otp|reset|forgot|register|signup|sign-up|password|verify|2fa|mfa",
    re.I)


def sensitive_routes(routes):
    """POST/PUT routes whose path suggests a credential-sensitive action (rate-limit candidates)."""
    seen, out = set(), []
    for r in routes:
        if r.method in ("POST", "PUT") and _SENSITIVE.search(r.path) and r.path not in seen:
            seen.add(r.path)
            out.append(r)
    return out


def prove_no_ratelimit(rt, route, auth=None, n=18):
    """Fire n rapid requests; if NONE are throttled (429/423, or a lockout 403 after a few) and the
    endpoint keeps responding, brute-force protection is missing. A throttle at any point -> defer."""
    body = {"username": "wavebrute", "password": "x"}     # handlers ignore extra fields
    statuses = []
    for i in range(n):
        st, _ = exploit.fire(rt.base_url, route.method, route.path, body, headers=dict(auth or {}))
        statuses.append(st)
        if st in (429, 423) or (st == 403 and i > 3):     # throttled / locked out -> protected
            return {"status": "not-proven", "cwe": "CWE-307",
                    "notes": f"throttled after {i + 1} requests (status {st}) -- rate limit present"}
    return {"status": "proven", "cwe": "CWE-307", "oracle": "behavioral",
            "payload": f"{n} rapid requests", "request": f"{route.method} {route.path}",
            "evidence": (f"{n} rapid requests to {route.path} all accepted (statuses "
                         f"{statuses[:6]}...) -- no rate limit / brute-force protection")}


def candidate_for(route):
    return Candidate(file=route.file, unit=route.function or "<handler>", line=0, cwe="CWE-307",
                     family="missing rate limiting / brute-force protection", detector="behavioral",
                     sink=f"{route.method} {route.path}", provable=True, rank=40,
                     route_hint=f"{route.method} {route.path}")
