"""Oracle layer — the deterministic verifier. Owns every verdict; the model never decides a verdict.

The model CRAFTS attack requests (exploit.craft_requests); the oracle fires them and PROVES via the
instrumented sink whether a payload reached it unneutralized. Also: differential (authz) and a benign
regression probe. Precision-first: only PROVEN hits become findings.
"""
import secrets
import time

from . import registry, exploit


def _sink_hit(rt, hook, marker):
    for line in rt.sink_lines(hook.marker):
        if registry.payload_in_sink(hook, line, marker):
            return line
    return None


def _any_sink_hit(rt, hooks, marker):
    for hook in hooks:
        hit = _sink_hit(rt, hook, marker)
        if hit:
            return hit
    return None


def prove_injection(rt, hooks, candidate, routes, model, strikes=1, auth=None):
    """Model crafts attack requests embedding a unique marker; fire them and check ANY of the app's
    instrumented sinks for that marker in an unsafe position. Trying all hooks (not one keyed on the
    model's fuzzy CWE label) makes proof robust to mis-classification. Verdict dict."""
    marker = "WZ" + secrets.token_hex(3)                   # unique per probe -> no cross-attribution
    for r in exploit.craft_requests(model, candidate, routes, marker):
        confirmations, evidence = 0, ""
        for _ in range(strikes):
            exploit.fire(rt.base_url, r["method"], r["path"], r["body"],
                         headers={**(auth or {}), **(r["headers"] or {})})
            hit = None
            for _ in range(8):                             # poll: container stdout -> docker logs lags
                hit = _any_sink_hit(rt, hooks, marker)
                if hit:
                    break
                time.sleep(0.4)
            if hit:
                confirmations += 1
                evidence = hit
        if confirmations == strikes and confirmations > 0:
            return {"status": "proven", "cwe": candidate.cwe, "payload": r["payload"],
                    "request": f"{r['method']} {r['path']}", "evidence": evidence.strip()[:200],
                    "oracle": "instrumented-sink", "proven_request": r}
    return {"status": "not-proven", "cwe": candidate.cwe,
            "notes": "no crafted payload observed unneutralized at the sink"}


def benign_status(rt, proven_request, auth=None):
    """Fire a benign version of the proven request; return the HTTP status (or None if unreachable).
    Used for the differential Gate-B baseline (original app) and the patched-app check."""
    if not proven_request:
        return None
    b = exploit.benignify(proven_request)
    status, _ = exploit.fire(rt.base_url, b["method"], b["path"], b["body"],
                             headers={**(auth or {}), **(b["headers"] or {})})
    return status


def differential(rt, request_fn, ctx_attacker, ctx_target):
    """Authorization oracle: attacker context yielding the target's protected state == breach."""
    sa, ta = request_fn(ctx_attacker)
    st, tt = request_fn(ctx_target)
    breach = sa == st and ta == tt and (sa == 200)
    return {"status": "proven" if breach else "cleared", "oracle": "differential",
            "evidence": f"attacker=={'target' if breach else 'denied'} (status {sa} vs {st})"}
