"""State machine — the serialized loop that ties the stages together.

v0.1: the deterministic DETECT->PROVE loop (discover -> provision -> exploit -> oracle) with a
DEFER ledger. The model-driven halves (auth synthesis, patch + dual-gate) attach at the marked
points as remediate.py / model.py land. Precision-first: only oracle-PROVEN candidates become
findings; provable candidates the oracle can't confirm are DEFERRED with a reason.
"""
from dataclasses import asdict

from . import discover as disc
from . import provision as prov
from . import routes as routes_mod
from . import registry, oracle, remediate, idor, exploit, dom_oracle, oast, missing_controls, behavioral
from . import auth as auth_mod
from .models import Finding


def _prove_xss(rt, c, routes, model, auth):
    """XSS has no backend sink -- the model crafts an executing payload and the headless-browser DOM
    oracle witnesses it run (mere reflection is not proven). Reflected XSS via the crafted request URL."""
    import secrets
    marker = "WZ" + secrets.token_hex(3)
    for r in exploit.craft_requests(model, c, routes, marker):
        url = rt.base_url.rstrip("/") + "/" + r["path"].lstrip("/")
        v = dom_oracle.prove_xss(url, {**(auth or {}), **(r["headers"] or {})}, marker)
        if v.get("status") == "proven":
            v["proven_request"], v["request"], v["payload"] = r, f"{r['method']} {r['path']}", r["payload"]
            return v
    return {"status": "not-proven", "cwe": "CWE-79", "notes": "no crafted XSS executed in the DOM"}


def run_loop(target, host_port=None, strikes=1, fix=False, model_discover=False):
    """Full loop on `target`: discover -> provision -> (MODEL crafts exploits) prove, then (if fix)
    patch + dual-gate. The model drives exploitation and remediation; tools prove. Returns a dict.

    Discovery is a HINT only (P4): deterministic by default (reliable); `model_discover=True` uses
    the fast review model. Either way the oracle is what proves a candidate, so a missed/over-eager
    candidate costs recall, never a false result."""
    from .model import Model
    routes = routes_mod.extract_routes(target)
    cands = disc.discover(target, model_driven=model_discover)
    provable = [c for c in cands if c.provable]

    rt = prov.provision(target, host_port=host_port)
    hook_list = registry.select(rt.profile.deps_text, rt.profile.lang)   # the app's instrumented sinks
    auth = auth_mod.synthesize(rt, routes)                 # session for routes behind login (or {})
    if auth:
        print(f"[auth] synthesized session ({list(auth)[0]})", flush=True)
    model = Model()                                        # 14B: crafts exploits + patches
    canary = oast.Canary().start()                         # OAST: async/blind egress witness
    findings, deferred, pending_oast = [], [], []
    try:
        for c in provable:
            if c.cwe == "CWE-79":                          # XSS -> DOM oracle (headless browser)
                v = _prove_xss(rt, c, routes, model, auth)
            elif c.cwe == "CWE-1333":                      # ReDoS -> behavioral timing oracle
                v = behavioral.prove_redos(rt, c, auth)
            elif not hook_list:
                deferred.append((c, "no instrumented sink hook for this app's drivers"))
                continue
            else:
                v = oracle.prove_injection(rt, hook_list, c, routes, model, strikes=strikes,
                                           auth=auth, canary=canary)
            if v.get("status") == "proven":
                f = Finding(candidate=c, status="proven", evidence=v["evidence"], payload=v.get("payload", ""),
                            proven_request=v.get("proven_request"),
                            notes=f"{v.get('oracle', '')} via {v.get('request', '')}")
                if v.get("proven_request"):
                    f.baseline_status = oracle.benign_status(rt, f.proven_request, auth=auth)
                findings.append(f)
            else:
                deferred.append((c, v.get("notes", "not proven at sink")))
                if v.get("marker"):
                    pending_oast.append((v["marker"], c))  # sweep for a LATE callback (async/2nd-order)

        # --- IDOR / authorization (differential oracle; model judges which id-routes are private) ---
        idor_routes = idor.flag_owned(model, idor.id_param_routes(routes))
        attackers = auth_mod.synthesize_multi(rt, routes, 2)      # >=1 authenticated attacker
        atk = attackers[0]["auth"] if attackers else auth
        for route in idor_routes:
            c = idor.candidate_for(route)
            v = idor.prove_idor(rt, route, atk)
            if v.get("status") == "proven":
                findings.append(Finding(candidate=c, status="proven", evidence=v["evidence"],
                                        payload=v["payload"], proven_request=None,
                                        notes=f"{v['oracle']} via {v['request']} [owner-judgment: needs confirm]"))
            else:
                deferred.append((c, v.get("notes", "idor not proven")))

        # --- Missing controls (behavioral; §18 #2): rate limiting on credential-sensitive routes ---
        for route in missing_controls.sensitive_routes(routes):
            c = missing_controls.candidate_for(route)
            v = missing_controls.prove_no_ratelimit(rt, route, auth)
            if v.get("status") == "proven":
                findings.append(Finding(candidate=c, status="proven", evidence=v["evidence"],
                                        payload=v["payload"], proven_request=None,
                                        notes=f"{v['oracle']} via {v['request']} [control-judgment: needs confirm]"))
            else:
                deferred.append((c, v.get("notes", "control present")))

        # --- OAST async sweep: a callback that arrived AFTER the synchronous proving window (a
        # second-order payload / a delayed worker egress) -- exactly what the sync sink poll misses. ---
        for mk, c in pending_oast:
            late = canary.hit(mk, wait=6)
            if late:
                findings.append(Finding(candidate=c, status="proven",
                    evidence=f"delayed OAST callback at {late[0]['path']} from {late[0]['client']}",
                    payload=mk, notes=f"OAST-canary (async) via {c.route_hint or c.loc()}"))
                deferred[:] = [(dc, r) for (dc, r) in deferred if dc is not c]
    finally:
        canary.stop()
        rt.down()                      # free the port before the patch phase re-provisions

    if fix and findings:
        for f in findings:
            if f.candidate.detector in ("differential", "behavioral") or f.candidate.cwe in ("CWE-79", "CWE-1333"):
                f.status = "proven (fix-deferred)"          # IDOR / rate-limit / XSS / ReDoS fixes not automated
                continue
            r = remediate.remediate(target, f.candidate, f, model, routes, hook_list, host_port=host_port)
            f.patch = r.get("patch", "")
            f.gate_a = r.get("gate_a", "")
            f.gate_b = r.get("gate_b", "")
            f.status = "fixed" if r.get("status") == "fixed" else "proven (" + r.get("status", "?") + ")"
    model.unload()

    return {
        "findings": findings,
        "deferred": deferred,
        "summary": {"candidates": len(cands), "provable": len(provable),
                    "proven": len(findings), "deferred": len(deferred),
                    "fixed": sum(1 for f in findings if f.status == "fixed")},
    }
