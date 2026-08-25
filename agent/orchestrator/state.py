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
from . import registry, oracle, remediate
from . import auth as auth_mod
from .models import Finding


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
    findings, deferred = [], []
    try:
        for c in provable:
            if not hook_list:
                deferred.append((c, "no instrumented sink hook for this app's drivers"))
                continue
            v = oracle.prove_injection(rt, hook_list, c, routes, model, strikes=strikes, auth=auth)
            if v.get("status") == "proven":
                f = Finding(candidate=c, status="proven", evidence=v["evidence"], payload=v["payload"],
                            proven_request=v["proven_request"], notes=f"{v['oracle']} via {v['request']}")
                f.baseline_status = oracle.benign_status(rt, f.proven_request, auth=auth)
                findings.append(f)
            else:
                deferred.append((c, v.get("notes", "not proven at sink")))
    finally:
        rt.down()                      # free the port before the patch phase re-provisions

    if fix and findings:
        for f in findings:
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
