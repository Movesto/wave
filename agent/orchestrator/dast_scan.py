"""Black-box DAST driver -- the live-URL loop: recon -> auth -> (injection | differential) -> report.

Pure black-box (agent/docs/dast_blackbox_plan.md): input is a URL, never source. The loop assembles the
already-black-box stages against a dast.Target stand-in and runs, per class, the oracle that can
witness it from the client:

  INJECTION (sink effect)      sqli / xss / path / redirect -> response-differential or DOM execution
  OUT-OF-BAND (blind effect)   ssrf / blind-RCE             -> an OAST callback to our canary
  JUDGMENT (differential)      idor / authz / rate-limit / old-password -> an observed behavioral
                               differential (two identities, or auth-vs-unauth) -> anomalous_state

Verdict tiers match recorder.py: a tool-witnessed injection / OAST callback is `confirmed`; a
behavioral differential (IDOR/authz/missing-control) is `anomalous_state` -- a real observed effect
whose *severity* is a judgment no tool settles automatically. The default loop is deterministic (no
model); the model is an optional hint, never the authority (the oracle owns `confirmed`).
"""
from __future__ import annotations

from . import auth as authmod
from . import browser_recon
from . import dast as dastmod
from . import dast_oracle
from . import idor as idormod
from . import missing_controls as mc
from . import oast as oastmod
from . import routes as routes_mod
from .recorder import CaseFile

# client-only injection classes (+ out-of-band ssrf/cmd, which self-skip without a canary).
INJECTION_BATTERY = ("sqli", "xss", "path", "ssti", "eval", "nosqli", "redirect", "ssrf", "cmd")

# param-NAME gates: these classes are only worth probing on a param whose name hints the sink, which
# keeps a live scan fast and precise (the oracle is still the authority; this just bounds the fan-out).
_REDIRECTY = ("redirect", "url", "next", "return", "returnurl", "dest", "destination", "continue", "goto")
_SSRFY = ("url", "uri", "link", "callback", "webhook", "target", "dest", "fetch", "host", "domain",
          "img", "image", "src", "feed", "proxy", "endpoint", "avatar", "site", "load", "page")
_CMDY = ("cmd", "command", "exec", "run", "ping", "host", "ip", "domain", "dns", "lookup", "shell",
         "action", "task", "job", "proc", "query")
_NAME_GATED = {"redirect": _REDIRECTY, "ssrf": _SSRFY, "cmd": _CMDY}


def _vector_for(method):
    """GET/DELETE carry input in the query string; POST/PUT/PATCH in the body."""
    return "query" if str(method).upper() in ("GET", "DELETE") else "body"


def targets_from_surface(recon, seed_targets=()):
    """The (method, route, vector, param) tuples to probe, from crawled FORMS (+ explicit seeds).

    Each form field is an input the server reads -> a candidate injection point. Links give routes but
    browser_recon drops their query string, so a link without a known param yields nothing to inject
    (recall is response-shaped -- stated in the plan; query-param discovery is a later recon upgrade).
    `seed_targets` lets a caller inject known (method, route, vector, param) tuples. Deduped, ordered."""
    out, seen = [], set()

    def add(method, route, vector, param):
        if not (route and param):
            return
        key = (str(method).upper(), route, vector, param)
        if key not in seen:
            seen.add(key)
            out.append(key)

    for f in (recon or {}).get("forms", []):
        method = f.get("method", "GET")
        vector = _vector_for(method)
        for field in f.get("fields", []):
            add(method, f.get("path", "/"), vector, field)
    for t in seed_targets:
        add(*t)
    return out


def _battery_for(param, battery):
    """The classes to try on a param: a name-gated class (redirect/ssrf/cmd) runs only when the param
    name hints that sink; sqli/xss/path run on every param."""
    low = (param or "").lower()
    for cls in battery:
        hints = _NAME_GATED.get(cls)
        if hints and not any(h in low for h in hints):
            continue
        yield cls


def _seed_routes(seed_targets):
    """Route objects for the seeded endpoints, so the differential oracles (idor/authz/controls) have a
    route table even when the crawler finds none (e.g. a JSON API with no HTML)."""
    seen, out = set(), []
    for method, route, _vector, _param in seed_targets:
        key = (str(method).upper(), route)
        if key not in seen:
            seen.add(key)
            out.append(routes_mod.Route(str(method).upper(), route, "<seed>", ""))
    return out


def _fill_path(method, route):
    """A concrete, fireable path for a (possibly templated) route -- leftover :params / {params} -> 1."""
    from . import exploit
    r = exploit.assemble({"method": method, "route": route, "vector": "query", "param": "", "value": "1"}, "1")
    return r["path"]


def _authz_unauth_access(rt, route, auth):
    """Access-control differential: a route that serves a substantial 2xx body WITH the attacker's
    session but serves the SAME body with NO auth -> missing authentication/authorization (CWE-862).
    Conservative: the caller restricts this to owned/sensitive-looking routes, and we require the two
    bodies to fingerprint identically (idor._fp strips volatile tokens) so a generic public 200 that
    differs per request doesn't read as a breach."""
    from . import exploit
    if not auth:
        return None                                  # nothing to differential against
    path = _fill_path(route.method, route.path)
    st_a, body_a = exploit.fire(rt.base_url, route.method, path, None, headers=dict(auth))
    if not (st_a and 200 <= st_a < 300 and len(body_a or "") >= 120):
        return None
    st_u, body_u = exploit.fire(rt.base_url, route.method, path, None, headers={})
    if not (st_u and 200 <= st_u < 300):
        return None                                  # unauth denied (401/403/redirect) -> protected, good
    if idormod._fp(body_a) == idormod._fp(body_u):
        return {"cwe": "CWE-862", "request": f"{route.method} {path}",
                "evidence": (f"identical {len(body_a)}-byte response served WITH and WITHOUT "
                             f"authentication (status {st_a}/{st_u}) -- missing access control")}
    return None


# routes whose path looks owned/private enough to bother authz-differentialing (reuses the IDOR surface
# + anything the sensitive-route detector flags).
def _authz_candidates(routes):
    owned = {(r.method, r.path): r for r in idormod.id_param_routes(routes)}
    for r in mc.sensitive_routes(routes):
        owned.setdefault((r.method, r.path), r)
    return list(owned.values())


def scan(url, seeds=("/",), max_pages=10, identities=2, seed_targets=(),
         battery=INJECTION_BATTERY, timing=False, oast=True, oast_host=None):
    """Run the black-box loop against `url`. Returns a CaseFile (the investigation record / report)."""
    case = CaseFile(target=url)

    ok, info = dastmod.reachable(url)
    if not ok:
        case.record("hypothesis", url, "tool", "blocked", provenance=url,
                    note=f"target not reachable: {info}")
        return case
    case.record("entity", url, "tool", "confirmed", provenance=url, note=f"live (HTTP {info})")

    canary = None
    if oast:
        try:
            canary = oastmod.Canary().start()
            if oast_host:
                canary.host = oast_host              # override the default host.docker.internal
            case.record("control", "oast", "tool", "confirmed", provenance=url,
                        note=f"OAST canary listening on :{canary.port} "
                             f"(callback host {getattr(canary, 'host', None) or oastmod.CONTAINER_TO_HOST})")
        except Exception as e:
            case.record("hypothesis", "oast", "tool", "blocked", provenance=url,
                        note=f"OAST listener unavailable: {e} (ssrf/blind-rce not probed)")

    try:
        rt = dastmod.Target(url)
        rec = browser_recon.recon(rt, seeds=tuple(seeds), max_pages=max_pages)
        routes = list(rec.get("routes", [])) + _seed_routes(seed_targets)
        for r in routes:
            case.record("route", f"{r.method} {r.path}", "tool", "confirmed", provenance=r.file or "")
        if rec.get("error"):
            case.record("hypothesis", url, "tool", "blocked", provenance=url,
                        note=f"recon limited: {rec['error']}")

        identity_list, auth_hdrs = [], {}
        if identities and routes:
            try:
                identity_list = authmod.synthesize_multi(rt, routes, n=max(identities, 1))
                if identity_list:
                    auth_hdrs = identity_list[0]["auth"]
                    case.record("control", "auth", "tool", "confirmed", provenance=url,
                                note=f"{len(identity_list)} identity(ies) synthesized "
                                     f"({'cookie' if 'Cookie' in auth_hdrs else 'bearer'})")
            except Exception as e:
                case.record("hypothesis", "auth", "tool", "blocked", provenance=url, note=f"auth failed: {e}")

        # ---- injection + out-of-band battery (confirmed) ----
        for method, route, vector, param in targets_from_surface(rec, seed_targets):
            for cls in _battery_for(param, battery):
                try:
                    sender = dast_oracle.Sender(url, method, route, vector, param, headers=auth_hdrs)
                    got = dast_oracle.witness(cls, sender.send, url_for=sender.url_for,
                                              headers=auth_hdrs, canary=canary,
                                              op_send=sender.send_op, timing=timing)
                except Exception:
                    got = None
                if got:
                    case.record("confirmation", f"{got['class']} via `{param}` on {method} {route}",
                                "oracle", "confirmed",
                                provenance=f"{method} {route}  [{vector}:{param}]  payload={got['payload']}",
                                cwe=got["cwe"], evidence=got["evidence"], payload=got["payload"])
                    break                            # one proven class per param is enough

        # ---- differential / judgment oracles (anomalous_state -- observed effect, severity is judgment) ----
        if routes:
            _run_differentials(case, rt, routes, auth_hdrs)
    finally:
        if canary is not None:
            canary.stop()

    deferred = sorted(dast_oracle.DEFERRED)
    case.record("hypothesis", "deferred-classes", "tool", "blocked", provenance=url,
                note=f"no black-box witness yet (payload-shape oracle unbuilt): {', '.join(deferred)}")
    return case


def _anom(case, subject, cwe, provenance, evidence):
    case.record("confirmation", subject, "oracle", "anomalous_state",
                provenance=provenance, cwe=cwe, evidence=evidence)


def _run_differentials(case, rt, routes, auth):
    """IDOR (cross-user access), authz (unauth access), and missing controls (rate-limit, old-password).
    Each is deterministic but its SEVERITY is a judgment -> anomalous_state, not confirmed. All guarded:
    a failure in one route never aborts the pass."""
    # IDOR / BOLA -- an authenticated attacker pulls multiple owners' resources through an id param.
    for r in idormod.id_param_routes(routes):
        try:
            res = idormod.prove_idor(rt, r, auth)
        except Exception:
            continue
        if res.get("status") == "proven":
            _anom(case, f"IDOR via id param on {r.method} {r.path}", res["cwe"],
                  res.get("request", f"{r.method} {r.path}"), res["evidence"])

    # Broken access control -- same resource served with and without authentication.
    for r in _authz_candidates(routes):
        try:
            res = _authz_unauth_access(rt, r, auth)
        except Exception:
            continue
        if res:
            _anom(case, f"missing access control on {r.method} {r.path}", res["cwe"],
                  res["request"], res["evidence"])

    # Missing rate limit on a secret-guessing route (brute-force). require_success=True so an endpoint
    # that merely 4xx-rejects our request shape is not mislabeled "no rate limit".
    for r in mc.sensitive_routes(routes):
        try:
            res = mc.prove_no_ratelimit(rt, r, auth, require_success=True)
        except Exception:
            continue
        if res.get("status") == "proven":
            _anom(case, f"no rate limit on {r.method} {r.path}", res["cwe"],
                  res.get("request", f"{r.method} {r.path}"), res["evidence"])

    # Missing old-password verification on an authenticated password change.
    for r in mc.change_routes(routes):
        try:
            res = mc.prove_no_oldpassword(rt, r, auth)
        except Exception:
            continue
        if res.get("status") == "proven":
            _anom(case, f"password change without old password on {r.method} {r.path}", res["cwe"],
                  res.get("request", f"{r.method} {r.path}"), res["evidence"])
