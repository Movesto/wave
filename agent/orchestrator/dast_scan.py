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
from . import dast_plugins
from . import dast_recon
from . import dast_stored
from . import dast_web
from . import dom_oracle
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


def query_targets(links):
    """(GET, path, query, param) for every query param in crawled/seed links that carry a query string.
    This is the recall fix for `?id=`/`?q=` params the crawler used to drop. Pure, deduped."""
    from urllib.parse import parse_qs, urlparse
    out, seen = [], set()
    for u in links or []:
        pr = urlparse(u)
        for k in parse_qs(pr.query):
            key = ("GET", pr.path or "/", "query", k)
            if key not in seen:
                seen.add(key)
                out.append(key)
    return out


def _dedup(targets):
    seen, out = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


# Common locations an API publishes its spec; one hit is enough.
_SPEC_PATHS = ("/openapi.json", "/swagger.json", "/v2/swagger.json", "/v3/api-docs", "/api-docs",
               "/api/swagger.json", "/swagger/v1/swagger.json")


def _expand_surface(url):
    """Pull routes + injection targets from the machine-readable surface: an OpenAPI/Swagger spec (the
    big API-recall win -- no manual seeding), plus robots.txt / sitemap.xml paths. Guarded/best-effort."""
    import json
    routes, targets, paths = [], [], []
    for sp in _SPEC_PATHS:
        r = dast_recon.http_fetch(url.rstrip("/") + sp, "GET")
        if not (r.get("status") and 200 <= r["status"] < 300):
            continue
        try:
            spec = json.loads(r.get("body") or "")
        except Exception:
            continue
        rts, tgts = dast_web.parse_openapi(spec)
        if rts or tgts:
            routes += rts
            targets += tgts
            break
    rb = dast_recon.http_fetch(url.rstrip("/") + "/robots.txt", "GET")
    if rb.get("status") and 200 <= rb["status"] < 300:
        paths += dast_web.paths_from_robots(rb.get("body"))
    sm = dast_recon.http_fetch(url.rstrip("/") + "/sitemap.xml", "GET")
    if sm.get("status") and 200 <= sm["status"] < 300:
        paths += dast_web.paths_from_sitemap(sm.get("body"))
    for p in paths:
        routes.append(("GET", p.split("?")[0]))
    targets += query_targets(paths)
    return routes, targets


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
         battery=INJECTION_BATTERY, timing=False, oast=True, oast_host=None,
         recon=True, ports=True, auth_headers=None, stored=False, delay=0.0, plugins=()):
    """Run the black-box loop against `url`. Returns a CaseFile (the investigation record / report).
    `auth_headers` (a dict) supplies a REAL session (cookie/bearer) to test authenticated areas directly
    -- when given it is used instead of synthesizing a dummy login. `delay` sets a minimum seconds
    between ALL outbound requests (politeness / rate-limit avoidance; 0 = as fast as possible)."""
    from . import dast_throttle
    dast_throttle.configure(delay)
    case = CaseFile(target=url)

    ok, info = dastmod.reachable(url)
    if not ok:
        case.record("hypothesis", url, "tool", "blocked", provenance=url,
                    note=f"target not reachable: {info}")
        dast_throttle.configure(0.0)
        return case
    case.record("entity", url, "tool", "confirmed", provenance=url, note=f"live (HTTP {info})")

    # ---- external recon (network / infra / posture) -- the red-teamer's map, before touching the app ----
    if recon:
        try:
            _run_recon(case, url, ports=ports)
        except Exception as e:
            case.record("hypothesis", "recon", "tool", "blocked", provenance=url, note=f"recon error: {e}")

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
        if rec.get("error"):
            case.record("hypothesis", url, "tool", "blocked", provenance=url,
                        note=f"recon limited: {rec['error']}")

        # ---- surface expansion (recall): crawled query params + OpenAPI spec + robots/sitemap ----
        targets = list(targets_from_surface(rec, seed_targets))
        targets += query_targets(rec.get("links"))
        ex_routes, ex_targets = _expand_surface(url)
        for m, p in ex_routes:
            routes.append(routes_mod.Route(m, p, "<surface>", ""))
        # ---- external-tool plugins (opt-in perception: nuclei/ffuf/...) -- leads + wider surface ----
        if plugins:
            try:
                records, pl_routes, pl_targets, pl_status = dast_plugins.collect(
                    plugins, url, authorized=True, delay=delay)
                dast_plugins.ingest(case, records)
                for m, p in pl_routes:
                    routes.append(routes_mod.Route(m, p, "<plugin>", ""))
                ex_targets += pl_targets
                case.record("entity", "plugins", "tool", "confirmed", provenance=url,
                            note="; ".join(f"{k}={v}" for k, v in pl_status.items()) or "none ran")
            except Exception as e:
                case.record("hypothesis", "plugins", "tool", "blocked", provenance=url,
                            note=f"plugin error: {e}")

        targets = _dedup(targets + ex_targets)
        for r in routes:
            case.record("route", f"{r.method} {r.path}", "tool", "confirmed", provenance=r.file or "")
        if ex_targets or ex_routes:
            case.record("entity", "surface-expansion", "tool", "confirmed", provenance=url,
                        note=f"recall: +{len(ex_routes)} routes, +{len(ex_targets)} params from "
                             f"OpenAPI/robots/sitemap")

        # ---- auth: a provided real session wins; else synthesize dummy identities ----
        auth_hdrs = {}
        if auth_headers:
            auth_hdrs = dict(auth_headers)
            case.record("control", "auth", "tool", "confirmed", provenance=url,
                        note=f"using provided session ({', '.join(auth_headers)})")
        elif identities and routes:
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
        for method, route, vector, param in targets:
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

        # ---- stored / second-order XSS (opt-in: it WRITES payloads + re-renders the surface) ----
        if stored:
            try:
                _run_stored_xss(case, url, targets, routes, auth_hdrs, canary)
            except Exception as e:
                case.record("hypothesis", "stored-xss", "tool", "blocked", provenance=url,
                            note=f"stored-xss error: {e}")

        # ---- differential / judgment oracles (anomalous_state -- observed effect, severity is judgment) ----
        if routes:
            _run_differentials(case, rt, routes, auth_hdrs)
    finally:
        if canary is not None:
            canary.stop()

    deferred = sorted(dast_oracle.DEFERRED)
    case.record("hypothesis", "deferred-classes", "tool", "blocked", provenance=url,
                note=f"no black-box witness yet (payload-shape oracle unbuilt): {', '.join(deferred)}")
    dast_throttle.configure(0.0)                         # reset so a later in-process SAST run isn't paced
    return case


def _anom(case, subject, cwe, provenance, evidence):
    case.record("confirmation", subject, "oracle", "anomalous_state",
                provenance=provenance, cwe=cwe, evidence=evidence)


def _find(case, subject, cwe, provenance, evidence):
    """A concrete confirmed exposure/leak (tool-observed fact, not a judgment)."""
    case.record("confirmation", subject, "oracle", "confirmed",
                provenance=provenance, cwe=cwe, evidence=evidence)


def _fact(case, subject, note):
    """A recon FACT (DNS/ports/TLS/fingerprint) -- surface intel, not a finding."""
    case.record("entity", subject, "tool", "confirmed", provenance=subject, note=note)


def _run_recon(case, url, ports=True):
    """External recon: DNS + email posture + subdomain-takeover, TLS, port/service exposure, HTTP
    fingerprint, security headers / cookies / CORS / methods, and sensitive-path discovery. Each block
    is guarded so one failure never aborts the pass. Facts -> entity; posture weaknesses ->
    anomalous_state; concrete exposures/leaks -> confirmed."""
    host, port, https = dast_recon.host_port(url)
    if not host:
        return

    # --- DNS, email spoofability, subdomain takeover ---
    try:
        dns = dast_recon.resolve(host)
        addrs = (dns.get("a") or []) + (dns.get("aaaa") or [])
        _fact(case, f"dns {host}", f"A/AAAA={addrs} CNAME={dns.get('cname') or '-'} "
                                   f"MX={len(dns.get('mx') or [])} NS={dns.get('ns') or '-'}")
        dmarc = dast_recon.resolve("_dmarc." + host).get("txt", []) if dns.get("txt") is not None else []
        for issue in dast_recon.email_security(dns.get("txt"), dmarc):
            _anom(case, f"email spoofing: {host}", "CWE-16", f"DNS {host}", issue)
        dangle = dast_recon.dangling_cname(dns.get("cname"), addrs)
        if dangle:
            _find(case, f"subdomain takeover: {host}", "CWE-350", f"DNS {host}", dangle)
    except Exception:
        pass

    # --- TLS certificate ---
    if https or port == 443:
        try:
            tls = dast_recon.tls_info(host, port if port else 443)
            if tls.get("cert"):
                a = dast_recon.analyze_cert(tls["cert"], host)
                _fact(case, f"tls {host}", f"issuer={a.get('issuer') or '-'} proto={tls.get('protocol')} "
                                           f"SAN={', '.join(a.get('san') or [])[:160] or '-'}")
                for issue in a.get("issues", []):
                    _anom(case, f"TLS: {host}", "CWE-295", f"TLS {host}:{port}", issue)
        except Exception:
            pass

    # --- open ports / exposed services ---
    if ports:
        try:
            open_ports = dast_recon.scan_ports(host)
            if open_ports:
                _fact(case, f"ports {host}", f"open: {open_ports}")
            for p, name, note in dast_recon.analyze_ports(open_ports):
                _anom(case, f"exposed service {name}:{p} on {host}", "CWE-668", f"{host}:{p}", note)
        except Exception:
            pass

    # --- HTTP posture: fingerprint, headers, cookies, methods, CORS ---
    try:
        base = dast_recon.http_fetch(url, "GET")
        if base.get("status"):
            fp = dast_web.fingerprint(base["headers"], base["body"])
            if fp:
                _fact(case, f"stack {url}", "; ".join(fp))
            for note, cwe in dast_web.security_headers(base["headers"], is_https=https):
                _anom(case, note.split(" -- ")[0], cwe, url, note)
            for note, cwe in dast_web.cookie_flags(base.get("cookies"), is_https=https):
                _anom(case, note.split(" -- ")[0], cwe, url, note)
            dl = dast_web.directory_listing(base["body"])
            if dl:
                _find(case, dl[0], dl[1], url, dl[0])
    except Exception:
        pass
    try:
        opt = dast_recon.http_fetch(url, "OPTIONS")
        for note, cwe in dast_web.http_methods(opt.get("allow")):
            _anom(case, note, cwe, f"OPTIONS {url}", f"advertised in Allow: {opt.get('allow')}")
    except Exception:
        pass
    try:
        evil = "https://wave.invalid"
        c = dast_recon.http_fetch(url, "GET", headers={"Origin": evil})
        res = dast_web.cors(evil, c.get("headers"))
        if res:
            tier = _find if "credentials" in res[0] else _anom
            tier(case, "CORS misconfiguration", res[1], url, res[0])
    except Exception:
        pass

    # --- sensitive-path / content discovery ---
    try:
        for path in dast_web.SENSITIVE_PATHS:
            r = dast_recon.http_fetch(url.rstrip("/") + path, "GET")
            hit = dast_web.classify_exposure(path, r.get("status"), r.get("body"),
                                             r.get("headers", {}).get("content-type", ""))
            if hit:
                _find(case, f"{hit[0]} ({path})", hit[1], f"GET {path}", hit[0])
    except Exception:
        pass


def _run_stored_xss(case, url, targets, routes, auth, canary):
    """Two-phase stored-XSS campaign. WRITE a unique-token payload into each writable param, then OBSERVE
    by re-rendering the surface in the headless browser + watching the OAST canary; a token that FIRES
    anywhere is a confirmed stored XSS attributed back to its injection point. Browser-less: fall back to
    a 'payload persisted un-encoded in a later page' reflection check (anomalous_state -- weaker)."""
    writes = dast_stored.plan_writes(targets)
    if not writes:
        return
    injected, written_paths = {}, []
    for method, route, vector, param in writes:
        token = dast_stored.new_token()
        cb = canary.url(token, getattr(canary, "host", None) or oastmod.CONTAINER_TO_HOST) if canary else None
        payload = dast_stored.write_payload(token, cb)
        try:
            sender = dast_oracle.Sender(url, method, route, vector, param, headers=auth)
            sender.send(payload)
        except Exception:
            continue
        injected[token] = {"source": f"{method} {route} [{vector}:{param}]", "payload": payload}
        written_paths.append(route.split("?")[0])

    if not injected:
        return
    pages = dast_stored.observe_pages(routes, written_paths)
    reported = set()

    # OBSERVE 1 -- render each surface page; a fired token proves execution and names its source sink.
    browser_ok = dom_oracle.available()
    for p in pages:
        page_url = url.rstrip("/") + "/" + p.lstrip("/")
        if browser_ok:
            execs, _err = dom_oracle.capture_execs(page_url, auth)
            for token, source in dast_stored.match_execs(execs, {t: v["source"] for t, v in injected.items()}):
                if source in reported:
                    continue
                reported.add(source)
                _find(case, f"stored XSS: {source} executes on {p}", "CWE-79",
                      f"injected at {source} -> fired at GET {p}",
                      f"stored payload (token {token}) executed in the DOM of {p}")
        else:                                               # browser-less: persisted-reflection fallback
            r = dast_recon.http_fetch(page_url, "GET", headers=auth)
            for token, v in injected.items():
                if v["source"] in reported:
                    continue
                if dast_stored.stored_reflection(r.get("body"), token, v["payload"]):
                    reported.add(v["source"])
                    _anom(case, f"stored reflection: {v['source']} on {p}", "CWE-79",
                          f"injected at {v['source']} -> reflected at GET {p}",
                          f"payload (token {token}) persisted un-encoded in {p} (needs a render to confirm execution)")

    # OBSERVE 2 -- out-of-band: a token that beaconed our canary fired SOMEWHERE (incl. an async viewer).
    if canary:
        for token, v in injected.items():
            if v["source"] in reported:
                continue
            if canary.hit(token, wait=0.2):
                reported.add(v["source"])
                _find(case, f"stored XSS (OAST): {v['source']}", "CWE-79",
                      f"injected at {v['source']}",
                      f"stored payload (token {token}) beaconed the OAST canary -- executed out of band")


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
