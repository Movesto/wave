"""Black-box DAST driver regression (dast_scan.py) -- the PURE parts: surface->targets, vector choice,
per-param battery, and the reachable()/Target plumbing. No network, no browser.

Run: pytest tests/test_dast_scan.py -q
"""
import os
import sys
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.orchestrator import dast as dastmod
from agent.orchestrator import dast_scan


def test_vector_for_method():
    assert dast_scan._vector_for("GET") == "query"
    assert dast_scan._vector_for("delete") == "query"
    assert dast_scan._vector_for("POST") == "body"
    assert dast_scan._vector_for("put") == "body"


def test_targets_from_forms():
    recon = {"forms": [
        {"method": "GET", "path": "/search", "fields": ["q", "page"]},
        {"method": "POST", "path": "/login", "fields": ["user", "pass"]},
    ]}
    t = dast_scan.targets_from_surface(recon)
    assert ("GET", "/search", "query", "q") in t
    assert ("GET", "/search", "query", "page") in t
    assert ("POST", "/login", "body", "user") in t


def test_targets_dedup_and_seeds():
    recon = {"forms": [{"method": "GET", "path": "/s", "fields": ["q"]}]}
    seeds = [("GET", "/s", "query", "q"), ("POST", "/api", "body", "id")]
    t = dast_scan.targets_from_surface(recon, seed_targets=seeds)
    assert t.count(("GET", "/s", "query", "q")) == 1          # form + seed collapse to one
    assert ("POST", "/api", "body", "id") in t


def test_targets_ignore_fieldless_forms():
    assert dast_scan.targets_from_surface({"forms": [{"method": "GET", "path": "/x", "fields": []}]}) == []


def test_battery_skips_redirect_unless_param_hints():
    assert "redirect" not in list(dast_scan._battery_for("q", dast_scan.INJECTION_BATTERY))
    assert "redirect" in list(dast_scan._battery_for("returnUrl", dast_scan.INJECTION_BATTERY))
    assert "sqli" in list(dast_scan._battery_for("q", dast_scan.INJECTION_BATTERY))


def test_battery_name_gates_ssrf_and_cmd():
    # sqli/xss/path always run; ssrf/cmd only on name hints
    plain = list(dast_scan._battery_for("q", dast_scan.INJECTION_BATTERY))
    assert "ssrf" not in plain and "cmd" not in plain
    assert {"sqli", "xss", "path"} <= set(plain)
    assert "ssrf" in list(dast_scan._battery_for("avatarUrl", dast_scan.INJECTION_BATTERY))
    assert "cmd" in list(dast_scan._battery_for("pingHost", dast_scan.INJECTION_BATTERY))


def test_seed_routes_builds_route_objects():
    rts = dast_scan._seed_routes([("GET", "/users/v1/:username", "path", "username"),
                                  ("GET", "/users/v1/:username", "path", "username")])   # dup collapses
    assert len(rts) == 1
    assert rts[0].method == "GET" and rts[0].path == "/users/v1/:username"


def test_target_strips_trailing_slash():
    assert dastmod.Target("http://x/").base_url == "http://x"
    assert dastmod.Target("http://x", hooks=[1]).hooks == [1]


def test_scan_records_blocked_when_unreachable():
    with mock.patch.object(dastmod, "reachable", return_value=(False, "connection refused")):
        case = dast_scan.scan("http://nope.invalid")
    assert case.counts()["blocked"] >= 1
    assert case.counts()["confirmed"] == 0


def test_run_differentials_records_idor_as_anomalous():
    from agent.orchestrator import idor as idormod
    from agent.orchestrator import routes as routes_mod
    from agent.orchestrator.recorder import CaseFile

    route = routes_mod.Route("GET", "/users/v1/:username", "<seed>", "")
    proven = {"status": "proven", "cwe": "CWE-639", "request": "GET /users/v1/:username",
              "evidence": "attacker read 3 distinct user-owned resources"}
    case = CaseFile(target="http://t")
    with mock.patch.object(idormod, "id_param_routes", return_value=[route]), \
         mock.patch.object(idormod, "prove_idor", return_value=proven):
        dast_scan._run_differentials(case, object(), [route], {"Cookie": "x"})
    anom = case.by_status("anomalous_state")
    assert len(anom) == 1 and anom[0].data["cwe"] == "CWE-639"
    assert case.counts()["confirmed"] == 0           # IDOR is a judgment, never a tool-confirmed finding


def test_scan_wires_canary_and_tears_it_down():
    recon = {"forms": [], "routes": [], "egress": []}
    stopped = {"n": 0}

    class FakeCanary:
        port = 12345
        def start(self): return self
        def stop(self): stopped["n"] += 1

    with mock.patch.object(dastmod, "reachable", return_value=(True, 200)), \
         mock.patch.object(dast_scan.oastmod, "Canary", return_value=FakeCanary()), \
         mock.patch.object(dast_scan.browser_recon, "recon", return_value=recon):
        case = dast_scan.scan("http://localhost:8080", identities=0)
    assert stopped["n"] == 1                          # canary always torn down (finally)
    assert any("OAST canary" in (e.data.get("note") or "") for e in case.all())


def test_ratelimit_require_success_rejects_4xx_only():
    from agent.orchestrator import missing_controls as mc
    from agent.orchestrator import routes as routes_mod

    import types
    rt = types.SimpleNamespace(base_url="http://t")
    route = routes_mod.Route("POST", "/register", "<seed>", "")
    # every attempt is a 400 (request-shape rejection), never throttled
    with mock.patch.object(mc.exploit, "fire", return_value=(400, "duplicate user")):
        strict = mc.prove_no_ratelimit(rt, route, require_success=True)
        loose = mc.prove_no_ratelimit(rt, route, require_success=False)
    assert strict["status"] == "not-proven"          # 4xx-only -> not a real brute-force path
    assert loose["status"] == "proven"               # legacy behavior (bench) unchanged


def test_ratelimit_require_success_still_fires_on_200s():
    from agent.orchestrator import missing_controls as mc
    from agent.orchestrator import routes as routes_mod

    import types
    rt = types.SimpleNamespace(base_url="http://t")
    route = routes_mod.Route("POST", "/login", "<seed>", "")
    with mock.patch.object(mc.exploit, "fire", return_value=(200, "wrong password")):
        res = mc.prove_no_ratelimit(rt, route, require_success=True)
    assert res["status"] == "proven"                 # 200s = real attempts, no throttle -> missing control


def test_scan_confirms_a_witnessed_param():
    # reachable + a recon surface with one form field; the oracle witnesses sqli on that param.
    recon = {"forms": [{"method": "GET", "path": "/search", "fields": ["q"]}], "routes": [], "egress": []}
    poc = {"class": "sqli", "cwe": "CWE-89", "payload": "1'", "evidence": "DB error leaked"}
    with mock.patch.object(dastmod, "reachable", return_value=(True, 200)), \
         mock.patch.object(dast_scan.browser_recon, "recon", return_value=recon), \
         mock.patch.object(dast_scan.dast_oracle, "witness", return_value=poc):
        case = dast_scan.scan("http://localhost:8080", identities=0, oast=False)
    findings = case.findings()
    assert len(findings) == 1
    assert findings[0].data["cwe"] == "CWE-89"
    assert "sqli" in findings[0].subject
