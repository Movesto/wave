"""Stored / second-order XSS regression (dast_stored.py pure core + the _run_stored_xss wiring). No
network, no browser: the Sender, the headless-render, and the canary are all stubbed.

Run: pytest tests/test_dast_stored.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.orchestrator import dast_scan
from agent.orchestrator import dast_stored as sx


# ---------- pure core ----------

def test_new_token_shape():
    t = sx.new_token()
    assert t.startswith("wsx") and t[3:].isalnum() and sx.new_token() != t


def test_write_payload_dom_only():
    p = sx.write_payload("wsxABCD")
    assert "alert('wsxABCD')" in p and "Image().src" not in p


def test_write_payload_with_beacon():
    p = sx.write_payload("wsxABCD", canary_url="http://c/wsxABCD")
    assert "alert('wsxABCD')" in p and "new Image().src='http://c/wsxABCD'" in p


def test_plan_writes_filters_and_caps():
    targets = [("GET", "/a", "query", "q"), ("POST", "/b", "body", "x"),
               ("GET", "/c", "path", "id")]          # path params aren't writable surface
    plan = sx.plan_writes(targets)
    assert ("GET", "/a", "query", "q") in plan and ("POST", "/b", "body", "x") in plan
    assert ("GET", "/c", "path", "id") not in plan
    assert len(sx.plan_writes([("POST", "/b", "body", f"f{i}") for i in range(100)], cap=5)) == 5


def test_observe_pages_dedup_and_written_first():
    from agent.orchestrator import routes as routes_mod
    routes = [routes_mod.Route("GET", "/list", "x", ""), routes_mod.Route("POST", "/write", "x", ""),
              routes_mod.Route("GET", "/list", "x", "")]
    pages = sx.observe_pages(routes, written_paths=["/write"])
    assert pages[0] == "/write"                       # the record's own view checked first
    assert "/list" in pages and pages.count("/list") == 1   # deduped; POST route excluded


def test_match_execs():
    execs = ["alert:wsx1111", "dialog:hello"]
    hits = sx.match_execs(execs, {"wsx1111": "POST /c [body:text]", "wsx2222": "POST /p [body:bio]"})
    assert hits == [("wsx1111", "POST /c [body:text]")]


def test_stored_reflection():
    payload = sx.write_payload("wsx9999")
    assert sx.stored_reflection(f"<div>{payload}</div>", "wsx9999", payload) is True
    assert sx.stored_reflection("&lt;img src=x onerror...&gt; wsx9999", "wsx9999", payload) is False
    assert sx.stored_reflection("nothing here", "wsx9999", payload) is False


# ---------- _run_stored_xss wiring (stubbed Sender / browser / canary) ----------

class _FakeSender:
    def __init__(self, *a, **k):
        pass

    def send(self, value):
        return None


def _case():
    from agent.orchestrator.recorder import CaseFile
    return CaseFile(target="http://t")


def _routes():
    from agent.orchestrator import routes as routes_mod
    return [routes_mod.Route("GET", "/comments", "<x>", "")]


def test_run_stored_xss_dom_execution_confirmed(monkeypatch):
    monkeypatch.setattr(sx, "new_token", lambda: "wsxFIXED")
    monkeypatch.setattr(dast_scan.dast_oracle, "Sender", _FakeSender)
    monkeypatch.setattr(dast_scan.dom_oracle, "available", lambda: True)
    monkeypatch.setattr(dast_scan.dom_oracle, "capture_execs",
                        lambda url, headers, *a, **k: (["alert:wsxFIXED"], None))
    case = _case()
    dast_scan._run_stored_xss(case, "http://t", [("POST", "/comments", "body", "text")], _routes(), {}, None)
    findings = case.findings()
    assert any(f.data.get("cwe") == "CWE-79" and "stored XSS" in f.subject for f in findings)


def test_run_stored_xss_reflection_fallback_without_browser(monkeypatch):
    monkeypatch.setattr(sx, "new_token", lambda: "wsxFIXED")
    monkeypatch.setattr(dast_scan.dast_oracle, "Sender", _FakeSender)
    monkeypatch.setattr(dast_scan.dom_oracle, "available", lambda: False)
    payload = sx.write_payload("wsxFIXED")
    monkeypatch.setattr(dast_scan.dast_recon, "http_fetch",
                        lambda u, method="GET", headers=None, timeout=8: {"status": 200, "body": f"x{payload}x"})
    case = _case()
    dast_scan._run_stored_xss(case, "http://t", [("POST", "/comments", "body", "text")], _routes(), {}, None)
    anom = case.by_status("anomalous_state")
    assert any("stored reflection" in e.subject for e in anom)
    assert case.findings() == []                      # reflection without a render stays a lead, not confirmed


def test_run_stored_xss_oast_callback(monkeypatch):
    monkeypatch.setattr(sx, "new_token", lambda: "wsxFIXED")
    monkeypatch.setattr(dast_scan.dast_oracle, "Sender", _FakeSender)
    monkeypatch.setattr(dast_scan.dom_oracle, "available", lambda: True)
    monkeypatch.setattr(dast_scan.dom_oracle, "capture_execs", lambda *a, **k: ([], None))  # nothing in-band

    class FakeCanary:
        host = "h"
        def url(self, token, host=None): return f"http://h/{token}"
        def hit(self, token, wait=0.2): return [{"path": "/" + token}]
    case = _case()
    dast_scan._run_stored_xss(case, "http://t", [("POST", "/comments", "body", "text")], _routes(), {}, FakeCanary())
    assert any("OAST" in f.subject and f.data.get("cwe") == "CWE-79" for f in case.findings())
