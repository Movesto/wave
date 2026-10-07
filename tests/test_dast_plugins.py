"""External-tool plugin regression (dast_plugins.py). Parsers are pure (fed canned tool output); runners
are never executed (no tool installed, nothing run live). collect() is tested with a stubbed registry.

Run: pytest tests/test_dast_plugins.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.orchestrator import dast_plugins as pl
from agent.orchestrator.recorder import CaseFile


# ---------- nuclei ----------

def test_parse_nuclei():
    jsonl = (
        '{"template-id":"tech-detect","type":"http","info":{"name":"Nginx","severity":"info",'
        '"classification":{"cwe-id":["CWE-200"]}},"matched-at":"http://t/"}\n'
        '{"template-id":"CVE-2021-1","type":"http","info":{"name":"RCE","severity":"critical"},'
        '"matched-at":"http://t/x"}\n'
        'not-json-line\n'
    )
    out = pl.parse_nuclei(jsonl)
    assert len(out) == 2
    assert out[0]["cwe"] == "CWE-200" and out[0]["tier"] == "anomalous"
    assert out[0]["provenance"] == "nuclei:tech-detect"
    assert "critical" in out[1]["evidence"]


def test_nuclei_rate_flags():
    assert pl.nuclei_rate_flags(0) == []
    assert pl.nuclei_rate_flags(0.5) == ["-rate-limit", "2"]
    assert pl.nuclei_rate_flags(2.0) == ["-rate-limit-minute", "30"]


# ---------- ffuf ----------

def test_parse_ffuf():
    js = '{"results":[{"input":{"FUZZ":"admin"},"url":"http://t/admin","status":200,"length":123},' \
         '{"input":{"FUZZ":"api"},"url":"http://t/api","status":403,"length":9}]}'
    out = pl.parse_ffuf(js)
    assert len(out) == 2
    assert out[0]["tier"] == "fact" and out[0]["provenance"] == "ffuf"
    assert out[0]["routes"] == [("GET", "/admin")]


def test_parse_ffuf_junk_is_empty():
    assert pl.parse_ffuf("not json") == []
    assert pl.parse_ffuf('{"results":[]}') == []


def test_ffuf_rate_flags():
    assert pl.ffuf_rate_flags(0) == []
    assert pl.ffuf_rate_flags(1.5) == ["-p", "1.5"]


# ---------- registry / resolve ----------

def test_resolve():
    assert pl.resolve(None) == []
    assert pl.resolve("all") == list(pl.PLUGINS)
    assert pl.resolve("nuclei,ffuf") == ["nuclei", "ffuf"]
    assert pl.resolve(["nuclei", "bogus"]) == ["nuclei"]


def test_zap_registered_and_implemented():
    assert "zap" in pl.PLUGINS and pl.ZAP_IMPLEMENTED is True


def test_zap_no_op_without_authorization(monkeypatch):
    monkeypatch.setattr(pl, "zap_available", lambda: True)
    assert pl.run_zap("http://t", authorized=False) == []        # never boots ZAP unauthorized


def test_parse_zap_tiers_and_cwe():
    alerts = {"alerts": [
        {"alert": "SQL Injection", "risk": "High", "cweid": "89", "url": "http://t/x", "pluginId": "40018"},
        {"name": "X-Frame-Options missing", "risk": "Low", "cweid": "1021", "url": "http://t/"},
        {"alert": "Info leak", "risk": "Informational", "cweid": "-1", "url": "http://t/"},
    ]}
    out = pl.parse_zap(alerts)
    assert out[0]["tier"] == "believed" and out[0]["cwe"] == "CWE-89" and out[0]["provenance"] == "zap:40018"
    assert out[1]["tier"] == "anomalous" and out[1]["cwe"] == "CWE-1021"
    assert out[2]["cwe"] == ""                                    # cweid -1 -> no CWE


def test_parse_zap_urls_dedup():
    spider = {"results": ["http://t/a", "http://t/a?x=1", "http://t/b", "http://x/c"]}
    routes = pl.parse_zap_urls(spider)
    assert ("GET", "/a") in routes and ("GET", "/b") in routes and ("GET", "/c") in routes
    assert routes.count(("GET", "/a")) == 1


def test_zap_delay_ms():
    assert pl.zap_delay_ms(0) == 0 and pl.zap_delay_ms(1.5) == 1500


# ---------- collect (stubbed registry) ----------

def test_collect_runs_available_skips_missing(monkeypatch):
    finding = {"tool": "nuclei", "class": "http", "cwe": "CWE-200", "severity": "low",
               "tier": "anomalous", "evidence": "x", "provenance": "nuclei:t",
               "routes": [("GET", "/a")], "targets": [("GET", "/a", "query", "q")]}
    monkeypatch.setitem(pl.PLUGINS, "nuclei", (lambda: True, lambda *a, **k: [dict(finding)]))
    monkeypatch.setitem(pl.PLUGINS, "ffuf", (lambda: False, lambda *a, **k: [{"x": 1}]))
    records, routes, targets, status = pl.collect("nuclei,ffuf", "http://t", authorized=True)
    assert len(records) == 1 and "routes" not in records[0]       # routes/targets pulled out
    assert routes == [("GET", "/a")] and targets == [("GET", "/a", "query", "q")]
    assert status["ffuf"] == "not installed"


def test_collect_requires_authorized_is_pluginside():
    # collect passes authorized through; the runner is what enforces it (no-op here, just a smoke call)
    records, routes, targets, status = pl.collect("", "http://t")
    assert records == [] and status == {}


# ---------- ingest ----------

def test_ingest_maps_tiers():
    case = CaseFile(target="http://t")
    pl.ingest(case, [
        {"tool": "ffuf", "class": "discovery", "tier": "fact", "evidence": "/admin", "provenance": "ffuf"},
        {"tool": "nuclei", "class": "http", "cwe": "CWE-79", "tier": "anomalous",
         "evidence": "xss lead", "provenance": "nuclei:xss"},
    ])
    assert any(e.kind == "entity" and e.status == "confirmed" for e in case.all())
    anom = case.by_status("anomalous_state")
    assert anom and anom[0].data.get("cwe") == "CWE-79"
    assert case.findings() == []                                  # a plugin lead is never a confirmed finding
