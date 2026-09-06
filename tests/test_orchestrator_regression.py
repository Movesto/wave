"""Regression suite for the wave orchestrator (Stages 1-4 + gates).

Every assertion here captures a behaviour verified once by hand during development and then lost -- this is
the durable net so a future edit can't silently break the taint tracer, a canary observer, a gate, or the
IO/escalation plumbing. ALL deterministic: no GPU, no docker, no model, no network (the one network path,
_probe, is mocked). Fast enough to run on every change.

Run: pytest tests/test_orchestrator_regression.py -q
"""
import os
import sys
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.orchestrator import (briefs, codemap, detector, provision, reachability, rung1, search, taint)
from agent.orchestrator import investigate as inv
from agent.orchestrator import prove
from agent.orchestrator import repomap
from agent.orchestrator.models import Candidate


def _cand(file="app.py", unit="f(x)", line=1, cwe="CWE-89", sink="", provable=False):
    return Candidate(file=file, unit=unit, line=line, cwe=cwe, family="t", detector="d", sink=sink,
                     provable=provable, rank=1)


def _write(tmp_path, name, body):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return p


# ============================ 1. value taint (taint.analyze) ============================

_TAINT_SRC = '''import db
def flows(uid):
    return db.execute(f"SELECT * FROM u WHERE id = {uid}")
def sanitized(uid):
    x = int(uid)
    return db.execute(f"SELECT * FROM u WHERE id = {x}")
def unrelated(uid):
    return db.execute("SELECT * FROM u WHERE active = 1")
def crossfn():
    data = load_input()
    return db.execute(f"SELECT * FROM u WHERE id = {data}")
'''


def test_taint_flows(tmp_path):
    p = _write(tmp_path, "t.py", _TAINT_SRC)
    assert taint.analyze(_cand(file=str(p), line=3))[0] == "flows"


def test_taint_sanitized(tmp_path):
    p = _write(tmp_path, "t.py", _TAINT_SRC)
    assert taint.analyze(_cand(file=str(p), line=6))[0] == "sanitized"


def test_taint_unrelated(tmp_path):
    p = _write(tmp_path, "t.py", _TAINT_SRC)
    assert taint.analyze(_cand(file=str(p), line=8))[0] == "unrelated"


def test_taint_crossfn_is_unknown_not_unrelated(tmp_path):
    # the safe-direction invariant: a value from an unresolved call is `unknown`, never `unrelated`,
    # so a real cross-function flow is never gated away.
    p = _write(tmp_path, "t.py", _TAINT_SRC)
    assert taint.analyze(_cand(file=str(p), line=11))[0] == "unknown"


def test_taint_non_python_is_unknown():
    assert taint.analyze(_cand(file="app.js", line=3))[0] == "unknown"


# ============================ 2. canary observer (rung1) ============================

M = "wzcafe01"


def test_canary_cmd_shell_proven():
    assert rung1._verdict_from_hits([("cmd", f"convert {M} out", "shell")], M, "CWE-78")[0] == "proven"


def test_canary_cmd_argv_safe():
    assert rung1._verdict_from_hits([("cmd", f"convert {M} out", "list")], M, "CWE-78")[0] == "safe"


def test_canary_path_traversal_proven():
    assert rung1._verdict_from_hits([("path", f"/up/../../{M}", "")], M, "CWE-22")[0] == "proven"


def test_canary_path_sanitized_safe():
    assert rung1._verdict_from_hits([("path", f"/up/{M}", "")], M, "CWE-22")[0] == "safe"


def test_canary_ssrf_host_proven():
    assert rung1._verdict_from_hits([("http", f"http://{M}.evil/", "")], M, "CWE-918")[0] == "proven"


def test_canary_ssrf_path_segment_not_proven():
    # marker only in a path segment of a fixed host -> not SSRF (must control the host)
    assert rung1._verdict_from_hits([("http", f"http://internal.svc/{M}", "")], M, "CWE-918")[0] == "unknown"


def test_canary_sqli_statement_proven():
    assert rung1._verdict_from_hits([("sql", f"SELECT * FROM u WHERE id={M}", "None")], M, "CWE-89")[0] == "proven"


def test_canary_sqli_param_safe():
    assert rung1._verdict_from_hits([("sql", "SELECT * FROM u WHERE id=%s", f"('{M}',)")], M, "CWE-89")[0] == "safe"


def test_canary_nosqli_operator_proven():
    hit = ("nosql", repr({"user": {"$ne": M}}), "operator")
    assert rung1._verdict_from_hits([hit], M, "CWE-943")[0] == "proven"


def test_canary_nosqli_scalar_safe():
    hit = ("nosql", repr({"user": M}), "scalar")
    assert rung1._verdict_from_hits([hit], M, "CWE-943")[0] == "safe"


def test_has_operator():
    assert rung1._has_operator({"$ne": "x"})
    assert rung1._has_operator({"u": {"$where": "x"}})
    assert not rung1._has_operator({"u": "x"})
    assert not rung1._has_operator({"u": "{'$ne':'x'}"})   # a stringified dict is not an operator


def test_payload_shapes():
    assert rung1._payload("CWE-918")[0].startswith("http://")          # host-shaped
    assert "../" in rung1._payload("CWE-22")[0]                        # traversal-shaped
    assert isinstance(rung1._payload("CWE-943")[0], dict)             # operator object


# ============================ 3. reachability + context gates ============================

_REACH_SRC = '''class _App:
    def get(self, p):
        def deco(fn): return fn
        return deco
app = _App()
@app.get("/run/{name}")
def run_route(name):
    do_it(name)
def do_it(name):
    __import__("os").system("x " + name)
def internal_only(name):
    __import__("os").system("x " + name)
'''


def test_reachability_route_reaches_sink(tmp_path):
    _write(tmp_path, "r.py", _REACH_SRC)
    cmap = codemap.build(str(tmp_path))
    reachable, _ = reachability.gate(cmap, "do_it")
    assert reachable


def test_reachability_internal_only_not_reached(tmp_path):
    _write(tmp_path, "r.py", _REACH_SRC)
    cmap = codemap.build(str(tmp_path))
    reachable, _ = reachability.gate(cmap, "internal_only")
    assert not reachable


def test_is_frontend_browser_global():
    assert reachability.is_frontend("app/src/utils/api.js", source="export const f=()=>window.location")


def test_is_frontend_backend_python():
    assert not reachability.is_frontend("backend/routers/x.py", source="import os")


def test_is_frontend_jsx():
    assert reachability.is_frontend("src/Foo.tsx", source="export const X=()=>1")


def test_is_frontend_backend_node_not_flagged():
    assert not reachability.is_frontend("services/api/handler.js",
                                        source="const db=require('pg'); db.query('...')")


# ============================ 4. detector verdict parse ============================

def test_parse_clean_json():
    assert detector._parse('{"reason":"safe","verdict":"refuted"}')["verdict"] == "refuted"


def test_parse_verdict_word_quoted_in_reason_last_wins():
    txt = '{"reason":"if safe the \\"verdict\\":\\"refuted\\" but here it survives","verdict":"survives"}'
    assert detector._parse(txt).get("verdict") == "survives"


def test_parse_think_block():
    assert detector._parse('<think>...</think>{"reason":"x","verdict":"refuted"}')["verdict"] == "refuted"


def test_parse_truncated_before_verdict():
    # broken JSON, no verdict recoverable -> empty (caller defaults to survives)
    assert detector._parse('{"reason":"long analysis with no verdict yet') == {}


# ============================ 5. proof-mode routing (briefs) ============================

def test_proof_mode_sanitizer():
    assert briefs._proof_mode(_cand(unit="sanitizeUrl(u)", cwe="CWE-79")) == "sanitizer"


def test_proof_mode_ssti():
    assert briefs._proof_mode(_cand(unit="home()", cwe="CWE-1336")) == "ssti"


def test_proof_mode_protopoll():
    assert briefs._proof_mode(_cand(unit="merge(a,b)", cwe="CWE-1321")) == "protopoll"


def test_proof_mode_deser():
    assert briefs._proof_mode(_cand(unit="loads(x)", cwe="CWE-502")) == "deser"


def test_proof_mode_render():
    assert briefs._proof_mode(_cand(unit="renderPage(d)", cwe="CWE-79")) == "render"


def test_proof_mode_call():
    assert briefs._proof_mode(_cand(unit="q(x)", cwe="CWE-89")) == "call"


# ============================ 6. prove wiring (_to_candidate, _apply_gate) ============================

def test_to_candidate_resolves_enclosing_function(tmp_path):
    _write(tmp_path, "r.py", _REACH_SRC)
    cmap = codemap.build(str(tmp_path))
    rel_index = {prove._rel(str(tmp_path), p): fi for p, fi in cmap.files.items()}
    surv = {"file": "r.py", "line": 10, "class": "cmd", "sink": "os.system"}   # inside do_it
    c = prove._to_candidate(surv, rel_index, str(tmp_path))
    assert c.unit.startswith("do_it")


def test_apply_gate_taint_unrelated_downgrades_model_confirm(tmp_path):
    _write(tmp_path, "r.py", _REACH_SRC)
    cmap = codemap.build(str(tmp_path))
    c = _cand(file=str(tmp_path / "r.py"), unit="run_route(name)", line=8, cwe="CWE-78")
    rec = {"verdict": "confirmed", "oracle": "investigate (3 run(s))", "taint": "unrelated", "why": ""}
    assert prove._apply_gate(rec, c, cmap)["verdict"] == "anomalous_state"


def test_apply_gate_taint_never_overrides_canary(tmp_path):
    _write(tmp_path, "r.py", _REACH_SRC)
    cmap = codemap.build(str(tmp_path))
    c = _cand(file=str(tmp_path / "r.py"), unit="run_route(name)", line=8, cwe="CWE-78")
    rec = {"verdict": "confirmed", "oracle": "rung1 micro-exec", "taint": "unrelated", "why": ""}
    # run_route IS a route (untrusted entry) so reachability keeps it; taint must NOT touch a canary confirm
    assert prove._apply_gate(rec, c, cmap)["verdict"] == "confirmed"


# ============================ 7. repomap pins (class detection + frontend suppression) ============================

def _pin(lang, line):
    return next((lab for lab, rx in repomap._lang_sinks(lang) if rx.search(line)), None)


def test_pin_ssti():
    assert _pin("python", "return render_template_string(request.args['t'])") == "ssti"


def test_pin_protopollution():
    assert _pin("javascript", "_.merge(target, JSON.parse(req.body))") == "protopollution"


def test_pin_nosqli():
    assert _pin("javascript", "coll.find({ user: req.body.u })") == "NoSQLi"


def test_frontend_file_suppresses_server_sink(tmp_path):
    _write(tmp_path, "api.js", "export async function apiFetch(url){ window.x=1; return fetch(url); }")
    cmap = codemap.build(str(tmp_path))
    fi = next(f for p, f in cmap.files.items() if p.endswith("api.js"))
    _routes, sinks, _dyn = repomap.scan_pins(fi)
    assert not any(lab == "ssrf" for _l, lab, _c in sinks)   # browser fetch is not server SSRF


# ============================ 8. investigate helpers (grounding + context discipline) ============================

def test_finalize_confirmed_needs_observation():
    assert inv._finalize("confirmed", "x", 0, False, False)[0] == "believed"


def test_finalize_refuted_on_provisioning_fail_becomes_blocked():
    assert inv._finalize("refuted", "x", 2, True, False)[0] == "blocked"


def test_finalize_clean_refuted_stays():
    assert inv._finalize("refuted", "x", 2, False, False)[0] == "refuted"


def test_provision_signal():
    assert inv._provision_signal("ModuleNotFoundError: No module named 'x'")
    assert inv._provision_signal("ECONNREFUSED 127.0.0.1")
    assert not inv._provision_signal("WAVE_RESULT: ok")


class _Res:
    def __init__(self, out): self.command, self.stdout, self.stderr, self.exit_code, self.duration, self.timed_out = "cmd", out, "", 0, 0.1, False


def test_digest_and_grep_recover_proof_beyond_tail():
    big = "\n".join(f"line{i}" for i in range(50)) + "\nWAVE_RESULT: uid=0(root) PROOF"
    d = inv._digest(_Res(big))
    assert "grep_output" in d                                   # digest hints at the query tools
    assert "PROOF" in inv._grep(big, "PROOF")                   # grep finds a line past the tail
    assert inv._grep(big, "zzz").startswith("no line")
    assert inv._tail(big, 1).endswith("PROOF")


# ============================ 9. provision (classify + probe) ============================

def test_classify_missing_dependency():
    assert provision._classify_failure("ModuleNotFoundError: No module named 'fastapi'") == "missing dependency"


def test_classify_port_clash():
    assert provision._classify_failure("Error: bind: address already in use") == "port clash"


def test_classify_db_not_ready():
    assert provision._classify_failure("could not connect to server: Connection refused") == "database not ready"


def test_classify_crash():
    assert provision._classify_failure("Traceback (most recent call last): ValueError") == "crash on startup"


def test_classify_unknown():
    assert provision._classify_failure("just listening on port 8000").startswith("did not become healthy")


def test_probe_404_is_up():
    # the crux fix: an HTTP response of ANY status means the server is up (was counted dead before).
    import urllib.error

    def _404(url, *a, **k):
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
    with mock.patch("urllib.request.urlopen", side_effect=_404):
        assert provision._probe("http://x")[0] is True


def test_probe_refused_is_down():
    with mock.patch("urllib.request.urlopen", side_effect=ConnectionRefusedError("refused")):
        assert provision._probe("http://x")[0] is False


# ============================ 10. web search/read degrade + url unwrap ============================

def test_web_read_empty_and_bad_url():
    assert search.web_read("") == ""
    assert search.web_read("notaurl") == ""


def test_web_search_empty():
    assert search.web_search("") == ""


def test_ddg_url_unwrap():
    assert search._real_url("/l/?uddg=https%3A%2F%2Fdocs.aws.amazon.com%2Fiam&rut=x") == \
        "https://docs.aws.amazon.com/iam"
