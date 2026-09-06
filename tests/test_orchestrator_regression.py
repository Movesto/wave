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
from agent.orchestrator import patch as patchmod
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
    reachable, conf, _ = reachability.gate(cmap, "do_it")
    assert reachable and conf == "high"          # unique name -> high confidence


def test_reachability_internal_only_not_reached(tmp_path):
    _write(tmp_path, "r.py", _REACH_SRC)
    cmap = codemap.build(str(tmp_path))
    reachable, _conf, _ = reachability.gate(cmap, "internal_only")
    assert not reachable


_AMBIG_SRC = '''class _App:
    def get(self, p):
        def deco(fn): return fn
        return deco
app = _App()
@app.get("/x")
def route_a(name):
    handle(name)
def handle(name):
    decode(name)
def decode(name):                 # decode #1 -- the sink, defined twice (ambiguous name)
    __import__("os").system(name)
class Other:
    def decode(self, name):       # decode #2 -- makes `decode` an ambiguous name-based edge
        return name
'''


def test_reachability_ambiguous_edge_is_low_confidence(tmp_path):
    # `decode` is defined twice -> the route->...->decode chain leans on a name-based guess -> low confidence
    _write(tmp_path, "a.py", _AMBIG_SRC)
    cmap = codemap.build(str(tmp_path))
    reachable, conf, _ = reachability.gate(cmap, "decode")
    assert reachable and conf == "low"


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


def test_proof_mode_asan_c_memory():
    assert briefs._proof_mode(_cand(file="v.c", unit="f(x)", cwe="CWE-120")) == "asan"
    assert briefs._proof_mode(_cand(file="v.cc", unit="f(x)", cwe="CWE-787")) == "asan"


def test_proof_mode_asan_only_c():
    # asan is C/C++ only -- a memory CWE on a .py file does not route to asan
    assert briefs._proof_mode(_cand(file="v.py", unit="f(x)", cwe="CWE-120")) == "call"
    # a cmd finding in C is not asan (it's the marker-side-effect witness)
    assert briefs._proof_mode(_cand(file="v.c", unit="f(x)", cwe="CWE-78")) == "call"


def test_asan_brief_content():
    b = briefs._brief_for(_cand(file="v.c", unit="vuln(char* x)", cwe="CWE-120", sink="strcpy"), ".", "n/a",
                          mode="asan")
    assert "-fsanitize=address,undefined" in b and "gcc" in b and "AddressSanitizer" in b
    bcpp = briefs._brief_for(_cand(file="v.cc", unit="f(x)", cwe="CWE-787", sink="memcpy"), ".", "n/a",
                             mode="asan")
    assert "g++ -fsanitize" in bcpp


def test_asan_report_is_grounding_marker():
    # an ASan/UBSan report counts as a REAL observed effect -> a confirm can be grounded on the sanitizer
    assert inv._real_exec("==1==ERROR: AddressSanitizer: stack-buffer-overflow")
    assert inv._real_exec("v.c:4:5: runtime error: signed integer overflow")
    assert not inv._real_exec("copied\nEXIT=0")


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


def test_apply_gate_intrinsic_sink_low_confidence_downgrades(tmp_path):
    # a deser (CWE-502) confirm reachable ONLY via an ambiguous `decode` edge -> mechanism, not exploitability
    _write(tmp_path, "a.py", _AMBIG_SRC)
    cmap = codemap.build(str(tmp_path))
    c = _cand(file=str(tmp_path / "a.py"), unit="decode(name)", line=12, cwe="CWE-502")
    rec = {"verdict": "confirmed", "oracle": "investigate (4 run(s))", "taint": "flows", "why": ""}
    out = prove._apply_gate(rec, c, cmap)
    assert out["verdict"] == "anomalous_state" and "intrinsic-sink" in out["why"]


def test_apply_gate_intrinsic_sink_high_confidence_kept(tmp_path):
    # a deser confirm with a HIGH-confidence chain (unique names) stays confirmed
    _write(tmp_path, "r.py", _REACH_SRC)
    cmap = codemap.build(str(tmp_path))
    c = _cand(file=str(tmp_path / "r.py"), unit="do_it(name)", line=11, cwe="CWE-502")
    rec = {"verdict": "confirmed", "oracle": "investigate (4 run(s))", "taint": "flows", "why": ""}
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


def test_pin_php():
    assert _pin("php", '$r = $db->query("SELECT * FROM u WHERE id=".$id);') == "SQLi"
    assert _pin("php", 'shell_exec("find ".$name);') == "cmd"
    assert _pin("php", '$o = unserialize($data);') == "deser"


def test_pin_ruby():
    assert _pin("ruby", 'system("lookup " + id)') == "cmd"
    assert _pin("ruby", 'eval(params[:code])') == "eval"
    assert _pin("ruby", 'Marshal.load(data)') == "deser"


def test_codemap_parses_ruby(tmp_path):
    _write(tmp_path, "a.rb", "class C\n  def show(id)\n    fetch(id)\n  end\nend\ndef fetch(id)\n  system(id)\nend\n")
    cmap = codemap.build(str(tmp_path), progress=False)
    fi = next(f for p, f in cmap.files.items() if p.endswith("a.rb"))
    assert any(f.name == "fetch" for f in fi.functions)
    assert any(c.name == "C" and any(m.name == "show" for m in c.methods) for c in fi.classes)
    assert "system" in [callee for _c, callee, _f, _l in cmap.calls]   # call edge fetch->system


def test_codemap_parses_php(tmp_path):
    _write(tmp_path, "a.php", "<?php\nclass C {\n  public function show($id){ return lookup($id); }\n}\nfunction lookup($n){ return shell_exec($n); }\n")
    cmap = codemap.build(str(tmp_path), progress=False)
    fi = next(f for p, f in cmap.files.items() if p.endswith("a.php"))
    assert any(f.name == "lookup" for f in fi.functions)
    assert any(c.name == "C" for c in fi.classes)
    assert "lookup" in [callee for _c, callee, _f, _l in cmap.calls]    # show->lookup edge


def test_pin_go():
    assert _pin("go", 'rows, _ := db.Query("SELECT * WHERE id="+id)') == "SQLi"
    assert _pin("go", 'exec.Command("sh","-c",x)') == "cmd"


def test_pin_java():
    assert _pin("java", 'Runtime.getRuntime().exec(cmd)') == "cmd"
    assert _pin("java", 'ois.readObject()') == "deser"


def test_pin_csharp():
    assert _pin("csharp", 'new SqlCommand(q).ExecuteReader()') == "SQLi"
    assert _pin("csharp", 'new BinaryFormatter().Deserialize(s)') == "deser"


def test_pin_rust():
    assert _pin("rust", 'Command::new("sh").arg(x)') == "cmd"


def test_pin_c_memory_and_format():
    assert _pin("c", 'strcpy(dst, src);') == "memory"
    assert _pin("c", 'printf(user);') == "format"
    assert _pin("cpp", 'system(cmd);') == "cmd"


def test_codemap_parses_go_java_c(tmp_path):
    _write(tmp_path, "m.go", 'package m\nfunc Handle(x string){ Run(x) }\nfunc Run(x string){ exec.Command(x) }\n')
    _write(tmp_path, "M.java", 'class C { public void run(String x){ helper(x); } void helper(String y){} }')
    _write(tmp_path, "m.c", 'void run(char* x){ system(x); }\nint main(){ run("y"); }\n')
    cmap = codemap.build(str(tmp_path), progress=False)
    langs = {fi.lang for fi in cmap.files.values()}
    assert {"go", "java", "c"} <= langs
    callees = [callee for _c, callee, _f, _l in cmap.calls]
    assert "Run" in callees and "helper" in callees and "system" in callees   # call edges resolve


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


# ============================ 10. patch Gate A: a fix must be CLEARED, not merely non-re-confirmed ========

class _FakeV:
    def __init__(self, verdict): self.verdict, self.why, self.ran, self.evidence, self.cwe, self.trail = verdict, "", 1, "", "", []


class _FakeMR:
    def __init__(self, verdict): self.verdict, self.reason, self.evidence, self.marker, self.stubs = verdict, "r", "", "", []


def _patch_status(a_status, gate_b_ok=True):
    with mock.patch.object(patchmod, "gen_patch", return_value="def f():\n    return 1\n"), \
         mock.patch.object(patchmod, "_apply", return_value="ORIG"), \
         mock.patch.object(patchmod, "_gate_a", return_value=(a_status, "n")), \
         mock.patch.object(patchmod, "_gate_b", return_value=(gate_b_ok, "b")), \
         mock.patch("pathlib.Path.write_text"):
        return patchmod._patch_one(None, ".", _cand(cwe="CWE-502"), {}, True, 6, False)["status"]


def test_gate_a_investigate_believed_is_unproven_not_still():
    # the authentik false-'fixed' bug: a reverify that comes back `believed` (couldn't re-witness) must be
    # `unproven`, NOT counted as cleared.
    with mock.patch.object(patchmod.invmod, "investigate", return_value=_FakeV("believed")), \
         mock.patch.object(patchmod.repro, "build", return_value=None), \
         mock.patch.object(patchmod.repro, "remove"):
        st, _ = patchmod._gate_a(None, ".", _cand(), {"oracle": "investigate (5 run(s))"}, True, 6)
    assert st == "unproven"


def test_gate_a_mappings_rung1():
    for v, exp in (("proven", "still"), ("safe", "cleared"), ("unknown", "unproven")):
        with mock.patch.object(patchmod.rung1, "micro_exec", return_value=_FakeMR(v)):
            st, _ = patchmod._gate_a(None, ".", _cand(cwe="CWE-78", provable=True),
                                     {"oracle": "rung1"}, True, 6)
        assert st == exp, (v, st)


def test_patch_fixed_only_when_cleared():
    assert _patch_status("cleared", True) == "fixed"


def test_patch_unverified_when_reverify_could_not_rewitness():
    # a non-fix whose reverify was believed/blocked -> unproven -> patch-unverified, NEVER fixed
    assert _patch_status("unproven", True) == "patch-unverified"


def test_patch_rejected_when_still_vulnerable():
    assert _patch_status("still", True) == "patch-rejected"


def test_patch_rejected_when_gate_b_regressed():
    assert _patch_status("cleared", False) == "patch-rejected"


# ============================ 11. evidence audit (corroboration + fresh auditor) ==================

from agent.orchestrator import audit as auditmod


class _FakeModel:
    def __init__(self, reply): self._reply = reply
    def generate(self, *a, **k): return self._reply


def test_audit_canary_must_reproduce(tmp_path):
    # a canary confirm that does NOT re-fire on the independent re-run -> downgraded (non-deterministic)
    p = _write(tmp_path, "v.py", "import os\ndef f(x):\n    os.system('a ' + x)\n")
    c = _cand(file=str(p), unit="f(x)", line=3, cwe="CWE-78", provable=True)
    with mock.patch.object(auditmod.rung1, "micro_exec",
                           return_value=type("MR", (), {"verdict": "unknown", "reason": "no hit"})()):
        v, _ = auditmod.audit(None, c, {"oracle": "rung1 micro-exec"})
    assert v == "anomalous_state"


def test_audit_fresh_auditor_downgrade(tmp_path):
    # the clean-room auditor says 'downgrade' (mechanism only) -> confirmed becomes needs-review
    p = _write(tmp_path, "v.py", "import pickle\ndef decode(d):\n    return pickle.loads(d)\n")
    c = _cand(file=str(p), unit="decode(d)", line=3, cwe="CWE-502", provable=False)
    m = _FakeModel('{"reason":"input comes from the DB, not attacker-controlled","verdict":"downgrade"}')
    v, note = auditmod.audit(m, c, {"oracle": "investigate (5 run(s))", "evidence": "pickle executed"})
    assert v == "anomalous_state" and "audit" in note


def test_audit_fresh_auditor_upholds(tmp_path):
    p = _write(tmp_path, "v.py", "import pickle\ndef decode(d):\n    return pickle.loads(d)\n")
    c = _cand(file=str(p), unit="decode(d)", line=3, cwe="CWE-502", provable=False)
    m = _FakeModel('{"reason":"the request body flows straight to pickle.loads","verdict":"upheld"}')
    v, _ = auditmod.audit(m, c, {"oracle": "investigate (5 run(s))", "evidence": "pickle executed"})
    assert v == "confirmed"


def test_audit_failure_upholds(tmp_path):
    # a glitch in the auditor must NOT silently clear a real confirmation -> upholds
    p = _write(tmp_path, "v.py", "import pickle\ndef decode(d):\n    return pickle.loads(d)\n")
    c = _cand(file=str(p), unit="decode(d)", line=3, cwe="CWE-502", provable=False)

    class _Boom:
        def generate(self, *a, **k): raise RuntimeError("boom")
    v, _ = auditmod.audit(_Boom(), c, {"oracle": "investigate (5 run(s))", "evidence": "x"})
    assert v == "confirmed"


# ============================ 12. web search/read degrade + url unwrap ============================

def test_web_read_empty_and_bad_url():
    assert search.web_read("") == ""
    assert search.web_read("notaurl") == ""


def test_web_search_empty():
    assert search.web_search("") == ""


def test_ddg_url_unwrap():
    assert search._real_url("/l/?uddg=https%3A%2F%2Fdocs.aws.amazon.com%2Fiam&rut=x") == \
        "https://docs.aws.amazon.com/iam"
