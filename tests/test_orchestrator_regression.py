"""Regression suite for the wave orchestrator (Stages 1-4 + gates).

Every assertion here captures a behaviour verified once by hand during development and then lost -- this is
the durable net so a future edit can't silently break the taint tracer, a canary observer, a gate, or the
IO/escalation plumbing. ALL deterministic: no GPU, no docker, no model, no network (the one network path,
_probe, is mocked). Fast enough to run on every change.

Run: pytest tests/test_orchestrator_regression.py -q
"""
import json
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
    reachable, conf, _, trust = reachability.gate(cmap, "do_it")
    assert reachable and conf == "high" and trust == "remote"   # a route is a REMOTE entry


def test_reachability_internal_only_not_reached(tmp_path):
    _write(tmp_path, "r.py", _REACH_SRC)
    cmap = codemap.build(str(tmp_path))
    reachable, _conf, _, trust = reachability.gate(cmap, "internal_only")
    assert not reachable and trust is None


_CLI_SRC = '''import argparse
def run_command(cmd):
    __import__("os").system(cmd)          # the sink -- injectable, but reachable only via a CLI main()
def main():
    p = argparse.ArgumentParser(); a = p.parse_args()
    run_command("echo " + a.x)
if __name__ == "__main__":
    main()
'''


def test_reachability_cli_main_is_local_not_remote(tmp_path):
    # a script's main() is a LOCAL/process entry, NOT a remote attack surface (Shift 3 fail-safe)
    _write(tmp_path, "scripts/tool.py", _CLI_SRC)
    cmap = codemap.build(str(tmp_path))
    reachable, _conf, note, trust = reachability.gate(cmap, "run_command")
    assert reachable and trust == "local"        # reached, but only via a CLI main()
    assert "local entry" in note


def test_other_front_doors_are_remote_entries():
    # decorator/annotation-based entries: GraphQL / NestJS messaging+ws / Spring msg / Celery / gRPC / Tauri
    from types import SimpleNamespace as NS
    for dec in ("@Query()", "@Mutation()", "@MessagePattern('t')", "@SubscribeMessage('m')",
                "@KafkaListener", "@shared_task", "#[tauri::command]", "@GrpcMethod", "@WebSocketGateway()"):
        assert reachability.entry_trust(NS(decorators=[dec], name="h")) == "remote", dec
    # realtime/consumer handler NAMES
    for nm in ("onMessage", "handle_event", "on_data", "resolver"):
        assert reachability.entry_trust(NS(decorators=[], name=nm)) == "remote", nm
    # unchanged: main is local, an ordinary helper is not an entry
    assert reachability.entry_trust(NS(decorators=[], name="main")) == "local"
    assert reachability.entry_trust(NS(decorators=[], name="helper")) is None


def test_named_socketio_handler_becomes_untrusted_entry(tmp_path):
    # socket.on("evt", namedHandler) / emitter.on(...) registers a front door -> namedHandler is a remote entry
    _write(tmp_path, "sh.js",
           'function addMonitor(data){ return fetch(data.url); }\nsocket.on("addMonitor", addMonitor);\n')
    cmap = codemap.build(str(tmp_path))
    assert "addMonitor" in cmap.event_handlers
    fs = cmap.funcs.get("addMonitor", [])
    assert fs and reachability.entry_trust(fs[0]) == "remote"
    # an INLINE arrow handler is now given a SYNTHETIC name (data-flow-lite) so it becomes a reachable entry
    _write(tmp_path, "inline.js",
           'function req(u){ return axios.get(u); }\nsocket.on("addMon", (data) => { req(data.url); });\n')
    cmap2 = codemap.build(str(tmp_path))
    assert "on:addMon" in cmap2.funcs                             # inline arrow got a synthetic front-door name
    assert reachability.entry_trust(cmap2.funcs["on:addMon"][0]) == "remote"
    reach, _c, _n, trust = reachability.gate(cmap2, "req")        # a sink under the inline handler is reachable
    assert reach and trust == "remote"


def test_apply_gate_downgrades_local_only_confirm_to_review(tmp_path):
    # a confirmed cmd-injection reachable only via a CLI main() -> anomalous_state (needs review), not confirmed
    _write(tmp_path, "scripts/tool.py", _CLI_SRC)
    cmap = codemap.build(str(tmp_path))
    c = mock.Mock(cwe="CWE-78", family="cmd", unit="run_command(cmd)",
                  file=str(tmp_path / "scripts" / "tool.py"))
    rec = {"verdict": "confirmed", "taint": "flows", "oracle": "rung1", "why": "marker reached shell"}
    out = prove._apply_gate(rec, c, cmap)
    assert out["verdict"] == "anomalous_state"
    assert "local-entry" in out["why"] or "local/CLI" in out["why"]


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
    reachable, conf, _, trust = reachability.gate(cmap, "decode")
    assert reachable and conf == "low" and trust == "remote"


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


def test_proof_mode_asan_by_sink_when_class_mislabeled():
    # the electron/c-fixture gap: the notebook labels a C strcpy as `other` (no CWE), but the SINK text
    # (strcpy/memcpy/...) reliably routes it to asan anyway -- so the sanitizer brief fires by design.
    assert briefs._proof_mode(_cand(file="records.c", unit="f(x)", cwe="", sink="strcpy(name, input)")) == "asan"
    assert briefs._proof_mode(_cand(file="x.cc", unit="f(x)", cwe="", sink="memcpy(a,b,n)")) == "asan"
    # guardrails: a memory-looking sink in Python is NOT asan; a non-memory C sink is NOT asan
    assert briefs._proof_mode(_cand(file="x.py", unit="f(x)", cwe="", sink="memmove(a)")) == "call"
    assert briefs._proof_mode(_cand(file="x.c", unit="f(x)", cwe="", sink="system(cmd)")) == "call"


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


def test_proof_mode_differential_for_access_control():
    # IDOR / broken-access-control CWEs route to the differential (2-identity) observer, others do not
    assert briefs._proof_mode(_cand(unit="get_order(id,user)", cwe="CWE-639")) == "differential"
    assert briefs._proof_mode(_cand(unit="h()", cwe="CWE-862")) == "differential"
    assert briefs._proof_mode(_cand(unit="q(x)", cwe="CWE-89")) == "call"


def test_differential_brief_content():
    b = briefs._brief_for(_cand(unit="get_order(order_id, user)", cwe="CWE-639", sink="db.get_order(order_id)"),
                          ".", "n/a", mode="differential")
    assert "TWO-IDENTITY" in b and "BASELINE" in b and "ATTACK" in b
    assert "anomalous_state" in b and "NEVER" in b            # never `confirmed` for business logic


def test_authz_class_maps_to_cwe_639():
    for cls in ("authz", "idor", "access", "bola"):
        assert prove._CLASS_CWE.get(cls) == "CWE-639"


def test_trace_logger_saves_only_verified_model_drives(tmp_path):
    from agent.orchestrator import traces
    with mock.patch.dict("os.environ", {"WAVE_TRACE_DIR": str(tmp_path)}):
        assert traces.enabled()
        kw = dict(target="/r", file="a.py", line=1, cls="cmd", cwe="CWE-78", evidence="e",
                  oracle="investigate", model="m", mode="call", ran=1)
        traces.save(verdict="confirmed", transcript=[{"role": "system"}], **kw)     # positive -> saved
        traces.save(verdict="refuted", transcript=[{"role": "system"}], **kw)       # negative -> saved
        traces.save(verdict="believed", transcript=[{"role": "system"}], **kw)      # not verified -> skip
        traces.save(verdict="confirmed", transcript=None, **kw)                     # canary (no drive) -> skip
        recs = [json.loads(x) for x in (tmp_path / "wave_traces.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(recs) == 2
    assert {r["verdict"] for r in recs} == {"confirmed", "refuted"}
    assert {r["label"] for r in recs} == {"positive", "negative"}


def test_trace_logger_disabled_by_default():
    from agent.orchestrator import traces
    with mock.patch.dict("os.environ", {}, clear=True):
        assert not traces.enabled()


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


def test_expected_lang_from_image():
    # the reverify container pins the language; the loop uses this to correct a wrong-language guess
    assert inv._expected_lang("rust:1-slim")[0] == "Rust"
    assert inv._expected_lang("rust:1-slim")[1] == "cargo"
    assert inv._expected_lang("golang:1.22")[0] == "Go"
    assert inv._expected_lang("python:3.12-slim")[0] == "Python"
    assert inv._expected_lang("node:20-slim")[0] == "JavaScript/TypeScript"
    assert inv._expected_lang("mcr.microsoft.com/dotnet/sdk:8.0")[0] == "C#/.NET"
    assert inv._expected_lang("weird-unknown-image")[0] is None
    note = inv._lang_note("Rust", "cargo")
    assert "Rust" in note and "cargo" in note and "other language" in note


def test_repro_scaffold_deep_resolver_and_actionable_error():
    # the render/call scaffold must (a) format cleanly, (b) carry the deep-search loader so a target that
    # is a METHOD nested in a factory/class config is reachable (not just a top-level export), and (c) tell
    # the model to hand-roll on a load failure instead of concluding safe. Regression for the PdfEmbed
    # (Node.create({ addNodeView(){} })) class of miss.
    from agent.orchestrator import repro
    js = repro._JS.format(target="./m.mjs", func="addNodeView", mode="render")
    py = repro._PY.format(root="/work", target="/work/t.py", func="read")
    for blob in (js, py):
        assert "WAVE_LOAD_ERROR" in blob
        assert "WRITE YOUR OWN" in blob and "NOT evidence the code is safe" in blob
    assert "depth" in js and "seen" in js and ".bind(val)" in js   # JS deep walk present
    assert "isclass" in py and "__dict__" in py                     # PY class-method deep find present


def test_write_file_tool_authors_repro_safely_and_cleans_up(tmp_path):
    # the model gets room to write its OWN repro when the scaffold doesn't fit -- but safely: inside the
    # mount only, never overwriting target source, and cleaned up by repro.remove afterward.
    from agent.orchestrator import repro
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "real.js").write_text("// source", encoding="utf-8")
    # new file OK, recorded in the manifest
    assert "wrote" in inv._do_write("app/.wave_repro.mjs", "console.log(1)", str(tmp_path))
    assert (tmp_path / "app" / ".wave_repro.mjs").exists()
    assert (tmp_path / ".wave_written.txt").exists()
    # never overwrites existing/target source
    assert "NOT overwrite" in inv._do_write("app/real.js", "HACKED", str(tmp_path))
    assert (tmp_path / "app" / "real.js").read_text(encoding="utf-8") == "// source"
    # never escapes the mount (traversal / absolute / drive)
    assert "refused" in inv._do_write("../escape.js", "x", str(tmp_path))
    assert not (tmp_path.parent / "escape.js").exists()
    assert "refused" in inv._do_write("/etc/pwn", "x", str(tmp_path))
    assert "refused" in inv._do_write("C:/win", "x", str(tmp_path))
    # repro.remove cleans the authored file + manifest, leaves real source untouched
    repro.remove(str(tmp_path))
    assert not (tmp_path / "app" / ".wave_repro.mjs").exists()
    assert not (tmp_path / ".wave_written.txt").exists()
    assert (tmp_path / "app" / "real.js").exists()
    # the tool is offered + the scaffold reframed as optional in both prompts
    assert inv._WRITE_TOOL["function"]["name"] == "write_file"
    assert "write_file" in inv._NATIVE_SYS and "SCAFFOLD IS OPTIONAL" in inv._NATIVE_SYS
    assert "SCAFFOLD IS OPTIONAL" in inv._AGENT_SYS


def test_not_exploitable_verdict_guard_and_safe_direction():
    # a REASONED not_exploitable must NAME why the input isn't attacker-controlled; a bare assertion
    # downgrades to a visible 'believed' lead (never silently clears a finding).
    assert "not_exploitable" in inv._VERDICTS
    v, _ = inv._finalize("not_exploitable",
                         "id comes from a build-time env var (process.env.CSC_NAME), never attacker input",
                         3, False, True)
    assert v == "not_exploitable"
    v2, _ = inv._finalize("not_exploitable", "looks safe", 3, False, True)
    assert v2 == "believed"                                  # no named source -> stays a lead (safe direction)
    v3, _ = inv._finalize("not_exploitable",
                          "the value is authenticated and ownership-scoped to the caller", 0, False, False)
    assert v3 == "not_exploitable"                           # a reasoning verdict needs no run
    # confirm direction is untouched: a bare confirmed with no run still downgrades to believed
    assert inv._finalize("confirmed", "x", 0, False, False)[0] == "believed"


def test_not_exploitable_is_shown_in_report_not_hidden(tmp_path):
    # a reasoned non-issue must still APPEAR in the report (re-prioritized, never deleted) so a mislabel
    # can't bury a real vuln, and it must be counted in the summary.
    import json as _json
    from pathlib import Path
    from agent.orchestrator import report
    recs = [{"verdict": "not_exploitable", "cwe": "CWE-78", "class": "cmd",
             "file": "apps/desktop/scripts/after-pack.js", "line": 126, "unit": "doBuild(context)",
             "why": "id from a build-time env var (process.env.CSC_NAME), never attacker input",
             "sink": "execSync"}]
    (tmp_path / "wave_findings.jsonl").write_text("\n".join(_json.dumps(r) for r in recs), encoding="utf-8")
    md = Path(report.generate(str(tmp_path))).read_text(encoding="utf-8")
    assert "Reasoned non-issues" in md                       # its own section header
    assert "reasoned non-issues" in md.lower()               # counted in the summary line
    assert "after-pack.js" in md                             # the finding itself is still shown
    # terminal + ordering wired in prove
    from agent.orchestrator import prove
    assert "not_exploitable" in prove._TERMINAL
    assert "not_exploitable" in prove._VERDICT_ORDER


# ============================ 9. Stage 5 -- review & reconcile (deterministic dedup) ============================

def test_reconcile_merges_same_line_contradiction_keeps_witnessed():
    # the netdata 1508 shape: same file+line, near-identical sinks (one with a `|| fatal` tail), contradictory
    # verdicts -> ONE merged finding, the witnessed verdict kept over the reasoned one, dropped read preserved.
    from agent.orchestrator import reconcile as rc
    f1 = {"file": "u.sh", "line": "1508", "unit": "", "class": "cmd", "cwe": "CWE-78",
          "sink": '. "$(dirname "${ENV}")/.install-type"', "verdict": "anomalous_state",
          "evidence": "touch ran", "why": "reachability downgrade"}
    f2 = {"file": "u.sh", "line": "1508", "unit": "", "class": "other", "cwe": "",
          "sink": '. "$(dirname "${ENV}")/.install-type" || fatal ', "verdict": "not_exploitable",
          "evidence": "", "why": "ENV is not attacker-controlled"}
    out, log = rc.reconcile([f1, f2])
    assert len(out) == 1
    assert out[0]["verdict"] == "anomalous_state"            # witnessed never dropped for a reasoned verdict
    assert out[0]["class"] == "cmd"                          # specific class beats 'other'
    assert "not attacker-controlled" in out[0]["why"]        # the dropped read is preserved, not hidden
    assert log and log[0]["action"] == "contradiction"


def test_reconcile_keeps_confirmed_over_reasoned_and_never_over_merges():
    from agent.orchestrator import reconcile as rc
    # witnessed confirmed + reasoned on the same sink -> confirmed kept (guardrail)
    same = [{"file": "a.py", "line": "5", "unit": "f()", "class": "sqli", "sink": "execute(q)",
             "verdict": "confirmed", "why": "uid=0"},
            {"file": "a.py", "line": "5", "unit": "f()", "class": "sqli", "sink": "execute(q)",
             "verdict": "believed", "why": "maybe"}]
    o1, _ = rc.reconcile(same)
    assert len(o1) == 1 and o1[0]["verdict"] == "confirmed"
    # DIFFERENT sinks on the same line are distinct bugs -> never merged
    diff = [{"file": "b.py", "line": "9", "unit": "g()", "class": "sqli", "sink": "execute(q)", "verdict": "believed"},
            {"file": "b.py", "line": "9", "unit": "g()", "class": "xss", "sink": "render(t)", "verdict": "believed"}]
    o2, _ = rc.reconcile(diff)
    assert len(o2) == 2


def test_reconcile_is_idempotent_and_deletes_nothing():
    from agent.orchestrator import reconcile as rc
    recs = [{"file": "u.sh", "line": "1508", "unit": "", "class": "cmd", "sink": "s", "verdict": "anomalous_state"},
            {"file": "u.sh", "line": "1508", "unit": "", "class": "other", "sink": "s", "verdict": "not_exploitable"},
            {"file": "z.py", "line": "1", "unit": "h()", "class": "ssrf", "sink": "get(u)", "verdict": "believed"}]
    out, _ = rc.reconcile(recs)
    assert len(out) == 2                                     # the two 1508s merge; z.py stays
    out2, log2 = rc.reconcile(out)                           # re-running changes nothing
    assert len(out2) == 2 and not log2


def test_reconcile_clusters_crossfile_lookalikes_by_signature():
    from agent.orchestrator import reconcile as rc
    fs = [{"file": "a.py", "line": "10", "class": "ssrf", "sink": "requests.get(url)", "verdict": "confirmed"},
          {"file": "b.py", "line": "20", "class": "ssrf", "sink": "requests.get(u)", "verdict": "not_exploitable"},
          {"file": "c.py", "line": "30", "class": "sqli", "sink": "execute(q)", "verdict": "believed"}]
    cl = rc._clusters(fs)
    assert len(cl) == 1 and {m["file"] for m in cl[0]} == {"a.py", "b.py"}   # same (class,callee), divergent


def test_reconcile_guardrail_witnessed_immutable_to_prose():
    from agent.orchestrator import reconcile as rc
    fs = [{"file": "a.py", "line": "10", "class": "ssrf", "sink": "requests.get(url)", "verdict": "confirmed"},
          {"file": "b.py", "line": "20", "class": "ssrf", "sink": "requests.get(u)", "verdict": "not_exploitable"}]
    by_ref = {f"{f['file']}:{f['line']}": f for f in fs}
    log, reinvest = [], []
    rc._apply_cluster_actions([
        {"ref": "a.py:10", "action": "reclassify", "verdict": "not_exploitable", "reason": "downgrade a confirmed"},
        {"ref": "b.py:20", "action": "reclassify", "verdict": "believed", "reason": "uncertain, keep as lead"},
        {"ref": "a.py:10", "action": "reinvestigate", "reason": "twin dismissed elsewhere"},
    ], by_ref, log, reinvest)
    assert by_ref["a.py:10"]["verdict"] == "confirmed"       # NEVER reasoned away
    assert by_ref["b.py:20"]["verdict"] == "believed"        # reasoned<->reasoned allowed
    assert any(e["action"] == "rejected-reclassify" for e in log)
    assert reinvest == [("a.py", 10, "ssrf")]


def test_trust_model_classifies_modules_and_entries(tmp_path):
    from agent.orchestrator import codemap, trust
    # a web module (a route), a desktop module (electron), a CLI script, a test file
    (tmp_path / "saas").mkdir(); (tmp_path / "saas" / "build.gradle").write_text("plugins{}", encoding="utf-8")
    (tmp_path / "saas" / "Ctrl.java").write_text(
        "@RestController\nclass C { @GetMapping public String get(){ return sink(); } }", encoding="utf-8")
    (tmp_path / "desk").mkdir(); (tmp_path / "desk" / "package.json").write_text(
        '{"devDependencies":{"electron":"1"}}', encoding="utf-8")
    (tmp_path / "scripts").mkdir(); (tmp_path / "scripts" / "tool.py").write_text(
        "import argparse\ndef main():\n    import os; os.system('x')\n", encoding="utf-8")
    (tmp_path / "tests").mkdir(); (tmp_path / "tests" / "t_it.py").write_text("def test_x():\n    pass\n", encoding="utf-8")
    cmap = codemap.build(str(tmp_path))
    tm = trust.build(cmap, str(tmp_path))
    assert tm.module_context(str(tmp_path / "saas" / "Ctrl.java")) == "web"
    assert tm.module_context(str(tmp_path / "desk" / "main.js")) == "desktop"
    assert tm.module_context(str(tmp_path / "scripts" / "tool.py")) == "cli"       # path signal
    assert tm.module_context(str(tmp_path / "tests" / "t_it.py")) == "test"        # path signal
    # round-trips through disk
    trust.save(tm, tmp_path)
    tm2 = trust.load(tmp_path)
    assert tm2 and tm2.modules == tm.modules


def test_apply_gate_downgrades_confirmed_in_test_module(tmp_path):
    from agent.orchestrator import trust
    tm = trust.TrustModel(target=str(tmp_path), entries={}, modules={})
    c = mock.Mock(cwe="CWE-918", family="ssrf", unit="step(x)",
                  file=str(tmp_path / "tests" / "cucumber" / "steps.py"))
    out = prove._apply_gate({"verdict": "confirmed", "why": "hit listener"}, c, None, tm)
    assert out["verdict"] == "anomalous_state" and "test-module" in out["why"]


def test_trust_enrich_is_safe_direction_only():
    # Shift 2: the model may only make a 'web' module MORE trusted; a promote-to-web / non-web touch is rejected
    import json as _json
    from agent.orchestrator import trust
    tm = trust.TrustModel(target="/t", modules={"app/api": "web", "app/admin": "web", "scripts": "cli"})

    class FakeModel:
        def generate(self, sysmsg, user, **k):
            return _json.dumps({"changes": [
                {"module": "app/admin", "context": "internal", "reason": "admin-only internal service"},
                {"module": "scripts", "context": "web", "reason": "promote (must be rejected)"},
                {"module": "app/api", "context": "web", "reason": "no-op promote"},
            ]})
        def unload(self):
            pass

    trust.enrich(FakeModel(), tm)
    assert tm.modules["app/admin"] == "internal"            # safe downgrade applied
    assert tm.modules["scripts"] == "cli"                   # promote-to-web rejected
    assert tm.modules["app/api"] == "web"                   # promote-to-web rejected
    assert "app/admin" in tm.refined


def test_apply_gate_downgrades_confirmed_in_internal_module():
    from agent.orchestrator import trust
    tm = trust.TrustModel(target="/t", modules={})
    tm.module_context = lambda f: "internal"                # model marked this module internal (Shift 2)
    c = mock.Mock(cwe="CWE-89", family="sqli", unit="q()", file="/t/app/admin/x.py")
    out = prove._apply_gate({"verdict": "confirmed", "why": "marker"}, c, None, tm)
    assert out["verdict"] == "anomalous_state" and "internal-module" in out["why"]


def test_reconcile_reinvestigation_only_a_tool_run_changes_a_verdict(tmp_path):
    # Phase 2/3 recall: the model flags a dismissed look-alike twin, and ONLY a tool re-prove may upgrade it.
    import json as _json
    from unittest import mock
    from agent.orchestrator import reconcile as rc, prove
    fs = [{"file": "a.py", "line": "10", "class": "ssrf", "sink": "requests.get(url)", "verdict": "confirmed"},
          {"file": "b.py", "line": "20", "class": "ssrf", "sink": "requests.get(u)", "verdict": "not_exploitable"}]
    (tmp_path / "wave_findings.jsonl").write_text("\n".join(_json.dumps(f) for f in fs), encoding="utf-8")

    class FakeModel:
        model_id = "fake"
        def generate(self, sysmsg, user, **k):
            return _json.dumps({"explanation": "b looks like a", "actions":
                                [{"ref": "b.py:20", "action": "reinvestigate", "reason": "twin of a confirmed"}]})
        def unload(self):
            pass

    def fake_reprove(model, target, todo, **k):              # a real tool run -> may change the verdict
        return [{**t, "verdict": "confirmed", "evidence": "re-proved", "why": "tool re-run"} for t in todo]

    with mock.patch.object(prove, "reprove", fake_reprove):
        reconciled, log = rc.run(str(tmp_path), model=FakeModel())
    by = {f["file"]: f["verdict"] for f in reconciled}
    assert by["b.py"] == "confirmed"                         # upgraded via the tool re-run, not prose
    assert any(e["action"] == "reinvestigated" for e in log)


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


# ============================ 13. on-demand dependency install (model-driven) ============================

from agent.orchestrator import execute as execmod


def test_safe_pkg_accepts_real_names():
    for name in ("fastapi", "python-jose[cryptography]", "uvicorn[standard]", "sqlalchemy==2.0.36",
                 "@scope/pkg", "requests>=2.0", "Django~=4.2"):
        assert execmod._safe_pkg(name), name


def test_safe_pkg_rejects_injection_and_flags():
    for name in ("x; rm -rf /", "--find-links=http://evil", "-e git+https://x", "a b", "pkg`whoami`",
                 "'; DROP", "../../etc", "", "x" * 200):
        assert not execmod._safe_pkg(name), name


def test_do_install_success_updates_state(monkeypatch):
    calls = {}
    def fake_install(pkgs, **kw):
        calls["pkgs"], calls["kw"] = list(pkgs), kw
        return execmod.ExecResult("install", "ok", "", 0, 0.1)
    monkeypatch.setattr(inv, "install_packages", fake_install)
    st = {"installs": 0, "budget": 6, "done": set()}
    msg = inv._do_install(["fastapi", "pydantic"], deps="/tmp/d", image="python:3.12-slim", kind="py", state=st)
    assert "installed" in msg.lower()
    assert st["installs"] == 1 and st["done"] == {"fastapi", "pydantic"}
    assert calls["pkgs"] == ["fastapi", "pydantic"] and calls["kw"]["kind"] == "py"


def test_do_install_dedups_already_installed(monkeypatch):
    monkeypatch.setattr(inv, "install_packages", lambda *a, **k: execmod.ExecResult("i", "", "", 0, 0.0))
    st = {"installs": 0, "budget": 6, "done": {"fastapi"}}
    msg = inv._do_install(["fastapi"], deps="/tmp/d", image="python:3.12-slim", kind="py", state=st)
    assert "already installed" in msg.lower() and st["installs"] == 0   # no download for a dup


def test_do_install_respects_budget(monkeypatch):
    monkeypatch.setattr(inv, "install_packages", lambda *a, **k: execmod.ExecResult("i", "", "", 0, 0.0))
    st = {"installs": 2, "budget": 2, "done": set()}
    msg = inv._do_install(["numpy"], deps="/tmp/d", image="python:3.12-slim", kind="py", state=st)
    assert "budget" in msg.lower() and st["installs"] == 2               # over budget -> no install


def test_do_install_reports_failure(monkeypatch):
    monkeypatch.setattr(inv, "install_packages",
                        lambda *a, **k: execmod.ExecResult("i", "", "No matching distribution", 1, 0.0))
    st = {"installs": 0, "budget": 6, "done": set()}
    msg = inv._do_install(["nope-xyz"], deps="/tmp/d", image="python:3.12-slim", kind="py", state=st)
    assert "failed" in msg.lower() and "nope-xyz" not in st["done"]      # a failed install isn't recorded done


def test_dep_kind_detection():
    assert inv._dep_kind_for("python:3.12-slim") == "py"
    assert inv._dep_kind_for("node:20-slim") == "js"
    assert inv._dep_kind_for("wave-js-runner") == "js"     # our runner image has no 'node' substring
    assert inv._dep_kind_for("gcc:13") == "py"


def test_execute_mounts_deps_and_sets_pythonpath(monkeypatch):
    captured = {}
    monkeypatch.setattr(execmod.shutil, "which", lambda _x: "/usr/bin/docker")
    class _R:
        stdout, stderr, returncode = "", "", 0
    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return _R()
    monkeypatch.setattr(execmod.subprocess, "run", fake_run)
    execmod.execute("echo hi", image="python:3.12-slim", mount="/repo", deps="/host/deps")
    argv = captured["cmd"]
    assert f":{execmod._DEPS_MOUNT}" in " ".join(argv)                   # deps bind-mounted
    assert f"PYTHONPATH={execmod._DEPS_MOUNT}" in argv                   # importable, no egress needed
    assert "--network" in argv and argv[argv.index("--network") + 1] == "none"  # exploit run stays offline


def test_install_packages_rejects_all_bad_names(monkeypatch):
    monkeypatch.setattr(execmod.shutil, "which", lambda _x: "/usr/bin/docker")
    called = {"ran": False}
    monkeypatch.setattr(execmod.subprocess, "run", lambda *a, **k: called.__setitem__("ran", True))
    res = execmod.install_packages(["--evil", "a;b"], deps="/d")
    assert res.exit_code == 1 and not called["ran"]                      # never shells out on bad input


# ============================ 14. web_read tiered chain (Jina primary) ============================

def test_web_read_prefers_jina(monkeypatch):
    monkeypatch.setattr(search, "_read_jina", lambda u, t: "JINA")
    monkeypatch.setattr(search, "_read_crawl4ai", lambda u, t: "CRAWL")
    monkeypatch.setattr(search, "_read_fallback", lambda u, t: "STRIP")
    assert search.web_read("https://x.dev/api") == "JINA"


def test_web_read_falls_through_to_crawl_then_strip(monkeypatch):
    monkeypatch.setattr(search, "_read_jina", lambda u, t: "")
    monkeypatch.setattr(search, "_read_crawl4ai", lambda u, t: "CRAWL")
    monkeypatch.setattr(search, "_read_fallback", lambda u, t: "STRIP")
    assert search.web_read("https://x.dev/api") == "CRAWL"
    monkeypatch.setattr(search, "_read_crawl4ai", lambda u, t: "")
    assert search.web_read("https://x.dev/api") == "STRIP"


def test_web_read_all_fail_is_empty(monkeypatch):
    for f in ("_read_jina", "_read_crawl4ai", "_read_fallback"):
        monkeypatch.setattr(search, f, lambda u, t: "")
    assert search.web_read("https://x.dev/api") == ""


def test_web_read_rejects_non_http():
    assert search.web_read("file:///etc/passwd") == ""
    assert search.web_read("") == ""


def test_jina_detects_bot_wall(monkeypatch):
    class _R:
        text = "Just a moment... cf-browser-verification"
        def raise_for_status(self): pass
    import types
    fake_requests = types.SimpleNamespace(get=lambda *a, **k: _R())
    monkeypatch.setitem(sys.modules, "requests", fake_requests)
    assert search._read_jina("https://blocked.example", 5) == ""   # bot-wall -> miss, not garbage


# ============================ 15. multi-framework route models (Rust/Java/C#/Go/Rails/Laravel) ======

from agent.orchestrator import routes as routes_mod

def test_routes_rust_rocket(tmp_path):
    _write(tmp_path, "api.rs", '#[get("/users/<id>")]\npub async fn get_user(id: i32) {}\n'
           '#[post("/login", data = "<c>")]\nfn login(c: C) {}\n')
    rs = routes_mod.extract_routes(str(tmp_path))
    assert ("GET", "get_user") in {(r.method, r.function) for r in rs}
    assert ("POST", "login") in {(r.method, r.function) for r in rs}

def test_routes_spring_base_plus_method(tmp_path):
    _write(tmp_path, "C.java", '@RequestMapping("/api/v1")\npublic class C {\n'
           '  @GetMapping("/users/{id}")\n  public User getUser(Long id) { return null; }\n}\n')
    rs = routes_mod.extract_routes(str(tmp_path))
    hit = [r for r in rs if r.function == "getUser"]
    assert hit and hit[0].path == "/api/v1/users/{id}" and hit[0].method == "GET"

def test_routes_csharp_attr(tmp_path):
    _write(tmp_path, "C.cs", '[Route("api/[controller]")]\npublic class UsersController {\n'
           '  [HttpGet("{id}")]\n  public IActionResult Get(int id) { return Ok(); }\n}\n')
    rs = routes_mod.extract_routes(str(tmp_path))
    assert ("GET", "Get") in {(r.method, r.function) for r in rs}

def test_routes_go_gin(tmp_path):
    _write(tmp_path, "m.go", 'func s(r *gin.Engine){\n r.GET("/users/:id", getUser)\n r.POST("/login", login)\n}\n')
    rs = routes_mod.extract_routes(str(tmp_path))
    paths = {(r.method, r.path) for r in rs}
    assert ("GET", "/users/:id") in paths and ("POST", "/login") in paths

def test_routes_rails_and_laravel(tmp_path):
    _write(tmp_path, "config/routes.rb", "Rails.application.routes.draw do\n  get '/users/:id', to: 'users#show'\nend\n")
    _write(tmp_path, "web.php", "Route::get('/items/{id}', [ItemController::class, 'show']);\n")
    rs = routes_mod.extract_routes(str(tmp_path))
    paths = {r.path for r in rs}
    assert "/users/:id" in paths and "/items/{id}" in paths
    assert "show" in {r.function for r in rs}   # laravel [Ctrl::class,'show'] -> action name

def test_codemap_captures_attribute_macros_as_decorators(tmp_path):
    _write(tmp_path, "a.rs", '#[get("/x")]\npub fn h() {}\n')
    _write(tmp_path, "B.java", '@RestController\npublic class B {\n @PostMapping("/y")\n public void p() {}\n}\n')
    cm = codemap.build(str(tmp_path))
    h = cm.funcs.get("h", [])
    assert h and any("#[get" in d for d in h[0].decorators)
    assert reachability.is_untrusted_entry(h[0])              # rust route -> untrusted entry (the reach fix)
    p = cm.funcs.get("p", [])
    assert p and reachability.is_untrusted_entry(p[0])        # spring @PostMapping -> untrusted entry

def test_reachability_hints_cover_new_frameworks():
    class _F:
        def __init__(self, decs): self.decorators = decs; self.name = "x"
    for d in ('#[get("/x")]', '@GetMapping("/x")', '[HttpGet("x")]', '#[Route("/x")]'):
        assert reachability.is_untrusted_entry(_F([d])), d

def test_repomap_route_pins_new_frameworks():
    for ln in ('#[post("/x")]', '@DeleteMapping("/x")', '[HttpPut("x")]', 'app.MapGet("/x", H)',
               'r.POST("/x", h)', "  resources :orders", 'Route::any("/x", [C::class,"m"]);'):
        assert repomap._ROUTE.search(ln), ln


# ============================ 16. Rust proof path (cargo repro) ============================

def _rc(cwe="CWE-248", sink="x.unwrap()"):
    return Candidate(file="src/util.rs", unit="parse_date(d: &str)", line=10, cwe=cwe, family="panic",
                     detector="d", sink=sink, provable=False, rank=1)

def test_rust_routes_to_rust_mode():
    assert briefs._proof_mode(_rc()) == "rust"
    assert briefs._is_rust("src/a.rs") and not briefs._is_rust("a.py")

def test_rust_uses_rust_toolchain_image():
    assert briefs._image_for("src/util.rs") == "rust:1-slim"

def test_rust_brief_is_a_cargo_repro():
    b = briefs._brief_for(_rc(), "/repo", "reachable panic", mode="rust")
    for token in ("cargo", "src/main.rs", "network 'host'", "panicked", "REFUTED", "blocked"):
        assert token in b, token

def test_rust_not_routed_to_asan_even_with_memory_cwe():
    # a .rs file must NOT hit the C-only ASan path even if the CWE overlaps (asan is _is_c-gated)
    assert briefs._proof_mode(_rc(cwe="CWE-190")) == "rust"

def test_rust_panic_is_a_real_exec_marker():
    assert inv._real_exec("thread 'main' panicked at src/main.rs:5:9")
    assert inv._real_exec("attempt to add with overflow")
    assert not inv._real_exec("just some normal output")


# ============================ 17. Go / Java / C# compile-repro proof paths ============================

def _cc(file, cwe="CWE-78", sink="exec"):
    return Candidate(file=file, unit="handle(x)", line=10, cwe=cwe, family="cmd", detector="d",
                     sink=sink, provable=False, rank=1)

def test_compiled_langs_route_to_own_modes():
    assert briefs._proof_mode(_cc("a.go")) == "go"
    assert briefs._proof_mode(_cc("A.java")) == "java"
    assert briefs._proof_mode(_cc("A.cs")) == "dotnet"

def test_compiled_langs_use_their_toolchain_images():
    assert briefs._image_for("a.go") == "golang:1-alpine"
    assert briefs._image_for("A.java") == "eclipse-temurin:21-jdk"
    assert "dotnet" in briefs._image_for("A.cs")

def test_compiled_briefs_are_build_and_run_recipes():
    for file, mode, needle in (("a.go", "go", "go run"), ("A.java", "java", "Repro.java"),
                               ("A.cs", "dotnet", "dotnet new console")):
        b = briefs._brief_for(_cc(file), "/repo", "reason", mode=mode)
        assert needle in b and "wave_HIT" in b and "REFUTED" in b and "blocked" in b, (mode, needle)

def test_compiled_crash_markers_are_grounding():
    assert inv._real_exec("panic: runtime error: index out of range")           # go
    assert inv._real_exec('Exception in thread "main" java.lang.NullPointer')    # java
    assert inv._real_exec("Unhandled exception. System.NullReferenceException")  # c#


# ============================ 18. Kotlin / Swift / Scala (web langs) detection + proof ============================

def test_new_langs_parsed_and_functions_extracted(tmp_path):
    _write(tmp_path, "App.kt", 'class C {\n  fun getUser(id: Int): String { return exec(id) }\n}\n')
    _write(tmp_path, "Api.swift", 'func fetch(_ u: String) -> String { return get(u) }\n')
    _write(tmp_path, "Svc.scala", 'class S {\n  def run(id: String): String = { proc(id) }\n}\n')
    cm = codemap.build(str(tmp_path))
    assert cm.funcs.get("getUser") and cm.funcs.get("fetch") and cm.funcs.get("run")  # names resolved

def test_new_langs_route_to_compiled_proof():
    assert briefs._proof_mode(_cc("App.kt")) == "kotlin"
    assert briefs._proof_mode(_cc("Api.swift")) == "swift"
    assert briefs._proof_mode(_cc("Svc.scala")) == "scala"

def test_new_langs_have_toolchain_images():
    assert briefs._image_for("App.kt") == "zenika/kotlin"
    assert briefs._image_for("Api.swift") == "swift:5.10"
    assert "scala" in briefs._image_for("Svc.scala")

def test_new_lang_briefs_build_and_run():
    for file, mode, needle in (("App.kt", "kotlin", "kotlinc"), ("Api.swift", "swift", "swift repro.swift"),
                               ("Svc.scala", "scala", "scala-cli")):
        b = briefs._brief_for(_cc(file), "/r", "reason", mode=mode)
        assert needle in b and "REFUTED" in b

def test_scala_cmd_sink_pins(tmp_path):
    _write(tmp_path, "S.scala", 'class S {\n  def r(id: String) = sys.process.Process(Seq("sh","-c",id)).!!\n}\n')
    mp = repomap.build_map(str(tmp_path))
    assert len(mp.get("pinned", [])) >= 1                     # scala.sys.process shell sink pins (not JVM-only)

def test_swift_fatal_error_is_grounding_marker():
    assert inv._real_exec("Fatal error: Unexpectedly found nil while unwrapping an Optional value")


# ============================ 19. Elixir / Bash / Lua / Haskell / Dart / Perl (backend niche) ============

def test_niche_langs_functions_extracted(tmp_path):
    _write(tmp_path, "c.ex", "defmodule M do\n  def get_user(id) do\n    System.cmd(\"sh\", [\"-c\", id])\n  end\nend\n")
    _write(tmp_path, "d.sh", "handle() {\n  eval \"$1\"\n}\n")
    _write(tmp_path, "a.lua", "local function getUser(id)\n  return os.execute(id)\nend\n")
    _write(tmp_path, "M.hs", "getUser :: String -> IO ()\ngetUser n = callCommand n\n")
    _write(tmp_path, "a.dart", "class C {\n  String getUser(String id) { return run(id); }\n}\n")
    _write(tmp_path, "c.pl", "sub get_user {\n  system(shift);\n}\n")
    cm = codemap.build(str(tmp_path))
    assert cm.funcs.get("get_user") and cm.funcs.get("handle") and cm.funcs.get("getUser")
    assert "M" in cm.classes                                # elixir defmodule -> module/class

def test_niche_langs_route_and_image():
    for ext, mode, img in ((".ex", "elixir", "elixir:latest"), (".sh", "bash", "bash:5"),
                           (".lua", "lua", "nickblah/lua:5.4"), (".hs", "haskell", "haskell:latest"),
                           (".dart", "dart", "dart:stable"), (".pl", "perl", "perl:latest")):
        c = _cc("x" + ext)
        assert briefs._proof_mode(c) == mode and briefs._image_for("x" + ext) == img

def test_niche_lang_sinks_pin(tmp_path):
    _write(tmp_path, "c.ex", "defmodule M do\n  def r(id), do: System.cmd(\"sh\", [\"-c\", id])\nend\n")
    _write(tmp_path, "d.sh", "f() { eval \"$1\"; }\n")
    _write(tmp_path, "c.pl", "sub r { system(shift); }\n")
    pinned = repomap.build_map(str(tmp_path)).get("pinned", [])
    assert len(pinned) >= 3                                 # each shell/system/eval sink pins

def test_elixir_and_haskell_crash_markers():
    assert inv._real_exec("** (RuntimeError) something bad")     # elixir
    assert inv._real_exec("*** Exception: Prelude.head: empty list")  # haskell


# ============================ 20. force a repro attempt before 'believed' ============================

class _ScriptedTool:
    """A fake tool-calling model: returns the given tool_calls in order."""
    supports_tools = True
    def __init__(self, script): self.script = script; self.i = 0; self.n = 0
    def chat(self, messages, tools=None, temperature=0):
        self.n += 1
        msg = self.script[min(self.i, len(self.script) - 1)]; self.i += 1
        return msg

def _tc(name, **args):
    return {"tool_calls": [{"id": "1", "function": {"name": name, "arguments": args}}], "content": ""}

def test_is_repro_attempt():
    assert not inv._is_repro_attempt("sed -n 1,40p /work/a.rs")
    assert not inv._is_repro_attempt("grep -n host x; cat y")
    assert inv._is_repro_attempt("cd /tmp && cargo run")
    assert inv._is_repro_attempt('python3 -c "import app"')
    assert inv._is_repro_attempt("ls -l /tmp/wave_HIT")

def test_believed_pushed_back_when_no_repro(monkeypatch):
    monkeypatch.setattr(inv, "execute", lambda *a, **k: execmod.ExecResult(a[0] if a else "", "src lines", "", 0, 0.1))
    # read (recon) -> conclude believed (should be REJECTED) -> conclude believed (accepted)
    m = _ScriptedTool([_tc("run_command", command="sed -n 1,40p /work/duo.rs"),
                       _tc("conclude", verdict="believed", why="the handler interpolates user input into the outbound URL and reaches the request sink without any validation"),
                       _tc("conclude", verdict="believed", why="the handler interpolates user input into the outbound URL and reaches the request sink without any validation")])
    v = inv.investigate(m, "test brief", deps=False, max_steps=6)
    assert v.verdict == "believed" and m.n == 3        # the first 'believed' was pushed back -> 3 model calls

def test_believed_accepted_after_a_real_repro(monkeypatch):
    monkeypatch.setattr(inv, "execute", lambda *a, **k: execmod.ExecResult(a[0] if a else "", "ran, nothing", "", 0, 0.1))
    # actually RUN something -> conclude believed (accepted immediately, no push-back)
    m = _ScriptedTool([_tc("run_command", command="cd /tmp && cargo run"),
                       _tc("conclude", verdict="believed", why="ran the repro but the outbound effect was not observable in this sandbox; plausible from the code path")])
    v = inv.investigate(m, "test brief", deps=False, max_steps=6)
    assert v.verdict == "believed" and m.n == 2        # repro attempted -> not pushed back


# ============================ 21. notebook recall determinism ============================

from agent.orchestrator import notebook as nb

def test_notebook_reads_are_deterministic_temp0():
    import inspect
    src = inspect.getsource(nb.read_note) + inspect.getsource(nb.select_targets)
    assert "temperature=0.2" not in src and src.count("temperature=0.0") >= 2   # both reads pinned to temp 0

def test_notebook_prompt_flags_panic_dos():
    s = nb._NOTE_SYS.lower()
    assert "unwrap" in s and "panic" in s and "'other'" in s   # crash/DoS class guidance present
    assert "authz" in s or "access control" in s               # authz guidance still there


# ============================ 22. Ruby / PHP interpreter proof briefs ============================

def test_ruby_php_route_to_interpreter_proof():
    assert briefs._proof_mode(_cc("app.rb")) == "ruby"
    assert briefs._proof_mode(_cc("index.php")) == "php"

def test_ruby_php_briefs_run_the_interpreter():
    rb = briefs._brief_for(_cc("app.rb"), "/r", "reason", mode="ruby")
    php = briefs._brief_for(_cc("index.php"), "/r", "reason", mode="php")
    assert "ruby repro.rb" in rb and "wave_HIT" in rb
    assert "php repro.php" in php and "wave_HIT" in php

def test_ruby_php_images():
    assert briefs._image_for("app.rb") == "ruby:3-slim" and briefs._image_for("i.php") == "php:8.2-cli"


# ============================ 23. skip vendored / minified assets ============================

def test_is_vendored_matches_libraries_and_bundles():
    for name in ("bootstrap.bundle.js", "jquery.min.js", "app.min.css", "react.production.min.js",
                 "vendor/popper.js", "d3.min.js", "chart-min.js", "select2.min.css"):
        assert codemap._is_vendored(name), name

def test_is_vendored_spares_app_source():
    for name in ("app.js", "src/user_model.rs", "handlers.py", "bundle_helper.rb", "main.go",
                 "reactor.py", "charts_controller.rb"):
        assert not codemap._is_vendored(name), name

def test_looks_minified():
    assert codemap._looks_minified(b"var a=1,b=2,c=3;" * 400)          # one huge line
    assert not codemap._looks_minified(b"def f(x):\n    return x + 1\n" * 200)

def test_vendored_file_excluded_from_map(tmp_path):
    _write(tmp_path, "app.js", "function handle(id){ return exec(id); }\n")
    _write(tmp_path, "static/bootstrap.bundle.js", "// bootstrap\n" + "function _b(){}\n" * 50)
    _write(tmp_path, "static/jquery.min.js", "!function(e){}(window);\n")
    cm = codemap.build(str(tmp_path))
    files = "\n".join(cm.files.keys())
    assert "app.js" in files and "bootstrap.bundle.js" not in files and "jquery.min.js" not in files


# ============================ 24. all-files coverage: unpinned files read head-to-tail ============================

def test_windows_cover_unpinned_file_head_to_tail():
    src = "\n".join(f"line {i}" for i in range(1, 400))     # 399-line file, NO pins
    wins = nb._windows_for(src, focus_lines=[])
    assert len(wins) >= 3 and [w[0] for w in wins] == [1, 151, 301]   # sequential head-to-tail, not head-only

def test_windows_still_cover_pins_when_present():
    src = "\n".join(f"line {i}" for i in range(1, 400))
    wins = nb._windows_for(src, focus_lines=[307])           # a pin deep in the file
    assert any(w[0] <= 307 <= w[0] + 149 for w in wins)      # a window actually covers the pinned line


# ============================ 25. value taint for JS/TS (was Python-only) ============================

def _write_taint_js(tmp_path, name, body):
    return str(_write(tmp_path, name, body))

def test_taint_js_flows(tmp_path):
    f = _write_taint_js(tmp_path, "a.js", "function h(req){\n  const q = req.query.id;\n  db.query(q);\n}\n")
    c = Candidate(file=f, unit="h", line=3, cwe="CWE-89", family="t", detector="d", sink="db.query", provable=False, rank=1)
    assert taint.analyze(c)[0] == "flows"

def test_taint_js_sanitized(tmp_path):
    f = _write_taint_js(tmp_path, "b.js", "function h(req){\n  const q = Number(req.query.id);\n  db.query(q);\n}\n")
    c = Candidate(file=f, unit="h", line=3, cwe="CWE-89", family="t", detector="d", sink="db.query", provable=False, rank=1)
    assert taint.analyze(c)[0] == "sanitized"

def test_taint_ts_unrelated(tmp_path):
    f = _write_taint_js(tmp_path, "c.ts", "function h(req: any){\n  const q = 'SELECT 1';\n  db.query(q);\n}\n")
    c = Candidate(file=f, unit="h", line=3, cwe="CWE-89", family="t", detector="d", sink="db.query", provable=False, rank=1)
    assert taint.analyze(c)[0] == "unrelated"

def test_taint_js_crossfn_is_unknown(tmp_path):
    # value from an unresolved call -> unknown (never `unrelated`), so a real cross-fn flow is never gated away
    f = _write_taint_js(tmp_path, "d.js", "function h(){\n  const q = loadInput();\n  db.query(q);\n}\n")
    c = Candidate(file=f, unit="h", line=3, cwe="CWE-89", family="t", detector="d", sink="db.query", provable=False, rank=1)
    assert taint.analyze(c)[0] == "unknown"

def test_taint_unsupported_lang_is_unknown(tmp_path):
    f = _write_taint_js(tmp_path, "e.kt", "fun h(id: String) { db.query(id) }\n")  # kotlin: not a taint lang
    c = Candidate(file=f, unit="h", line=1, cwe="CWE-89", family="t", detector="d", sink="db.query", provable=False, rank=1)
    assert taint.analyze(c)[0] == "unknown"


# ============================ 26. no-sink IDOR/authz recall pin ============================

def _authz_pins_for(tmp_path, body):
    _write(tmp_path, "h.py", body)
    cm = codemap.build(str(tmp_path))
    finfo = next(iter(cm.files.values()))
    _r, sinks, _d = repomap.scan_pins(finfo)
    return [(ln, code) for ln, lbl, code in sinks if lbl == "authz"]

def test_authz_pin_fires_on_idor_handler(tmp_path):
    pins = _authz_pins_for(tmp_path, "from x import *\n"
        "@router.get('/orders/{order_id}')\n"
        "def get_order(order_id: int):\n"
        "    return db.query(Order).get(order_id)\n")
    assert len(pins) == 1 and "get_order" in pins[0][1]

def test_authz_pin_skips_ownership_checked(tmp_path):
    pins = _authz_pins_for(tmp_path, "from x import *\n"
        "@router.get('/orders/{order_id}')\n"
        "def get_order(order_id: int, user=Depends(current_user)):\n"
        "    o = db.query(Order).get(order_id)\n"
        "    if o.owner_id != user.id: raise HTTPException(403)\n"
        "    return o\n")
    assert pins == []

def test_authz_pin_skips_internal_helper(tmp_path):
    # not a route/untrusted-entry -> not flagged (internal getter, called by trusted code)
    pins = _authz_pins_for(tmp_path, "def _load(order_id):\n    return db.query(Order).get(order_id)\n")
    assert pins == []

def test_authz_pin_skips_route_without_id_param(tmp_path):
    pins = _authz_pins_for(tmp_path, "from x import *\n"
        "@router.get('/health')\n"
        "def health():\n    return db.query(Status).first()\n")
    assert pins == []


# ============================ 27. mid-loop read-thrash nudge ============================

def test_recon_streak_triggers_midloop_nudge(monkeypatch):
    monkeypatch.setattr(inv, "execute", lambda *a, **k: execmod.ExecResult(a[0] if a else "", "src", "", 0, 0.1))
    seen = {"nudged": False}
    class _M:
        supports_tools = True
        def __init__(s): s.i = 0; s.n = 0
        def chat(s, messages, tools=None, temperature=0):
            s.n += 1
            # detect the mid-loop nudge appearing in the last tool message
            for m in messages:
                if m.get("role") == "tool" and "STOP reading" in (m.get("content") or ""):
                    seen["nudged"] = True
            # emit read-only commands until nudged, then conclude
            if seen["nudged"]:
                return _tc("conclude", verdict="refuted", why="ran it and it is safe after inspection done here")
            return _tc("run_command", command=f"sed -n {s.n},40p /work/x.py")
        pass
    v = inv.investigate(_M(), "brief", deps=False, max_steps=8)
    assert seen["nudged"]              # after 3 read-only commands, the mid-loop nudge fired


# ============================ 28. Ktor/Actix DSL routes + broader auth detection ============================

def test_ktor_and_actix_routes_pin():
    for ln in ['get("/users/{id}") {', 'post("/login") {',
               '.route("/api/x", web::get().to(handler))', 'web::resource("/y").route(web::post().to(h))']:
        assert repomap._ROUTE.search(ln), ln

def test_route_pin_not_over_eager_on_plain_get():
    # a bare map/get access without the DSL lambda shape must NOT pin
    assert not repomap._ROUTE.search('val name = cache.get("key")')

def test_auth_detection_covers_more_stacks():
    assert nb._auth_from('@PreAuthorize("hasRole(ADMIN)")') == "admin"
    assert nb._auth_from("fun handler(_token: AdminToken)") == "admin"
    assert nb._auth_from('@Secured("ROLE_USER")') == "session"
    assert nb._auth_from("before_action :require_login") == "session"
    assert nb._auth_from("def public_health():") == "none"


# ============================ 29. detection-recall benchmark (the measuring stick) ============================

def test_detect_recall_benchmark_holds():
    from agent.bench import detect_recall
    r = detect_recall.run()
    assert r["recall"] >= 0.95, f"detection recall regressed: {r['recall']:.0%} ({r['fn']} misses)"
    assert r["fp"] == 0, f"deterministic precision regressed: {r['fp']} guarded-clean cases leaked a pin"


# ============================ 30. value taint across Go/Java/C#/Ruby/PHP/Rust ============================

def _taint_of(tmp_path, name, body, line, sink="sink"):
    f = _write(tmp_path, name, body)
    c = Candidate(file=str(f), unit="h", line=line, cwe="CWE-89", family="t", detector="d", sink=sink, provable=False, rank=1)
    return taint.analyze(c)[0]

def test_taint_flows_go_java_cs_ruby_php_rust(tmp_path):
    assert _taint_of(tmp_path, "z.go", 'func h(id string){\n q:="x"+id\n db.Query(q)\n}\n', 3) == "flows"
    assert _taint_of(tmp_path, "Z.java", 'class C{void h(String id){\n String q="x"+id;\n db.query(q);\n}}\n', 3) == "flows"
    assert _taint_of(tmp_path, "Z.cs", 'class C{void H(string id){\n var q="x"+id;\n Db.Query(q);\n}}\n', 3) == "flows"
    assert _taint_of(tmp_path, "z.rb", 'def h(id)\n q="x"+id\n db.query(q)\nend\n', 3) == "flows"
    assert _taint_of(tmp_path, "z.php", '<?php function h($id){\n $q="x".$id;\n db_query($q);\n}\n', 3) == "flows"
    assert _taint_of(tmp_path, "z.rs", 'fn h(id:&str){\n let q=format!("{}",id);\n db_query(&q);\n}\n', 3) == "flows"

def test_taint_const_and_sanitized_other_langs(tmp_path):
    # a constant (no param) -> unrelated; a wrapped value -> sanitized -- the precision signals, cross-lang
    assert _taint_of(tmp_path, "c.go", 'func h(){\n q:="SELECT 1"\n db.Query(q)\n}\n', 3) == "unrelated"
    assert _taint_of(tmp_path, "S.java", 'class C{void h(String id){\n int q=Integer.parseInt(id);\n db.query(q);\n}}\n', 3) == "sanitized"


# ============================ 31. custom-named sink recall ============================

def _custom_pins(tmp_path, body):
    _write(tmp_path, "h.py", body)
    cm = codemap.build(str(tmp_path))
    finfo = next(iter(cm.files.values()))
    _r, sinks, _d = repomap.scan_pins(finfo)
    return [lbl for _ln, lbl, _c in sinks]

def test_custom_sinks_detected_with_inferred_class(tmp_path):
    assert "cmd" in _custom_pins(tmp_path, "def h(req):\n    run_shell_command(req.args['c'])\n")
    assert "SQLi" in _custom_pins(tmp_path, "def h(req):\n    exec_sql('SELECT ' + req.args['q'])\n")
    assert "deser" in _custom_pins(tmp_path, "def h(req):\n    unpickle_data(req.data)\n")
    assert "xss" in _custom_pins(tmp_path, "def h(req):\n    unsafe_render(req.args['t'])\n")

def test_custom_sink_quiet_on_benign_names(tmp_path):
    assert _custom_pins(tmp_path, "def h():\n    a = run_report()\n    b = query_count()\n    return execute_plan()\n") == []


# ============================ 32. CWE metadata + report enrichment ============================

from agent.orchestrator import cwe_info

def test_cwe_describe_known_and_fallback():
    name, sev, rem = cwe_info.describe("CWE-89")
    assert "SQL Injection" in name and sev == "high" and "parameteriz" in rem.lower()
    # class fallback when the CWE id is missing/fuzzy
    name2, sev2, _ = cwe_info.describe("", "authz")
    assert "Authorization" in name2 or "IDOR" in name2
    # unknown -> generic, never a bare id
    name3, sev3, rem3 = cwe_info.describe("CWE-99999", "mystery")
    assert name3 and sev3 == "unknown" and rem3

def test_cwe_severity_ordering():
    assert cwe_info.sev_rank("CWE-78") < cwe_info.sev_rank("CWE-89")      # cmd(critical) more severe than sqli(high)
    assert cwe_info.sev_rank("CWE-89") < cwe_info.sev_rank("CWE-601")     # sqli(high) more severe than redirect(medium)

def test_report_shows_cwe_name_and_remediation(tmp_path):
    from agent.orchestrator import report
    (tmp_path / "wave_findings.jsonl").write_text(
        json.dumps({"file": "db.py", "line": 1, "class": "sqli", "cwe": "CWE-89", "verdict": "confirmed",
                    "evidence": "marker in SQL", "confidence": "high"}) + "\n", encoding="utf-8")
    report.generate(str(tmp_path), model="m")
    md = (tmp_path / "WAVE_REPORT.md").read_text(encoding="utf-8")
    assert "SQL Injection" in md and "· high" in md and "how to fix" in md and "parameteriz" in md.lower()

def test_report_orders_by_severity(tmp_path):
    from agent.orchestrator import report
    rows = [{"file": "a.py", "line": 1, "class": "redirect", "cwe": "CWE-601", "verdict": "believed", "why": "x"},
            {"file": "b.py", "line": 2, "class": "cmd", "cwe": "CWE-78", "verdict": "believed", "why": "y"}]
    (tmp_path / "wave_findings.jsonl").write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    report.generate(str(tmp_path), model="m")
    md = (tmp_path / "WAVE_REPORT.md").read_text(encoding="utf-8")
    assert md.index("Command Injection") < md.index("Open Redirect")     # critical before medium


# ============================ 33. SARIF 2.1.0 export ============================

from agent.orchestrator import sarif as sarifmod

def test_sarif_structure_and_filtering():
    findings = [
        {"file": "db.py", "line": 42, "class": "sqli", "cwe": "CWE-89", "verdict": "confirmed", "evidence": "x"},
        {"file": "o.py", "line": 9, "class": "authz", "cwe": "CWE-639", "verdict": "anomalous_state", "why": "y"},
        {"file": "s.py", "line": 1, "class": "sqli", "cwe": "CWE-89", "verdict": "refuted", "why": "safe"},
        {"file": "b.py", "line": 2, "class": "cmd", "cwe": "CWE-78", "verdict": "blocked"},
    ]
    doc = sarifmod.to_sarif(findings, root=".")
    assert doc["version"] == "2.1.0" and doc["runs"][0]["tool"]["driver"]["name"] == "wave"
    results = doc["runs"][0]["results"]
    assert len(results) == 2                                        # refuted + blocked excluded
    assert {r["ruleId"] for r in results} == {"CWE-89", "CWE-639"}
    assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in results)

def test_sarif_level_and_helpuri():
    doc = sarifmod.to_sarif([{"file": "c.py", "line": 1, "class": "cmd", "cwe": "CWE-78", "verdict": "confirmed"},
                             {"file": "r.py", "line": 1, "class": "redirect", "cwe": "CWE-601", "verdict": "believed"}])
    rules = {x["id"]: x for x in doc["runs"][0]["runs"][0]["tool"]["driver"]["rules"]} if False else {
        x["id"]: x for x in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["CWE-78"]["defaultConfiguration"]["level"] == "error"      # critical -> error
    assert rules["CWE-601"]["defaultConfiguration"]["level"] == "warning"   # medium -> warning
    assert rules["CWE-78"]["helpUri"].endswith("/78.html")

def test_sarif_write(tmp_path):
    n = sarifmod.write([{"file": "db.py", "line": 5, "class": "sqli", "cwe": "CWE-89", "verdict": "confirmed"}],
                       tmp_path / "wave.sarif", root=str(tmp_path))
    assert n == 1
    doc = json.loads((tmp_path / "wave.sarif").read_text(encoding="utf-8"))
    assert doc["runs"][0]["results"][0]["ruleId"] == "CWE-89"


# ============================ 34. DAST escalation decision layer ============================

from agent.orchestrator import dast

def test_dast_mode_mapping():
    assert dast.dast_mode({"cwe": "CWE-639", "class": "authz"}) == "differential"
    assert dast.dast_mode({"class": "sqli"}) == "injection"
    assert dast.dast_mode({"class": "ssrf"}) == "injection"
    assert dast.dast_mode({"class": "other"}) is None

def test_dast_bootable(tmp_path):
    assert dast.bootable(str(tmp_path)) is False
    (tmp_path / "docker-compose.yml").write_text("services:\n  web:\n    build: .\n", encoding="utf-8")
    assert dast.bootable(str(tmp_path)) is True

def test_dast_plan_escalates_only_unproven_on_bootable():
    findings = [{"file": "a.py", "line": 1, "class": "sqli", "cwe": "CWE-89", "verdict": "believed"},
                {"file": "b.py", "line": 2, "class": "authz", "cwe": "CWE-639", "verdict": "blocked"},
                {"file": "c.py", "line": 3, "class": "sqli", "cwe": "CWE-89", "verdict": "confirmed"},   # settled
                {"file": "d.py", "line": 4, "class": "other", "verdict": "believed"}]                    # no oracle
    esc = dast.plan(findings, can_boot=True)
    assert len(esc) == 2
    modes = {e["mode"] for e in esc}
    assert modes == {"injection", "differential"}

def test_dast_plan_empty_when_not_bootable():
    findings = [{"file": "a.py", "line": 1, "class": "sqli", "cwe": "CWE-89", "verdict": "believed"}]
    assert dast.plan(findings, can_boot=False) == []

def test_dast_summarize():
    assert "live-app run" in dast.summarize([{"mode": "injection"}, {"mode": "injection"}])
    assert "no findings" in dast.summarize([])


# ============================ 35. Rust serde deserialization is safe (MemWhale FP) ============================

def test_rust_serde_yaml_not_flagged_deser(tmp_path):
    # Rust serde deserialization into a typed struct is safe -- must NOT pin CWE-502 (real FP from MemWhale)
    _write(tmp_path, "p.rs", "fn validate(t: &str) {\n  let m: Metadata = serde_yaml::from_str(t).unwrap();\n}\n")
    cm = codemap.build(str(tmp_path))
    finfo = next(iter(cm.files.values()))
    _r, sinks, _d = repomap.scan_pins(finfo)
    assert "deser" not in [lbl for _l, lbl, _c in sinks]

def test_rust_real_cmd_sink_still_pins(tmp_path):
    _write(tmp_path, "r.rs", "fn run(c: &str) {\n  Command::new(\"sh\").arg(\"-c\").arg(c);\n}\n")
    cm = codemap.build(str(tmp_path))
    finfo = next(iter(cm.files.values()))
    _r, sinks, _d = repomap.scan_pins(finfo)
    assert "cmd" in [lbl for _l, lbl, _c in sinks]          # no over-correction


# ============================ 36. authz is server-side (frontend authz suppressed; MemWhale App.tsx FP) ====

def test_frontend_authz_suppressed_backend_kept(tmp_path):
    _write(tmp_path, "src/App.tsx", "export function App(){\n  const approve = (id) => callBackend('approve_lesson', { id });\n  return null;\n}\n")
    _write(tmp_path, "api.py", "from x import *\n@router.get('/o/{oid}')\ndef get_o(oid: int):\n    return db.query(O).get(oid)\n")
    cm = codemap.build(str(tmp_path))
    pins = {}
    for p, f in cm.files.items():
        _r, s, _d = repomap.scan_pins(f)
        pins[__import__("pathlib").Path(p).name] = [lbl for _l, lbl, _c in s]
    assert "authz" not in pins.get("App.tsx", [])            # authz lives server-side, not in a React handler
    assert "authz" in pins.get("api.py", [])                 # backend authz still flagged (no over-correction)

def test_authz_in_server_only_sets():
    assert "authz" in reachability.SERVER_ONLY_CLASSES and "CWE-639" in reachability.SERVER_ONLY_CWE


# ============================ 37. remediation + notebook safe-pattern guidance (MemWhale follow-ups) ====

def test_cwe502_remediation_is_language_neutral():
    _n, _s, rem = cwe_info.describe("CWE-502")
    assert "Rust serde" in rem and "readObject" in rem     # not pickle-only; notes Rust serde is safe

def test_notebook_prompt_marks_safe_patterns():
    s = nb._NOTE_SYS
    assert "serde" in s and "Value` indexing" in s and "argv-list" in s   # the MemWhale over-flags, pre-empted


# ============================ 38. desktop-app authz downgrade (Tauri/Electron single-user) ============

def test_is_desktop_app_detects_tauri_and_electron(tmp_path):
    (tmp_path / "src-tauri").mkdir()
    (tmp_path / "src-tauri" / "Cargo.toml").write_text("[dependencies]\ntauri = \"1\"\n", encoding="utf-8")
    assert reachability.is_desktop_app(str(tmp_path)) is True
    e = tmp_path / "electronapp"
    e.mkdir()
    (e / "package.json").write_text('{"dependencies": {"electron": "^30"}}', encoding="utf-8")
    assert reachability.is_desktop_app(str(e)) is True

def test_is_desktop_app_false_for_plain_repo(tmp_path):
    (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")
    assert reachability.is_desktop_app(str(tmp_path)) is False

def test_desktop_authz_downgrades_only_authz(tmp_path):
    from agent.orchestrator import reachability
    reachability._detect_desktop.cache_clear()
    # a desktop repo (electron marker) with a plain authz file and a server-endpoint file
    (tmp_path / "package.json").write_text('{"devDependencies":{"electron":"1"}}', encoding="utf-8")
    (tmp_path / "store.py").write_text("def get(id):\n    return db[id]\n", encoding="utf-8")
    (tmp_path / "ctrl.java").write_text("@RestController\nclass C { @GetMapping String f(@PathVariable String id){} }",
                                        encoding="utf-8")
    c_authz = _cand(file=str(tmp_path / "store.py"), cwe="CWE-639"); c_authz.__dict__["family"] = "IDOR"
    c_sqli = _cand(file=str(tmp_path / "store.py"), cwe="CWE-89"); c_sqli.__dict__["family"] = "sqli"
    c_route = _cand(file=str(tmp_path / "ctrl.java"), cwe="CWE-639"); c_route.__dict__["family"] = "IDOR"
    # authz in a plain (non-endpoint) file of a desktop app -> downgraded
    r1 = prove._desktop_authz({"verdict": "anomalous_state", "why": "no check"}, c_authz, str(tmp_path))
    assert r1["verdict"] == "believed" and r1["confidence"] == "low" and r1["desktop_context"]
    # injection untouched even in a desktop app
    r2 = prove._desktop_authz({"verdict": "confirmed", "why": "marker"}, c_sqli, str(tmp_path))
    assert r2["verdict"] == "confirmed" and "desktop_context" not in r2
    # SERVER ENDPOINT (web route) authz is a real multi-tenant boundary -> NOT downgraded (the Stirling saas bug)
    r3 = prove._desktop_authz({"verdict": "anomalous_state", "why": "no ownership check"}, c_route, str(tmp_path))
    assert r3["verdict"] == "anomalous_state" and "desktop_context" not in r3


def test_desktop_is_scoped_per_module_not_repo_global(tmp_path):
    # a repo that ships a desktop build in one module must NOT tag a sibling web module as desktop (Stirling)
    from agent.orchestrator import reachability
    reachability._detect_desktop.cache_clear()
    (tmp_path / "desktop").mkdir(); (tmp_path / "desktop" / "package.json").write_text(
        '{"devDependencies":{"electron":"1"}}', encoding="utf-8")
    (tmp_path / "saas").mkdir(); (tmp_path / "saas" / "build.gradle").write_text("plugins {}", encoding="utf-8")
    (tmp_path / "saas" / "Ctrl.java").write_text("class C {}", encoding="utf-8")
    assert reachability.is_desktop_app(str(tmp_path), str(tmp_path / "desktop" / "app.js"))   # desktop module
    assert not reachability.is_desktop_app(str(tmp_path), str(tmp_path / "saas" / "Ctrl.java"))  # web module
