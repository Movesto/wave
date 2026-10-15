"""The request-context gate (self-trigger hardening). The always-on eval/exec/fs/ssrf wraps must NOT
forge a tape-grade confirm out of code the model ran DIRECTLY in the sandbox: a sink reached outside a
served HTTP request logs the BARE token (which oracle.scan ignores); only a sink reached THROUGH the
app's request path seals with the per-run secret. These prove the gate end-to-end without a full boot.
"""
import importlib.util
import shutil
import subprocess
import sys
import types
from pathlib import Path

import pytest

from agent.orchestrator import oracle, registry


def _exec_ctx_py(tmp_path, secret, monkeypatch, fake_modules=None):
    """Load the Python gate module from its registry source, with WAVE_WITNESS set and optional fake
    framework modules installed first (so its wrap try-blocks pick them up)."""
    for name, mod in (fake_modules or {}).items():
        monkeypatch.setitem(sys.modules, name, mod)
    monkeypatch.setenv("WAVE_WITNESS", secret)
    f = tmp_path / "_wave_sink_ctx.py"
    f.write_text(registry.context_module("py").code, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("_wave_ctx_under_test", f)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_py_gate_seals_only_inside_a_request(tmp_path, monkeypatch):
    ctx = _exec_ctx_py(tmp_path, "sekret", monkeypatch)
    # OUTSIDE a served request -> BARE token (a model-written driver calling the sink directly)
    assert ctx.in_request() is False
    assert ctx.seal("WAVE-SINK-EVAL") == "WAVE-SINK-EVAL"
    # INSIDE a request -> SEALED with the per-run secret (the only form the oracle counts)
    tok = ctx._in_req.set(True)
    try:
        assert ctx.in_request() is True
        assert ctx.seal("WAVE-SINK-EVAL") == "WAVE-SINK-EVAL#sekret"
    finally:
        ctx._in_req.reset(tok)
    assert ctx.seal("WAVE-SINK-EVAL") == "WAVE-SINK-EVAL"   # reset -> bare again


def test_py_gate_wraps_the_flask_per_request_entry(tmp_path, monkeypatch):
    seen = {}
    ref = {}

    class _FakeFlask:
        def wsgi_app(self, environ, start_response):
            seen["in_request"] = ref["ctx"].in_request()
            seen["sealed"] = ref["ctx"].seal("WAVE-SINK-PATH")
            return ["ok"]

    fake = types.ModuleType("flask")
    fake.Flask = _FakeFlask
    ctx = _exec_ctx_py(tmp_path, "s3", monkeypatch, fake_modules={"flask": fake})
    ref["ctx"] = ctx

    assert getattr(_FakeFlask.wsgi_app, "__wave", False) is True   # gate replaced the WSGI entry
    assert ctx.in_request() is False
    _FakeFlask().wsgi_app({}, lambda *a: None)                     # server serves one request
    assert seen["in_request"] is True                              # the view ran WITH request context
    assert seen["sealed"] == "WAVE-SINK-PATH#s3"                   # a sink there seals -> counts
    assert ctx.in_request() is False                               # context cleared after the response


def test_gate_output_is_what_the_oracle_counts():
    """The gate's two forms, graded by the real oracle: a self-triggered (bare) marker is NOT a witness;
    a request-reached (sealed) marker IS -- even with the SAME secret in scope."""
    assert oracle.scan("WAVE-SINK-EVAL:: payload", "sekret") == set()                 # bare -> ignored
    assert oracle.scan("WAVE-SINK-EVAL#sekret:: payload", "sekret") == {"WAVE-SINK-EVAL"}
    # 1b reach tape: the tracer on a BARE line does not prove reach; on a SEALED line it does.
    assert oracle.reach_in_sink("WAVE-SINK-EVAL:: WAVEREACH9", "sekret", "WAVEREACH9") is False
    assert oracle.reach_in_sink("WAVE-SINK-EVAL#sekret:: WAVEREACH9", "sekret", "WAVEREACH9") is True


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_js_gate_end_to_end_direct_vs_served(tmp_path, monkeypatch):
    """Real node: a direct eval (no request) logs BARE; an eval reached through a served HTTP request
    logs SEALED. This is the self-trigger hole closed, proven in the actual runtime."""
    hdir = tmp_path / "hooks"
    hdir.mkdir()
    for m in (registry.context_module("js"), *[h for h in registry.HOOKS if h.name == "js_eval"]):
        (hdir / m.filename).write_text(m.code, encoding="utf-8")
    script = tmp_path / "drive.js"
    script.write_text(
        'const http = require("http");\n'
        'eval("1+1");\n'                                           # DIRECT -> outside any request
        'const srv = http.createServer((req, res) => { eval("2+2"); res.end("ok"); });\n'  # SERVED
        'srv.listen(0, () => {\n'
        '  const port = srv.address().port;\n'
        '  http.get("http://127.0.0.1:" + port + "/", (r) => {\n'
        '    r.on("data", () => {}); r.on("end", () => srv.close(() => process.exit(0)));\n'
        '  });\n'
        '});\n', encoding="utf-8")
    monkeypatch.setenv("WAVE_WITNESS", "sekret")
    r = subprocess.run(
        ["node", "--require", str(hdir / "_wave_sink_ctx.js"),
         "--require", str(hdir / "_wave_sink_eval.js"), str(script)],
        capture_output=True, text=True, timeout=30)
    out = r.stdout + r.stderr
    assert "WAVE-SINK-EVAL:: 1+1" in out                           # direct self-trigger -> BARE
    assert "WAVE-SINK-EVAL#sekret:: 2+2" in out                    # reached via a served request -> SEALED
    assert "WAVE-SINK-EVAL#sekret:: 1+1" not in out                # the direct one never seals
    assert oracle.scan(out, "sekret") == {"WAVE-SINK-EVAL"}        # only the served hit is counted
