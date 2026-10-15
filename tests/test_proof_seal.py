"""The proof seal (remaining-work 1a): the HARNESS-planted WAVE-SINK-* markers carry a per-run secret so a
cat'd hook / memorized / prompt-injected BARE marker can no longer forge a tape-grade confirm.

Covers: (1) oracle.scan/graded secret semantics, (2) every instrumented sink hook reads $WAVE_WITNESS and
emits the sealed marker (exec'd in a SUBPROCESS -- the Python audit hooks install a process-wide audit hook
that would otherwise pollute the rest of the suite), (3) the secret is threaded prove -> investigate.
"""
import shutil
import subprocess
import sys
from pathlib import Path

from agent.orchestrator import oracle, registry


# --- (1) oracle seal semantics ------------------------------------------------------------------------
def test_sealed_marker_witnesses_bare_does_not():
    S = "deadbeefcafe"
    sealed = "WAVE-SINK-SQL#" + S + ":: 'SELECT * FROM u WHERE id=1'"
    bare = "WAVE-SINK-SQL:: (this came from `cat _wave_sink_pg.js` or memorization)"
    assert oracle.scan(sealed, S) == {"WAVE-SINK-SQL"}
    assert oracle.scan(bare, S) == set()            # the whole point: bare must NOT witness under a secret
    # wrong secret (another run's) must not cross-witness
    assert oracle.scan("WAVE-SINK-SQL#0000:: x", S) == set()


def test_legacy_no_secret_still_matches_bare():
    # the boot-path oracle and isolated callers pass no secret -> unchanged bare behaviour
    assert oracle.scan("WAVE-SINK-SSRF:: http://x") == {"WAVE-SINK-SSRF"}
    assert oracle.scan("WAVE-SINK-SSRF#s:: http://x") == {"WAVE-SINK-SSRF"}   # base token is a substring


def test_model_markers_and_canary_unaffected_by_secret():
    S = "abc123"
    assert "WAVE-PWNED" in oracle.scan("... WAVE-PWNED ...", S)      # model-planted, matched with/without secret
    assert "WAVE_RENDER_CANARY:1" in oracle.scan("WAVE_RENDER_CANARY: 1", S)   # fired canary (its own seal)
    assert oracle.scan("WAVE_RENDER_CANARY: none", S) == set()


def test_graded_consumes_canonical_tokens_from_sealed_scan():
    S = "feedface"
    sealed = "WAVE-SINK-MONGO#" + S + ':: filter={"$where":"x"}'
    assert oracle.graded("nosqli", oracle.scan(sealed, S))[0] is True
    assert oracle.graded("nosqli", oracle.scan(sealed.replace("#" + S, ""), S))[0] is False  # bare -> not witnessed


def test_seal_helper():
    assert oracle.seal("WAVE-SINK-SQL", "x7") == "WAVE-SINK-SQL#x7"
    assert oracle.seal("WAVE-SINK-SQL", "") == "WAVE-SINK-SQL"


# --- (2) every hook seals its marker THROUGH the request-context gate ---------------------------------
def _run_py_hook_marker(code, marker, secret, in_request):
    """Exec a Python hook's source in a FRESH subprocess (keeps its process-wide audit hook out of pytest),
    with the REAL request-context gate importable, and read the marker `_seal(marker)` builds -- optionally
    from inside a simulated served request."""
    import os
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="wave-hooktest-"))
    try:
        (d / "_wave_sink_ctx.py").write_text(registry.context_module("py").code, encoding="utf-8")
        probe = ("import _wave_sink_ctx as _ctx\n"
                 + ("_ctx._in_req.set(True)\n" if in_request else "")
                 + code + "\n"
                 + f"import sys as _s\n_s.stdout.write('MARK=' + _seal({marker!r}) + '\\n')\n")
        (d / "probe.py").write_text(probe, encoding="utf-8")
        env = {"PATH": os.environ.get("PATH", "")}
        if secret:
            env["WAVE_WITNESS"] = secret
        r = subprocess.run([sys.executable, "probe.py"], cwd=str(d),
                           capture_output=True, text=True, env=env, timeout=60)
        for line in (r.stdout or "").splitlines():
            if line.startswith("MARK="):
                return line[len("MARK="):]
        raise AssertionError(f"hook did not report its marker; stderr={r.stderr[:300]}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_every_python_hook_seals_marker_through_the_gate():
    for h in [h for h in registry.HOOKS if h.lang == "py"]:
        compile(h.code, h.filename, "exec")                       # must be syntactically valid
        # no secret -> bare regardless of context (legacy boot path, unchanged)
        assert _run_py_hook_marker(h.code, h.marker, "", in_request=True) == h.marker
        # secret set but OUTSIDE a served request -> BARE (self-trigger defanged: a direct driver can't seal)
        assert _run_py_hook_marker(h.code, h.marker, "sec987", in_request=False) == h.marker
        # secret set and INSIDE a served request -> SEALED (the only form the oracle counts)
        assert _run_py_hook_marker(h.code, h.marker, "sec987", in_request=True) == h.marker + "#sec987"


def test_every_js_hook_builds_sealed_marker_through_the_gate():
    for h in [h for h in registry.HOOKS if h.lang == "js"]:
        assert 'require("./_wave_sink_ctx.js")' in h.code, (h.name, "hook does not load the context gate")
        assert f'_seal("{h.marker}")' in h.code, (h.name, "hook does not seal its marker through the gate")
        assert "process.env.WAVE_WITNESS" in h.code, (h.name, "gate-absent fallback must still read the env")


def test_hooks_do_not_print_bare_marker_literal_in_witness_lines():
    # the witness print must use _WSINK, never the hard literal `WAVE-SINK-X::` (which would be unsealed)
    for h in registry.HOOKS:
        assert f'"{h.marker}:: ' not in h.code and f"'{h.marker}:: " not in h.code, (
            h.name, "a witness line still prints the BARE marker literal instead of the sealed _WSINK")


# --- (3) the secret is threaded through the prover -----------------------------------------------------
def test_prove_generates_and_threads_sink_secret():
    import inspect
    from agent.orchestrator import prove, investigate
    assert "sink_secret" in inspect.signature(investigate.investigate).parameters
    src = inspect.getsource(prove._prove_one)
    assert "sink_secret" in src and "secrets.token_hex" in src
    assert "sink_secret=sink_secret" in src           # actually handed to investigate()


# --- Half-B from the tape (1b) ------------------------------------------------------------------------
def test_reach_in_sink_requires_sealed_marker_and_tracer():
    S, R = "aa11bb22", "WAVEREACHdead"
    # the tracer arriving at a SEALED sink line -> reach witnessed by the tape
    assert oracle.reach_in_sink(f"WAVE-SINK-SQL#{S}:: SELECT ... '{R}' ...", S, R) is True
    # tracer present but the sink line is BARE (cat'd hook / unsealed) -> NOT witnessed
    assert oracle.reach_in_sink(f"WAVE-SINK-SQL:: ... {R} ...", S, R) is False
    # sealed sink fired but WITHOUT the tracer (sink proven, reach not driven from the entry) -> NOT witnessed
    assert oracle.reach_in_sink(f"WAVE-SINK-SQL#{S}:: SELECT 1", S, R) is False
    # tracer and a sealed marker on DIFFERENT lines -> NOT witnessed (must co-occur at the sink)
    assert oracle.reach_in_sink(f"echo {R}\nWAVE-SINK-SQL#{S}:: SELECT 1", S, R) is False
    # no secret / no tracer -> never witnessed
    assert oracle.reach_in_sink(f"WAVE-SINK-SQL:: {R}", "", R) is False
    assert oracle.reach_in_sink(f"WAVE-SINK-SQL#{S}::", S, "") is False


def test_reach_tracer_in_brief_when_reach_id_given():
    from agent.orchestrator import briefs
    reached = briefs._reach_block(("handler", ["entry", "handler", "sink"]), reach_id="WAVEREACHbeef")
    assert "WAVEREACHbeef" in reached and "reach_witnessed" in reached
    # no reach_id -> no tracer line (back-compat: the model's self-assessed flag stays the only signal)
    assert "WAVEREACH" not in briefs._reach_block(("handler", ["entry", "sink"]))
    routed = briefs._route_block(("GET", "/x", "flask", "client.get('/x')"), reach_id="WAVEREACHbeef")
    assert "WAVEREACHbeef" in routed


def test_verdict_carries_reach_tape_default_false():
    from agent.orchestrator import investigate as inv
    assert inv.Verdict("confirmed", "why").reach_tape is False
    assert inv.Verdict("confirmed", "why", reach_tape=True).reach_tape is True
