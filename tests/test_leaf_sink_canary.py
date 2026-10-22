"""Fix 2 (non-web unit selection): when the flagged sink is a CALL to a repo-defined leaf function that
lives in another file (the web-handler assumption "the sink's enclosing fn is a simple-input callable"
fails for a library entrypoint), the canary drives that LEAF directly. Also: arg-building omits defaulted
params and never passes *args/**kwargs by name, so a real library leaf is callable from just its target."""
import inspect
import types

from agent.orchestrator import codemap, prove, rung1


def test_call_args_omits_defaults_and_varargs():
    def f(url, headers=None, *args, **kw):   # noqa: ANN001
        return url
    variants = dict((tgt, args) for tgt, args in rung1._call_args(f, "MARK"))
    # url-targeted variant: marker in url, headers (defaulted) omitted, *args/**kw never passed
    assert variants["url"] == {"url": "MARK"}
    # headers-targeted variant: url is required -> benign, headers gets the marker
    assert variants["headers"] == {"url": "", "headers": "MARK"}
    assert "args" not in variants["url"] and "kw" not in variants["url"]


def test_call_args_required_params_still_benign():
    def login(username, password):   # noqa: ANN001
        return username
    variants = dict((tgt, args) for tgt, args in rung1._call_args(login, "MARK"))
    assert variants["username"] == {"username": "MARK", "password": ""}


def _cand(file, unit, sink, cwe):
    c = types.SimpleNamespace()
    c.file, c.unit, c.sink, c.cwe = str(file), unit, sink, cwe
    c.route_hint, c.rank, c.family = "", 6, "path (detector survivor)"
    return c


def test_sink_callee_resolves_to_the_leaf_function(tmp_path):
    (tmp_path / "app.py").write_text(
        "def load(p):\n    return open(p)\n\ndef run(p):\n    return load(p)\n", encoding="utf-8")
    cmap = codemap.build(str(tmp_path))
    c = _cand(tmp_path / "app.py", "run(p)", "load(p)", "CWE-22")
    leaf = prove._sink_callee_candidate(c, cmap, str(tmp_path))
    assert leaf is not None
    assert leaf.unit.split("(")[0] == "load"
    assert leaf.resolved_from == "sink-callee"


def test_method_call_sink_is_not_resolved(tmp_path):
    (tmp_path / "app.py").write_text("def run(p):\n    return p.open()\n", encoding="utf-8")
    cmap = codemap.build(str(tmp_path))
    c = _cand(tmp_path / "app.py", "run(p)", "p.open()", "CWE-22")   # `obj.meth(` -> not a bare repo call
    assert prove._sink_callee_candidate(c, cmap, str(tmp_path)) is None


def test_leaf_candidate_proves_via_canary(tmp_path):
    (tmp_path / "app.py").write_text(
        "def load(p):\n    return open(p)\n\ndef run(p):\n    return load(p)\n", encoding="utf-8")
    cmap = codemap.build(str(tmp_path))
    c = _cand(tmp_path / "app.py", "run(p)", "load(p)", "CWE-22")
    leaf = prove._sink_callee_candidate(c, cmap, str(tmp_path))
    mr = rung1.micro_exec(leaf, rt=None)                      # stdlib-only fixture -> importable in-process
    assert mr.verdict == "proven", f"{mr.verdict}: {mr.reason}"
