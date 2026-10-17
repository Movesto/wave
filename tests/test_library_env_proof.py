"""Fix 1 (non-web proof env): a canary can prove a LIBRARY/CLI sink out-of-process via a venv built from
the target's own manifest -- no server, no compose. We don't pip-install a real dep here (slow/networked);
instead we point the "venv python" at the current interpreter and drive a path-traversal sink, which
exercises the exact same driver + observer path a real library takes. Also covers the manifest gate and the
dotted-name helper that lets the driver import by name (so the target's relative imports resolve)."""
import sys
import types
from pathlib import Path

from agent.orchestrator import provision, rung1


def _cand(file, unit, cwe):
    c = types.SimpleNamespace()
    c.file, c.unit, c.cwe = str(file), unit, cwe
    return c


def test_dotted_name_from_src_layout(tmp_path):
    root = tmp_path / "src"
    (root / "pkg").mkdir(parents=True)
    f = root / "pkg" / "http.py"
    f.write_text("x = 1\n", encoding="utf-8")
    assert rung1._dotted_name(str(f), str(root)) == "pkg.http"
    assert rung1._dotted_name(str(root / "pkg" / "__init__.py"), str(root)) == "pkg"
    assert rung1._dotted_name(str(f), str(tmp_path / "elsewhere")) == ""   # not under root


def test_venv_executor_proves_a_library_path_sink(tmp_path):
    # a standalone library module (no package, no web server) with an unsanitized file-open sink
    mod = tmp_path / "vuln_lib.py"
    mod.write_text("def load(p):\n    return open(p)\n", encoding="utf-8")
    venv = provision.LibraryEnv(python=sys.executable, note="test", root=str(tmp_path))
    c = _cand(mod, "load(p)", "CWE-22")
    payload, marker = rung1._payload("CWE-22")
    obs = rung1.PythonVenvExecutor().run(c, payload, venv)
    assert obs.ran, f"driver did not run: {obs.error}"
    assert any(kind == "path" and marker in text for kind, text, _ in obs.sink_hits), obs.sink_hits


def test_micro_exec_falls_back_to_venv_when_given(tmp_path):
    mod = tmp_path / "vuln_lib2.py"
    mod.write_text("def load(p):\n    return open(p)\n", encoding="utf-8")
    venv = provision.LibraryEnv(python=sys.executable, note="test", root=str(tmp_path))
    c = _cand(mod, "load(p)", "CWE-22")
    # in-process import of this module would succeed too, but the point is the venv path yields a verdict
    mr = rung1.micro_exec(c, rt=None, venv=venv)
    assert mr.verdict == "proven", f"{mr.verdict}: {mr.reason}"


def test_not_ready_venv_is_ignored(tmp_path):
    mod = tmp_path / "vuln_lib3.py"
    mod.write_text("def load(p):\n    return open(p)\n", encoding="utf-8")
    c = _cand(mod, "load(p)", "CWE-22")
    obs = rung1.PythonVenvExecutor().run(c, rung1._payload("CWE-22")[0], provision.LibraryEnv())
    assert not obs.ran and "no library venv" in obs.error


def test_manifest_gate(tmp_path):
    assert not provision.has_py_manifest(str(tmp_path))
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    assert provision.has_py_manifest(str(tmp_path))
    # no manifest -> library_env returns None (nothing to build)
    assert provision.library_env(str(tmp_path / "nope")) is None


def test_library_deps_gated_on_manifest(tmp_path):
    # no manifest -> None, WITHOUT ever touching docker/network
    assert provision.library_deps(str(tmp_path / "no-such-dir")) is None


def test_seed_deps_refuses_without_manifest(tmp_path):
    # seed_deps must NOT run pip for a target that has no manifest (exit != 0, no network)
    from agent.orchestrator import execute
    r = execute.seed_deps(str(tmp_path), deps=str(tmp_path / "deps"))
    assert r.exit_code != 0
