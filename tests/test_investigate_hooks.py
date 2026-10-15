"""Hook-in-investigate-sandbox follow-on: the piece that makes a GREEN tape-grade confirm reachable from
the investigate path (and so from `/sast`), not only from a whole-app `--dynamic`/bench boot.

  - provision.sink_hook_env writes the matching SEALED hooks to a THROWAWAY dir (NOT the target tree, so no
    scan stage ever mistakes wave's own instrumentation for target source) and returns the env that
    auto-loads them in the sandbox (NODE_OPTIONS for JS, a sitecustomize on PYTHONPATH for PY).
  - execute bind-mounts that dir read-only at /wave_hooks and merges PYTHONPATH/NODE_PATH so the hooks load
    AND the app's / installed modules still resolve.
"""
import shutil
from pathlib import Path

from agent.orchestrator import provision


def test_sink_hook_env_js_writes_to_throwaway_dir_not_the_target(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"express":"4","node-serialize":"0"}}',
                                           encoding="utf-8")
    env, hdir = provision.sink_hook_env(str(tmp_path), is_js=True)
    try:
        # the hooks live OUTSIDE the scanned target -- nothing written into tmp_path
        assert hdir is not None and Path(hdir).resolve() != tmp_path.resolve()
        assert not (tmp_path / ".wave_hooks").exists()
        for f in ("_wave_sink_eval.js", "_wave_sink_shell.js", "_wave_sink_fs.js", "_wave_sink_ssrf.js",
                  "_wave_sink_deser.js"):                      # core sinks + node-serialize (dep present)
            assert (Path(hdir) / f).exists(), f
        assert "NODE_OPTIONS" in env and "PYTHONPATH" not in env
        for f in ("_wave_sink_eval.js", "_wave_sink_deser.js"):
            assert f"--require /wave_hooks/{f}" in env["NODE_OPTIONS"]
        # the SECRET is read at runtime from the env, never baked into the file
        assert "process.env.WAVE_WITNESS" in (Path(hdir) / "_wave_sink_eval.js").read_text(encoding="utf-8")
    finally:
        shutil.rmtree(hdir, ignore_errors=True)


def test_sink_hook_env_py_writes_sitecustomize_and_pythonpath(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask\npsycopg2-binary\njinja2\n", encoding="utf-8")
    env, hdir = provision.sink_hook_env(str(tmp_path), is_js=False)
    try:
        assert env == {"PYTHONPATH": "/wave_hooks"}
        sc = (Path(hdir) / "sitecustomize.py").read_text(encoding="utf-8")
        for mod in ("_wave_sink_audit", "_wave_sink_fs", "_wave_sink_ssrf", "_wave_sink_psycopg2", "_wave_sink_jinja"):
            assert (Path(hdir) / (mod + ".py")).exists(), mod
            assert f"import {mod}" in sc
        assert 'os.environ["WAVE_WITNESS"]' in (Path(hdir) / "_wave_sink_audit.py").read_text(encoding="utf-8")
    finally:
        shutil.rmtree(hdir, ignore_errors=True)


def test_execute_mounts_hooks_readonly_and_puts_app_node_modules_on_node_path(monkeypatch, tmp_path):
    import agent.orchestrator.execute as ex

    captured = {}

    class _R:
        returncode, stdout, stderr = 0, "", ""

    monkeypatch.setattr(ex.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(ex.subprocess, "run", lambda cmd, **k: captured.setdefault("cmd", cmd) or _R())

    ex.execute("node x.js", image="node:20-slim", mount=str(tmp_path), hooks=str(tmp_path),
               env={"NODE_OPTIONS": "--require /wave_hooks/_wave_sink_eval.js", "WAVE_WITNESS": "sekret"})
    cmd = " ".join(captured["cmd"])
    assert ":/wave_hooks:ro" in cmd                                    # hooks mounted read-only
    assert "NODE_PATH=/work/node_modules" in captured["cmd"]           # driver hooks resolve the app's deps
    assert "NODE_OPTIONS=--require /wave_hooks/_wave_sink_eval.js" in captured["cmd"]
    assert "WAVE_WITNESS=sekret" in captured["cmd"]                    # the seal still rides along


def test_execute_merges_hook_pythonpath_with_the_deps_mount(monkeypatch, tmp_path):
    import agent.orchestrator.execute as ex

    captured = {}

    class _R:
        returncode, stdout, stderr = 0, "", ""

    monkeypatch.setattr(ex.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(ex.subprocess, "run", lambda cmd, **k: captured.setdefault("cmd", cmd) or _R())

    ex.execute("python x.py", mount=str(tmp_path), hooks=str(tmp_path), deps=str(tmp_path),
               env={"PYTHONPATH": "/wave_hooks"})
    assert "PYTHONPATH=/wave_hooks:/wave_deps" in captured["cmd"]       # hooks dir AND deps both importable


def test_execute_deps_pythonpath_unchanged_without_a_caller_value(monkeypatch, tmp_path):
    import agent.orchestrator.execute as ex

    captured = {}

    class _R:
        returncode, stdout, stderr = 0, "", ""

    monkeypatch.setattr(ex.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(ex.subprocess, "run", lambda cmd, **k: captured.setdefault("cmd", cmd) or _R())

    ex.execute("python x.py", mount=str(tmp_path), deps=str(tmp_path))
    assert "PYTHONPATH=/wave_deps" in captured["cmd"]                   # back-compat: deps mount only
