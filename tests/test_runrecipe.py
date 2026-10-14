"""Run-recipe detection + the injectable test runner that backs the stronger patch gate (plan §5)."""
import json

from agent.orchestrator import runrecipe


def _mk(tmp_path, files):
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmp_path


def test_detect_node_npm(tmp_path):
    _mk(tmp_path, {
        "package.json": json.dumps({"scripts": {"test": "jest", "build": "tsc", "start": "node ."}}),
        "package-lock.json": "{}"})
    r = runrecipe.detect(str(tmp_path))
    assert r.ecosystem == "node" and r.package_manager == "npm"
    assert r.test == "npm test" and r.build == "npm run build" and r.run == "npm run start"


def test_detect_node_pnpm(tmp_path):
    _mk(tmp_path, {"package.json": json.dumps({"scripts": {"test": "vitest"}}), "pnpm-lock.yaml": ""})
    r = runrecipe.detect(str(tmp_path))
    assert r.package_manager == "pnpm" and r.test == "pnpm test"


def test_detect_python_requirements(tmp_path):
    _mk(tmp_path, {"requirements.txt": "flask\n", "tests/test_x.py": "def test_x(): pass\n"})
    r = runrecipe.detect(str(tmp_path))
    assert r.ecosystem == "python" and r.package_manager == "pip"
    assert r.install == "pip install -r requirements.txt" and r.test == "pytest"


def test_detect_go_and_rust(tmp_path):
    g = _mk(tmp_path / "g", {"go.mod": "module x\n"})
    assert runrecipe.detect(str(g)).test == "go test ./..."
    r = _mk(tmp_path / "r", {"Cargo.toml": "[package]\nname='x'\n"})
    assert runrecipe.detect(str(r)).test == "cargo test"


def test_detect_unknown(tmp_path):
    r = runrecipe.detect(str(_mk(tmp_path, {"readme.txt": "hi"})))
    assert r.ecosystem == "unknown" and r.test == ""


def test_makefile_fills_gaps(tmp_path):
    _mk(tmp_path, {"main.c": "int main(){}", "Makefile": "build:\n\tgcc main.c\ntest:\n\t./a.out\n"})
    r = runrecipe.detect(str(tmp_path))
    assert r.test == "make test"


def test_manifest_wins_over_detection(tmp_path):
    _mk(tmp_path, {"package.json": json.dumps({"scripts": {"test": "jest"}})})
    runrecipe.save_manifest(str(tmp_path), runrecipe.Recipe(ecosystem="python", test="pytest -q"))
    r = runrecipe.load_or_detect(str(tmp_path))
    assert r.ecosystem == "python" and r.test == "pytest -q"   # persisted manifest is source of truth


def test_run_tests_pass_fail_none():
    rec = runrecipe.Recipe(test="pytest")
    assert runrecipe.run_tests(rec, ".", runner=lambda c, cwd, t: (0, "ok"))[0] is True
    passed, note = runrecipe.run_tests(rec, ".", runner=lambda c, cwd, t: (1, "2 failed"))
    assert passed is False and "failed" in note
    assert runrecipe.run_tests(runrecipe.Recipe(test=""), ".")[0] is None   # no test command
