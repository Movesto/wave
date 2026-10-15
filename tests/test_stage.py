"""Answer-key staging (remaining-work 3): a bench scan runs on a MANIFEST-free copy of the app code, so
the model in the sandbox cannot `cat MANIFEST.json` / a prior wave output and read the answers."""
from pathlib import Path

from agent.bench import stage


def _mk(tmp_path, files):
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmp_path


def test_stage_excludes_answer_key_and_wave_outputs_keeps_app_code(tmp_path):
    src = _mk(tmp_path / "target", {
        "app.py": "print('hi')",
        "requirements.txt": "flask\n",
        "sub/handler.py": "def h(): pass",
        "MANIFEST.json": '{"vulns":[{"cwe":"CWE-89"}]}',       # THE answer key -> must not be copied
        "casefile.json": "{}",                                 # prior run output
        "wave_findings.jsonl": '{"verdict":"confirmed"}\n',     # prior run output
        "WAVE_REPORT.md": "# report",
        "wave.compose.full.yml": "services: {}",               # provisioning artifact
        "_wave_entry.py": "import sys",                        # provisioning artifact
        "_wave_hooks/sitecustomize.py": "pass",                # provisioning artifact dir
        ".wave/environment.json": "{}",                        # wave state dir
        "app.pyc": "x",
    })
    with stage.staged(src) as appdir:
        app = Path(appdir)
        # app code copied
        assert (app / "app.py").exists()
        assert (app / "requirements.txt").exists()
        assert (app / "sub" / "handler.py").exists()
        # answer key + wave artifacts NOT copied
        assert not (app / "MANIFEST.json").exists()
        assert not (app / "casefile.json").exists()
        assert not (app / "wave_findings.jsonl").exists()
        assert not (app / "WAVE_REPORT.md").exists()
        assert not (app / "wave.compose.full.yml").exists()
        assert not (app / "_wave_entry.py").exists()
        assert not (app / "_wave_hooks").exists()
        assert not (app / ".wave").exists()
        assert not (app / "app.pyc").exists()
        staged_root = app.parent
    # auto-cleaned on context exit; the ORIGINAL target is untouched
    assert not staged_root.exists()
    assert (src / "MANIFEST.json").exists()


def test_is_excluded_matrix():
    for name in ("MANIFEST.json", "casefile.json", "wave_detect.jsonl", ".wave", "_wave_sink_pg.js",
                 "Dockerfile.wave", "foo.pyc", "wave.compose.full.yml", "__pycache__"):
        assert stage._is_excluded(name), name
    for name in ("app.py", "package.json", "requirements.txt", "Dockerfile", "docker-compose.yml",
                 "server.js", "manifest.ts"):
        assert not stage._is_excluded(name), name
