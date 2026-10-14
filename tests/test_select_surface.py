"""Surface selection: Tier-1 (test-filename deprioritization) + Tier-2 (reachability ranking + partial-scan
drop of low-priority files), and the detector-stage drop of low-priority findings on a partial scan."""
import json
from pathlib import Path

import pytest

from agent.orchestrator import detector, repomap, select
from agent.orchestrator.repomap import is_low_priority_path as lp


# ---- Tier 1: colocated test/fixture files are low-priority by NAMING, not just by directory ----
@pytest.mark.parametrize("path,expected", [
    ("src/data/bundledJson.test.mjs", True),
    ("src/standalone/startupChrome.test.mjs", True),
    ("src/foo.spec.ts", True),
    ("pkg/foo_test.py", True),
    ("pkg/foo-test.js", True),
    ("tests/test_users.py", True),            # leading test_ (and a test dir)
    ("src/Button.stories.tsx", True),
    ("conftest.py", True),
    ("scripts/deploy.sh", True),              # existing: shell
    # NOT low-priority -- real app files whose name merely contains the letters test/spec
    ("src/providers/cctv.js", False),
    ("server/providers/cctv/media.js", False),
    ("src/latest.js", False),
    ("src/contest.js", False),
    ("pkg/fastest_run.py", False),
    ("src/specialist.js", False),
])
def test_tier1_test_filename_detection(path, expected):
    assert lp(path) is expected


# ---- the direct-request-access entry signal (undecorated handlers) ----
@pytest.mark.parametrize("src,expected", [
    ("const u = new URL(req.url, 'http://x'); const id = u.searchParams.get('id')", True),
    ("const id = req.query.id", True),
    ("name = request.args.get('q')", True),                 # flask
    ("const v = incoming.searchParams.get('lat')", True),
    ("id := c.Query(\"id\")", True),                        # gin
    ("const x = $_GET['id'];", True),                       # php
    ("const r = await fetch('https://fixed.example/path')", False),  # fixed outbound, not an entry
    ("const total = a + b", False),
])
def test_request_access_signal(src, expected):
    assert select.reads_request(src) is expected


# ---- Tier 2: end-to-end selection on a tiny real repo (tree-sitter) ----
@pytest.fixture
def tiny_repo(tmp_path):
    (tmp_path / "app").mkdir()
    # a real route handler: route decorator + request access + a SQL sink
    (tmp_path / "app" / "routes.js").write_text(
        "const app = require('express')();\n"
        "app.get('/user', (req, res) => {\n"
        "  const id = req.query.id;\n"
        "  db.query('SELECT * FROM users WHERE id = ' + id);\n"
        "});\n", encoding="utf-8")
    # a colocated TEST file full of fixture sinks (fetch + eval) -- the noise we must drop
    (tmp_path / "app" / "util.test.mjs").write_text(
        "const r = await fetch('http://fixture.local/x');\n"
        "eval(fixturePayload);\n", encoding="utf-8")
    # a plain server util with a sink but NO entry -- must be KEPT (conservative), ranked below the route
    (tmp_path / "app" / "helper.js").write_text(
        "const cp = require('child_process');\n"
        "function runIt(cmd) { cp.exec(cmd); }\n", encoding="utf-8")
    return tmp_path


def _rel(p):
    return Path(p).as_posix().split("/app/")[-1]


def test_partition_drops_tests_on_partial_keeps_on_allfiles(tiny_repo, tmp_path):
    res = repomap.build_map(str(tiny_repo), out=str(tmp_path / "map.md"))
    cmap, per_file, pinned = res["cmap"], res["per_file"], res["pinned"]
    rels = {_rel(p) for p in pinned}
    assert {"routes.js", "util.test.mjs", "helper.js"} <= rels, f"all three should pin; got {rels}"

    kept, dropped = select.partition_surface(cmap, per_file, pinned, partial=True)
    kept_rel, dropped_rel = [_rel(p) for p in kept], [_rel(p) for p in dropped]
    # the test fixture file is dropped; real code is kept
    assert "util.test.mjs" in dropped_rel
    assert "routes.js" in kept_rel and "helper.js" in kept_rel
    # the entry-bearing route ranks ABOVE the entry-less util
    assert kept_rel.index("routes.js") < kept_rel.index("helper.js")

    # --all-files keeps everything (completeness contract)
    kept_all, dropped_all = select.partition_surface(cmap, per_file, pinned, partial=False)
    assert dropped_all == []
    assert "util.test.mjs" in [_rel(p) for p in kept_all]


# ---- detector stage: low-priority findings dropped on a partial scan, kept on --all-files ----
def test_detector_load_findings_drops_low_priority(tiny_repo, tmp_path):
    nb = tmp_path / "wave_notebook.jsonl"
    nb.write_text("\n".join(json.dumps(x) for x in [
        {"file": "app/routes.js", "findings": [{"line": 4, "class": "sqli", "sink": "db.query", "confidence": "high"}]},
        {"file": "app/util.test.mjs", "findings": [{"line": 2, "class": "eval", "sink": "eval(", "confidence": "high"}]},
    ]) + "\n", encoding="utf-8")

    partial = detector._load_findings(str(nb), root=str(tiny_repo), include_low_priority=False)
    files_partial = {f["file"] for f in partial}
    assert "app/routes.js" in files_partial
    assert "app/util.test.mjs" not in files_partial, "a test-file finding must not reach Stage 2 on a partial scan"

    full = detector._load_findings(str(nb), root=str(tiny_repo), include_low_priority=True)
    assert "app/util.test.mjs" in {f["file"] for f in full}


def test_codemap_pins_respects_low_priority(tiny_repo):
    pins_partial = detector._codemap_pins(str(tiny_repo), include_low_priority=False)
    assert all(".test." not in f["file"] for f in pins_partial)
    pins_full = detector._codemap_pins(str(tiny_repo), include_low_priority=True)
    assert any(".test." in f["file"] for f in pins_full)


# ---- shell parallelism: fan out on a cloud model, serial on a local one ----
def test_model_jobs_cloud_vs_local(monkeypatch):
    from agent.orchestrator import parallel, shell
    monkeypatch.setattr(parallel, "is_cloud_model", lambda m: True)
    assert shell._model_jobs(4) == 4
    monkeypatch.setattr(parallel, "is_cloud_model", lambda m: False)
    assert shell._model_jobs(4) == 1
