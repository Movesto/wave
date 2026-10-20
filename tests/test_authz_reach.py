"""reach x guard composition (authzcov): a remote route that reaches a high-severity sink with NO auth
guard on the path is raised as a needs-review CWE-306 lead -- the opencode `/session/:id/shell` -> spawn
shape that injection detection reports only as 'CWE-78 injection', never as 'and it's unauthenticated'.

The dangerous direction is crying wolf on a guarded route, so the negatives matter as much as the hit:
an authed route, a locally-reached (non-remote) sink, and no-cmap must all stay silent."""
from pathlib import Path

from agent.orchestrator import repomap, authzcov, controls


def _build(tmp_path):
    (tmp_path / "worker.py").write_text(
        "import os, subprocess\n"
        "def run_job(cmd):\n"
        "    os.system(cmd)\n"                       # cmd sink, reached from an UNAUTHED route
        "    return 'ok'\n"
        "def run_job2(cmd):\n"
        "    subprocess.call(cmd, shell=True)\n"     # cmd sink, reached only from an AUTHED route
        "    return 'ok'\n"
        "def offline_job(cmd):\n"
        "    os.system(cmd)\n",                      # cmd sink, reached only from main() (local, not remote)
        encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\n"
        "from worker import run_job, run_job2, offline_job\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/run', methods=['POST'])\n"
        "def run_handler():\n"
        "    return run_job(request.json['cmd'])\n"
        "\n"
        "@app.route('/admin', methods=['POST'])\n"
        "def admin_handler():\n"
        "    require_auth(request)\n"               # an auth signal on THIS route -> must clear it
        "    return run_job2(request.json['cmd'])\n"
        "\n"
        "def main():\n"
        "    offline_job('ls')\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8")
    res = repomap.build_map(str(tmp_path), out=str(tmp_path / "map.md"))
    return res["cmap"], res["per_file"]


def test_unauthenticated_exec_route_is_flagged(tmp_path):
    cmap, per_file = _build(tmp_path)
    findings = authzcov.scan(str(tmp_path), cmap, per_file)
    handlers = {f["title"].split("(")[-1].rstrip(")") for f in findings}
    assert "run_handler" in handlers, f"the unauthed /run route reaching os.system must be flagged: {findings}"


def test_authed_route_is_not_flagged(tmp_path):
    cmap, per_file = _build(tmp_path)
    findings = authzcov.scan(str(tmp_path), cmap, per_file)
    handlers = {f["title"].split("(")[-1].rstrip(")") for f in findings}
    assert "admin_handler" not in handlers, "a route with an auth check must NOT be flagged (safe direction)"


def test_local_only_sink_is_not_flagged(tmp_path):
    cmap, per_file = _build(tmp_path)
    findings = authzcov.scan(str(tmp_path), cmap, per_file)
    handlers = {f["title"].split("(")[-1].rstrip(")") for f in findings}
    assert "main" not in handlers and "offline_job" not in handlers, "a main()-only sink is not remote-reachable"


def test_findings_are_review_tier_cwe_306(tmp_path):
    cmap, per_file = _build(tmp_path)
    findings = authzcov.scan(str(tmp_path), cmap, per_file)
    hit = [f for f in findings if "run_handler" in f["title"]]
    assert hit and hit[0]["cwe"] == "CWE-306" and hit[0]["control"] == "unauth-exec"
    assert "CAVEAT" in hit[0]["detail"]              # states the framework-unaware-auth caveat


def test_controls_runs_authzcov_only_with_cmap(tmp_path):
    cmap, per_file = _build(tmp_path)
    with_graph = controls.scan(str(tmp_path), cmap=cmap, per_file=per_file)
    without = controls.scan(str(tmp_path))           # no call graph -> the reach rule can't run
    assert any(f.get("control") == "unauth-exec" for f in with_graph)
    assert not any(f.get("control") == "unauth-exec" for f in without)


def test_scan_is_safe_without_cmap():
    assert authzcov.scan("nonexistent", None, None) == []
