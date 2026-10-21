"""Preflight witness plan: assess what a boot-and-drive witness would TAKE for a route-reached sink (runtime,
entrypoint, deps, external services, cost tier, feasibility) WITHOUT booting anything -- so a heavy monorepo
is surfaced as an opt-in with its cost instead of blind-booted."""
import json
from types import SimpleNamespace

from agent.orchestrator import witness_plan
from agent.orchestrator.report import _witness_line


def _cand(tmp_path, name="server.ts"):
    f = tmp_path / name
    f.write_text("export const x = 1\n", encoding="utf-8")
    return SimpleNamespace(file=str(f), line=1434, unit="", cwe="CWE-78", family="cmd", sink="spawn")


def test_no_route_means_not_needed(tmp_path):
    plan = witness_plan.build_plan(str(tmp_path), _cand(tmp_path), route=None)
    assert plan.needed is False and plan.summary() == ""


def test_bun_server_route_plan_is_ready_when_self_contained(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps(
        {"name": "api", "scripts": {"dev": "bun run src/server.ts"}, "dependencies": {"hono": "^4"}}),
        encoding="utf-8")
    (tmp_path / "bun.lock").write_text("", encoding="utf-8")
    plan = witness_plan.build_plan(str(tmp_path), _cand(tmp_path),
                                   route=("POST", "/session/:id/shell", "hono", ""))
    assert plan.needed and plan.runtime == "bun" and plan.package == "api"
    assert plan.entrypoint == "bun run dev" and plan.route == "POST /session/:id/shell"
    assert plan.services == [] and plan.feasibility == "ready"
    assert "boot api on bun" in plan.summary() and "POST /session/:id/shell" in plan.summary()


def test_external_service_makes_it_underspecified(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps(
        {"name": "api", "scripts": {"start": "node index.js"},
         "dependencies": {"pg": "^8", "express": "^4"}}), encoding="utf-8")
    plan = witness_plan.build_plan(str(tmp_path), _cand(tmp_path), route=("GET", "/u", "express", ""))
    assert plan.feasibility == "underspecified" and "PostgreSQL" in plan.services
    assert any("external service" in r for r in plan.reasons)


def test_missing_entrypoint_is_underspecified(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "lib", "dependencies": {}}), encoding="utf-8")
    plan = witness_plan.build_plan(str(tmp_path), _cand(tmp_path), route=("GET", "/x", "hono", ""))
    assert plan.feasibility == "underspecified"
    assert any("entrypoint" in r or "start script" in r for r in plan.reasons)


def test_heavy_tier_from_many_direct_deps(tmp_path):
    deps = {f"pkg{i}": "^1" for i in range(200)}
    (tmp_path / "package.json").write_text(json.dumps(
        {"name": "big", "scripts": {"start": "node i.js"}, "dependencies": deps}), encoding="utf-8")
    plan = witness_plan.build_plan(str(tmp_path), _cand(tmp_path), route=("GET", "/x", "express", ""))
    assert plan.cost_tier == "heavy" and plan.feasibility == "heavy"
    assert "HEAVY" in plan.summary()


def test_mem_cap_scales_with_tier(monkeypatch):
    monkeypatch.delenv("WAVE_BOOT_MEMORY", raising=False)
    assert (witness_plan.mem_for_tier("light"), witness_plan.mem_for_tier("medium"),
            witness_plan.mem_for_tier("heavy")) == ("1g", "2g", "4g")
    monkeypatch.setenv("WAVE_BOOT_MEMORY", "8g")
    assert witness_plan.mem_for_tier("heavy") == "8g"           # explicit override wins


def test_size_dominates_tier_over_count():
    # bun's node_modules shows few top-level entries for gigabytes -> size must drive the tier
    assert witness_plan._cost_tier(modules_count=11, direct_deps=20, modules_mb=1525) == "heavy"
    assert witness_plan._cost_tier(modules_count=11, direct_deps=20, modules_mb=0) == "light"


def test_workspace_root_is_the_lockfile_root_not_a_symlink_farm(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "bun.lock").write_text("", encoding="utf-8")         # install root marker
    (repo / "node_modules").mkdir()                              # the real (hoisted) deps
    pkg = repo / "packages" / "opencode"
    (pkg / "node_modules").mkdir(parents=True)                   # a package's symlink farm (must NOT win)
    (pkg / "package.json").write_text('{"name":"opencode"}', encoding="utf-8")
    src = pkg / "src"
    src.mkdir()
    root, sub = witness_plan.workspace_root(str(src))
    assert root.resolve() == repo.resolve() and sub == "packages/opencode"


def test_project_footprint_measures_storage_and_caps_memory(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "bun.lock").write_text("", encoding="utf-8")
    nm = repo / "node_modules" / "big"
    nm.mkdir(parents=True)
    (nm / "blob.bin").write_bytes(b"x" * (2 * 1024 * 1024))      # 2 MB of deps
    (repo / "package.json").write_text('{"name":"api","scripts":{"start":"bun run s.ts"}}', encoding="utf-8")
    fp = witness_plan.project_footprint(str(repo))
    assert fp.modules_installed and fp.modules_mb >= 1.5         # measured a real size
    assert fp.mem_cap in ("1g", "2g", "4g") and fp.free_disk_gb >= 0
    assert "node_modules" in fp.line() and "memory cap" in fp.line()


def test_report_renders_from_the_persisted_dict(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps(
        {"name": "api", "scripts": {"dev": "bun run s.ts"}, "dependencies": {"hono": "^4"}}), encoding="utf-8")
    (tmp_path / "bun.lock").write_text("", encoding="utf-8")
    plan = witness_plan.build_plan(str(tmp_path), _cand(tmp_path), route=("POST", "/shell", "hono", ""))
    line = _witness_line(plan.as_dict())           # the report reads the persisted dict, not the object
    assert "boot api on bun" in line and "POST /shell" in line
