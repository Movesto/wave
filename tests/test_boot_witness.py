"""Boot-and-drive witness executor -- the deterministic, Docker-free parts: applicability gate, request
synthesis, port/marker grading, mount-root resolution, and the driver-script brace safety. The live
container path (actually booting a server + driving it) is validated out-of-band against Docker, not here."""
import json
from types import SimpleNamespace

import pytest

from agent.orchestrator import boot_witness, witness_plan


def _plan(tmp_path, runtime="bun", entry="bun run start", feasibility="ready"):
    return SimpleNamespace(needed=True, runtime=runtime, entrypoint=entry, feasibility=feasibility,
                           package="api", as_dict=lambda: {"needed": True})


def _cand(cwe="CWE-78", family="cmd"):
    return SimpleNamespace(file="x/server.ts", line=1, unit="", cwe=cwe, family=family, sink="spawn")


def test_enabled_is_opt_in(monkeypatch):
    monkeypatch.delenv("WAVE_BOOT_WITNESS", raising=False)
    assert boot_witness.enabled() is False
    monkeypatch.setenv("WAVE_BOOT_WITNESS", "1")
    assert boot_witness.enabled() is True


def test_applicable_only_for_exec_route_with_entrypoint(tmp_path):
    assert boot_witness.is_applicable(_cand(), _plan(tmp_path)) is True
    assert boot_witness.is_applicable(_cand(cwe="CWE-89", family="sqli"), _plan(tmp_path)) is False  # not exec
    assert boot_witness.is_applicable(_cand(), _plan(tmp_path, entry="")) is False                   # no entry
    assert boot_witness.is_applicable(_cand(), _plan(tmp_path, runtime="python")) is False            # not JS
    assert boot_witness.is_applicable(_cand(), None) is False


def test_default_request_fills_params_and_injects_on_post():
    spec = boot_witness._default_request(("POST", "/session/:id/shell", "hono", ""), "MK")
    assert spec["method"] == "POST" and spec["path"] == "/session/1/shell"
    body = json.loads(spec["body"])
    assert body["command"] == "; touch /work/MK"            # marker injected into the common exec fields


def test_default_request_omits_body_on_get():
    spec = boot_witness._default_request(("GET", "/x", "hono", ""), "MK")
    assert spec["method"] == "GET" and spec["body"] == ""   # a GET body makes fetch throw


@pytest.mark.parametrize("out,expected", [
    ("WAVE_BOOT: PORT=3000\nWAVE_RESP_STATUS: 200\nWAVE_BOOT: MARKER_PRESENT\n---LOG---\nx", "confirmed"),
    ("WAVE_BOOT: PORT=80\nWAVE_RESP_STATUS: 401\nWAVE_BOOT: MARKER_ABSENT\n---LOG---\nx", "refuted"),
    ("WAVE_BOOT: PORT=80\nWAVE_RESP_STATUS: 200\nWAVE_BOOT: MARKER_ABSENT\n---LOG---\nx", "anomalous_state"),
    ("WAVE_BOOT: NO_PORT\n---LOG---\nboot failed", "blocked"),
    ("WAVE_BOOT: SERVER_EXITED\n---LOG---\ncrash", "blocked"),
])
def test_classify_grades_each_outcome(out, expected):
    assert boot_witness._classify(out, "MK").verdict == expected


def test_classify_confirmed_carries_marker_for_the_confirm_pipeline():
    out = "WAVE_RESP_STATUS: 200\nWAVE_BOOT: MARKER_PRESENT\n---LOG---\nok"
    res = boot_witness._classify(out, "MK")
    assert res.verdict == "confirmed" and res.marker == "boot:/work/MK" and res.status == 200


def test_classify_names_an_offline_startup_fetch_as_the_blocker():
    # the opencode case: the server fetches models.dev at boot; offline (--network none) it crashes before
    # binding a port. The blocked reason must SAY so (not "neither marker nor usable response") and name the
    # opt-in -- so the user knows boot ran, why it failed, and how to let it complete.
    out = ("WAVE_BOOT: SERVER_EXITED\n---LOG---\n"
           "TypeError: getaddrinfo EAI_AGAIN models.dev\n  at fetch(\"https://models.dev/api.json\")")
    res = boot_witness._classify(out, "MK")
    assert res.verdict == "blocked"
    assert "models.dev" in res.why and "--network none" in res.why and "WAVE_BOOT_NETWORK" in res.why
    # a crash with no network signature keeps the generic bind-a-port reason
    assert "bind a port" in boot_witness._classify("WAVE_BOOT: NO_PORT\n---LOG---\nOOM killed", "MK").why


def test_render_driver_survives_shell_and_regex_braces():
    # _render_driver uses token replacement, NOT str.format, so `{2,5}` / `${...}` are untouched.
    script = boot_witness._render_driver(sub=".", marker="MK", ep="bun run start", wait=5,
                                         spec='{"path":"/x"}', runner="bun")
    assert "[0-9]{2,5}" in script and "@@" not in script     # regex intact, every token substituted
    assert "bun run start" in script and "/work/MK" in script


def test_boot_root_prefers_node_modules_ancestor(tmp_path):
    root = tmp_path / "repo"
    (root / "node_modules").mkdir(parents=True)
    (root / "package.json").write_text("{}", encoding="utf-8")
    pkg = root / "packages" / "api"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text("{}", encoding="utf-8")
    got_root, sub = boot_witness._boot_root(str(pkg))
    assert got_root.resolve() == root.resolve()              # mount the deps root (monorepo-hoisted)
    assert sub == "packages/api"                             # cd into the actual server package


def test_drive_is_noop_when_not_applicable(tmp_path, monkeypatch):
    monkeypatch.setattr(boot_witness, "available", lambda: True)
    out = boot_witness.drive(str(tmp_path), _cand(cwe="CWE-89", family="sqli"), _plan(tmp_path),
                             image="oven/bun:1", runtime="bun", route=("POST", "/x", "hono", ""))
    assert out is None                                        # non-exec class -> caller keeps its own path


def _monorepo_with_cli(tmp_path):
    """A monorepo whose server package starts the HTTP server via a CLI SUBCOMMAND (the opencode shape)."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "bun.lock").write_text("", encoding="utf-8")
    pkg = repo / "packages" / "api"
    (pkg / "src").mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps(
        {"name": "api", "scripts": {"dev": "bun run ./src/index.ts"}, "bin": {"api": "./bin/api"}}),
        encoding="utf-8")
    (pkg / "src" / "index.ts").write_text(
        "import { ServeCommand } from './cli/serve'\ncli.command(ServeCommand)  // `serve` boots the HTTP server\n",
        encoding="utf-8")
    (pkg / "bin").mkdir()
    (pkg / "bin" / "api").write_text("#!/bin/sh\nexec bun run ./src/index.ts \"$@\"\n", encoding="utf-8")  # shim
    return str(pkg / "src" / "server.ts")


def test_resolve_server_cmd_priority(tmp_path, monkeypatch):
    cand_file = _monorepo_with_cli(tmp_path)
    plan = SimpleNamespace(entrypoint="bun run dev")
    route = ("POST", "/session/:id/shell", "hono", "")

    class _Model:
        def chat(self, msgs, temperature=0):
            self.saw = msgs[-1]["content"]
            return {"content": '{"cmd":"bun run ./src/index.ts serve --port 4096"}'}
    m = _Model()

    monkeypatch.delenv("WAVE_BOOT_CMD", raising=False)
    cmd, src = boot_witness._resolve_server_cmd(cand_file, plan, route, m)
    assert cmd == "bun run ./src/index.ts serve --port 4096" and src == "model"
    # the model was shown the project's OWN command table (index.ts), not a guess / the bin shim
    assert "ServeCommand" in m.saw and "exec bun run" not in m.saw

    monkeypatch.setenv("WAVE_BOOT_CMD", "bun run ./src/index.ts serve")      # explicit override wins over model
    assert boot_witness._resolve_server_cmd(cand_file, plan, route, m) == ("bun run ./src/index.ts serve",
                                                                           "WAVE_BOOT_CMD")
    monkeypatch.delenv("WAVE_BOOT_CMD", raising=False)
    # no model -> fall back to the preflight's deterministic entrypoint (never invents)
    assert boot_witness._resolve_server_cmd(cand_file, plan, route, None) == ("bun run dev", "preflight")


def test_entry_source_prefers_real_source_over_bin_shim(tmp_path):
    cand_file = _monorepo_with_cli(tmp_path)
    pkg_dir = witness_plan.workspace_root(cand_file)
    root, sub = pkg_dir
    pdir = root / sub
    name, src = boot_witness._entry_source(pdir, witness_plan._read_json(pdir / "package.json"))
    assert name == "index.ts" and "ServeCommand" in src          # the command table, not the bin launcher
