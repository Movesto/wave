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
