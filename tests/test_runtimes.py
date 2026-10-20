"""Adaptive capability provisioning: the sandbox learns WHICH runtime a project needs from a data table,
not a hard-coded branch -- so a non-Node JS stack (the opencode/Bun miss) can be provisioned + run. Also
the strict-HOW floor: only a registry (trusted) image is ever provisionable, and a model's runtime
nomination is cross-checked against detection."""
from pathlib import Path

import pytest

from agent.orchestrator import runtimes, investigate


# ---------------------------------------- detection (data-driven) -----------------------------------------

def test_bun_detected_by_lockfile(tmp_path):
    (tmp_path / "bun.lockb").write_text("", encoding="utf-8")
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")   # node manifest also present...
    assert runtimes.detect(str(tmp_path)).name == "bun"              # ...but the bun lockfile wins (more specific)


def test_bun_detected_by_source_signal_when_lockfile_is_at_unscanned_root(tmp_path):
    # the scoped-subdir case: no manifest under the scan target, but the source uses Bun.* APIs
    sub = tmp_path / "packages" / "app" / "src"
    sub.mkdir(parents=True)
    (sub / "server.ts").write_text("const p = Bun.spawn(['echo','hi'])\n", encoding="utf-8")
    assert runtimes.detect(str(sub)).name == "bun"


def test_deno_detected(tmp_path):
    (tmp_path / "deno.json").write_text("{}", encoding="utf-8")
    assert runtimes.detect(str(tmp_path)).name == "deno"


def test_node_detected_from_package_json(tmp_path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    assert runtimes.detect(str(tmp_path)).name == "node"


def test_python_detected(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    assert runtimes.detect(str(tmp_path)).name == "python"


def test_no_signal_returns_none(tmp_path):
    (tmp_path / "README.md").write_text("hi", encoding="utf-8")
    assert runtimes.detect(str(tmp_path)) is None


def test_manifest_found_up_at_repo_root(tmp_path):
    (tmp_path / "bun.lock").write_text("", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    deep = tmp_path / "packages" / "x"
    deep.mkdir(parents=True)
    assert runtimes.detect(str(deep)).name == "bun"     # walks up to the manifest at the repo root


# ---------------------------------------- the trusted-image policy ----------------------------------------

def test_registry_images_are_trusted():
    for r in runtimes.REGISTRY:
        assert runtimes.is_trusted_image(r.image)

def test_trusted_is_tag_insensitive():
    assert runtimes.is_trusted_image("oven/bun:1.1.30")   # a trusted repo at any tag

def test_arbitrary_image_is_untrusted():
    assert not runtimes.is_trusted_image("attacker/evil:latest")
    assert not runtimes.is_trusted_image("")

def test_by_name_and_runtime_for_image():
    assert runtimes.by_name("BUN").name == "bun"          # case-insensitive
    assert runtimes.by_name("nope") is None
    assert runtimes.runtime_for_image("oven/bun:1").name == "bun"


# ---------------------------------------- the model's provisioning action ---------------------------------

def _state():
    return {"installs": 0, "budget": 6, "done": set()}

def test_unknown_runtime_is_rejected(tmp_path):
    msg = investigate._do_provision_runtime("rust", target=str(tmp_path), deps=None, state=_state(), image="x")
    assert "unknown runtime" in msg.lower() and "bun" in msg.lower()   # lists the provisionable set

def test_nomination_mismatch_is_rejected(tmp_path):
    # the project clearly auto-detects as python, so a 'bun' request is suspect -> blocked (reject-only gate)
    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    msg = investigate._do_provision_runtime("bun", target=str(tmp_path), deps=None, state=_state(), image="x")
    assert "not confirmed" in msg.lower() and "python" in msg.lower()

def test_known_runtime_provisions_via_trusted_image(tmp_path, monkeypatch):
    (tmp_path / "bun.lock").write_text("", encoding="utf-8")           # detection agrees -> passes the gate
    pulled = {}
    monkeypatch.setattr("agent.orchestrator.js_env.ensure_image", lambda img: pulled.setdefault("img", img) or img)
    monkeypatch.setattr("agent.orchestrator.js_env.ensure_runtime_deps", lambda t, rt: True)
    st = _state()
    msg = investigate._do_provision_runtime("bun", target=str(tmp_path), deps=None, state=st, image="node:20-slim")
    assert pulled["img"] == "oven/bun:1"                  # provisioned the registry's trusted bun image
    assert "oven/bun:1" in msg and "run_command" in msg  # tells the model how to re-run
    assert "bun" in st["done"]

def test_budget_caps_provisioning(tmp_path):
    (tmp_path / "bun.lock").write_text("", encoding="utf-8")
    st = {"installs": 6, "budget": 6, "done": set()}
    msg = investigate._do_provision_runtime("bun", target=str(tmp_path), deps=None, state=st, image="x")
    assert "budget" in msg.lower()

def test_dep_kind_follows_the_runtime_image():
    assert investigate._dep_kind_for("oven/bun:1") == "js"
    assert investigate._dep_kind_for("python:3.12-slim") == "py"
