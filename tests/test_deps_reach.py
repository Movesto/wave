"""Dependency-CVE reachability regression (deps.py, sast-improvement plan 5). Pure import-matching +
ranking; no network (OSV is never called here).

Run: pytest tests/test_deps_reach.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.orchestrator import deps


# ---- _extract_imports ----

def test_extract_python():
    t = "import requests\nfrom foo.bar import baz\n  import os.path\nfrom . import x\n"
    assert deps._extract_imports(t, "PyPI") == {"requests", "foo", "os"}


def test_extract_npm():
    t = "const a = require('lodash')\nimport x from \"@scope/pkg/sub\"\nimport './local'\nimport y from \"axios/dist\"\n"
    out = deps._extract_imports(t, "npm")
    assert "lodash" in out and "@scope/pkg" in out and "axios" in out and "./local" not in out


def test_extract_rust_and_go():
    assert deps._extract_imports("use serde::Deserialize;\nextern crate libc;\nuse foo_bar;", "crates.io") == \
        {"serde", "libc", "foo_bar"}
    assert deps._extract_imports('import "github.com/foo/bar"\n', "Go") == {"github.com/foo/bar"}


# ---- reach_status (conservative) ----

def test_reach_npm_exact():
    toks = {"npm": {"lodash"}, "PyPI": set(), "crates.io": set(), "Go": set()}
    assert deps.reach_status("lodash", "npm", toks) == "reachable"
    assert deps.reach_status("left-pad", "npm", toks) == "unused"


def test_reach_crates_name_normalizes_dash_to_underscore():
    toks = {"crates.io": {"serde_json"}, "npm": set(), "PyPI": set(), "Go": set()}
    assert deps.reach_status("serde-json", "crates.io", toks) == "reachable"
    assert deps.reach_status("tokio", "crates.io", toks) == "unused"


def test_reach_go_by_path():
    toks = {"Go": {"github.com/foo/bar"}, "npm": set(), "PyPI": set(), "crates.io": set()}
    assert deps.reach_status("github.com/foo/bar", "Go", toks) == "reachable"
    assert deps.reach_status("github.com/x/y", "Go", toks) == "unused"


def test_reach_pypi_is_never_hidden_only_promoted():
    toks = {"PyPI": {"requests"}, "npm": set(), "crates.io": set(), "Go": set()}
    assert deps.reach_status("requests", "PyPI", toks) == "reachable"
    # PyYAML's import name is `yaml`, not `pyyaml` -> we can't confirm absence -> 'unknown', NOT 'unused'
    assert deps.reach_status("PyYAML", "PyPI", toks) == "unknown"


# ---- imported_tokens over a real tree ----

def test_imported_tokens(tmp_path):
    (tmp_path / "app.py").write_text("import requests\nfrom flask import Flask\n", encoding="utf-8")
    (tmp_path / "ui.js").write_text("const _ = require('lodash')\n", encoding="utf-8")
    (tmp_path / "lib.rs").write_text("use serde::Serialize;\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.js").write_text("require('should-be-skipped')\n", encoding="utf-8")
    toks = deps.imported_tokens(str(tmp_path))
    assert "requests" in toks["PyPI"] and "flask" in toks["PyPI"]
    assert "lodash" in toks["npm"] and "should-be-skipped" not in toks["npm"]   # node_modules skipped
    assert "serde" in toks["crates.io"]


# ---- render groups unused last + labels reachable ----

def test_render_promotes_reachable_and_groups_unused():
    findings = [
        {"ecosystem": "npm", "package": "used", "version": "1", "id": "A", "cve": "", "severity": "",
         "fixed": "", "summary": "", "file": "f", "reachable": "reachable"},
        {"ecosystem": "npm", "package": "transitive", "version": "1", "id": "B", "cve": "", "severity": "",
         "fixed": "", "summary": "", "file": "f", "reachable": "unused"},
    ]
    md = deps.render(findings)
    assert "1 in packages the app imports" in md
    assert md.index("used 1") < md.index("Not imported by first-party code")  # reachable shown first
    assert "`[imported]`" in md and "`[not imported]`" in md
