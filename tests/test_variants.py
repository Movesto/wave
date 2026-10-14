"""Variant hunting (variants.py, sast-improvement plan 3). Pure: given a CONFIRMED finding, locate OTHER
repo lines matching the same sink class/shape, excluding already-seen locations. No model, no network.

Run: pytest tests/test_variants.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.orchestrator import variants


def test_finds_sibling_sink_same_class(tmp_path):
    (tmp_path / "a.py").write_text(
        "def f(u):\n    db.session.execute(text(q))\n", encoding="utf-8")   # the confirmed sink
    (tmp_path / "b.py").write_text(
        "def g(x):\n    cursor.execute(sql)\n    y = 1\n", encoding="utf-8")  # a sibling SQLi sink
    confirmed = [{"file": "a.py", "line": 2, "class": "sqli"}]
    seen = {("a.py", 2, "sqli")}
    out = variants.find(confirmed, str(tmp_path), seen)
    hits = {(v["file"].replace("\\", "/"), v["class"]) for v in out}
    assert ("b.py", "sqli") in hits
    assert all(v["confidence"] == "low" and v.get("variant") for v in out)     # leads, never auto-confirm


def test_excludes_already_seen_location(tmp_path):
    (tmp_path / "a.py").write_text(
        "def f(u):\n    cursor.execute(sql)\n", encoding="utf-8")
    confirmed = [{"file": "a.py", "line": 2, "class": "sqli"}]
    seen = {("a.py", 2, "sqli")}
    out = variants.find(confirmed, str(tmp_path), seen)
    assert not any(v["file"].replace("\\", "/") == "a.py" and v["line"] == 2 for v in out)


def test_no_confirmed_is_quiet(tmp_path):
    (tmp_path / "a.py").write_text("cursor.execute(sql)\n", encoding="utf-8")
    assert variants.find([], str(tmp_path), set()) == []
    assert variants.find([{"file": "x", "line": 1}], str(tmp_path), set()) == []   # no class -> quiet


def test_cap_is_respected(tmp_path):
    (tmp_path / "a.py").write_text("\n".join(["cursor.execute(q)"] * 50) + "\n", encoding="utf-8")
    out = variants.find([{"file": "z.py", "line": 1, "class": "sqli"}], str(tmp_path), set(), cap=5)
    assert len(out) == 5


def test_skips_vendor_dirs(tmp_path):
    vend = tmp_path / "node_modules" / "pkg"
    vend.mkdir(parents=True)
    (vend / "a.py").write_text("cursor.execute(sql)\n", encoding="utf-8")
    assert variants.find([{"file": "z.py", "line": 1, "class": "sqli"}], str(tmp_path), set()) == []
