"""Scoreboard funnel math: stage counts vs MANIFEST ground truth, safe-twin false-confirm detection,
and the flaky-verdict diff -- all offline (synthetic wave_*.jsonl, no model)."""
import json

from agent.bench import scoreboard as sb


def _write(d, name, rows):
    (d / name).write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def _vuln_target(tmp_path):
    d = tmp_path / "vt"
    d.mkdir()
    (d / "MANIFEST.json").write_text(json.dumps({
        "name": "vt", "stack": "py",
        "vulns": [{"cwe": "CWE-89"}, {"cwe": "CWE-918"}, {"cwe": "CWE-22"}]}), encoding="utf-8")
    # notebook saw sqli + ssrf (not path); candidates kept sqli + ssrf; findings: sqli CONFIRMED, ssrf refuted,
    # plus a bogus CONFIRMED cmd (not a real bug -> a false positive)
    _write(d, "wave_notebook.jsonl", [
        {"file": "a.py", "findings": [{"line": 1, "class": "sqli"}, {"line": 2, "class": "ssrf"}]}])
    _write(d, "wave_candidates.jsonl", [
        {"file": "a.py", "line": 1, "class": "sqli"}, {"file": "a.py", "line": 2, "class": "ssrf"}])
    _write(d, "wave_findings.jsonl", [
        {"file": "a.py", "line": 1, "class": "sqli", "cwe": "CWE-89", "verdict": "confirmed"},
        {"file": "a.py", "line": 2, "class": "ssrf", "cwe": "CWE-918", "verdict": "refuted"},
        {"file": "b.py", "line": 9, "class": "cmd", "cwe": "CWE-78", "verdict": "confirmed"}])
    return d


def test_funnel_counts(tmp_path):
    r = sb.score_target(_vuln_target(tmp_path), pins=False)
    assert r["real"] == 3
    f = r["funnel"]
    assert f["pinned"] is None            # pins=False
    assert f["notebook"] == 2             # sqli + ssrf of the 3 real
    assert f["survived"] == 2
    assert f["reached_prove"] == 2        # sqli + ssrf appear in findings (any verdict)
    assert f["confirmed"] == 1            # only sqli confirmed among the real bugs
    assert r["fp_confirmed"] == 1         # the bogus confirmed cmd is not a real bug


def test_safe_twin_any_confirm_is_fp(tmp_path):
    d = tmp_path / "safe"
    d.mkdir()
    (d / "MANIFEST.json").write_text(json.dumps({"name": "safe", "safe": True, "vulns": []}), encoding="utf-8")
    _write(d, "wave_findings.jsonl", [
        {"file": "x.py", "line": 3, "class": "sqli", "cwe": "CWE-89", "verdict": "confirmed"},
        {"file": "x.py", "line": 4, "class": "xss", "cwe": "CWE-79", "verdict": "refuted"}])
    r = sb.score_target(d, pins=False)
    assert r["safe"] is True
    assert r["real"] == 0
    assert r["fp_confirmed"] == 1         # the single confirm on a safe twin is a false positive


def test_class_only_findings_map_to_cwe(tmp_path):
    # a candidate with only a coarse class (no cwe) still matches a CWE ground truth
    d = tmp_path / "ct"
    d.mkdir()
    (d / "MANIFEST.json").write_text(json.dumps({"name": "ct", "vulns": [{"cwe": "CWE-918"}]}), encoding="utf-8")
    _write(d, "wave_candidates.jsonl", [{"file": "a.py", "line": 1, "class": "ssrf"}])
    r = sb.score_target(d, pins=False)
    assert r["funnel"]["survived"] == 1


def test_no_outputs_marked(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()
    (d / "MANIFEST.json").write_text(json.dumps({"name": "empty", "vulns": [{"cwe": "CWE-89"}]}), encoding="utf-8")
    r = sb.score_target(d, pins=False)
    assert r["has_outputs"] is False


def test_table_renders_recall_and_safe_line(tmp_path):
    results = [sb.score_target(_vuln_target(tmp_path), pins=False)]
    table = sb.funnel_table(results, model="m")
    assert "1/3 = 33%" in table
    assert "Safe-twin false confirms" in table


def test_flaky_detects_verdict_flip():
    a = [{"file": "a.py", "line": 1, "class": "sqli", "verdict": "confirmed"},
         {"file": "a.py", "line": 2, "class": "ssrf", "verdict": "refuted"}]
    b = [{"file": "a.py", "line": 1, "class": "sqli", "verdict": "refuted"},   # flipped
         {"file": "a.py", "line": 2, "class": "ssrf", "verdict": "refuted"}]   # stable
    flipped = sb.flaky(a, b)
    assert flipped == [("a.py", 1, "sqli")]
