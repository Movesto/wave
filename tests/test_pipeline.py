"""Unit tests for the data-quality pipeline modules:
  cwe_contracts (cross-CWE bleed), template_reason (deterministic assembler),
  postprocess (field cleanup/coherence), vuln_types (sink classifier).

Run: python tests/test_pipeline.py   (or: pytest tests/test_pipeline.py)
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cot.cwe_contracts import check_bleed, family_of
from cot.template_reason import build_vuln_trace, type_to_cwe
from cot.postprocess import clean_scan_output
from cot.vuln_types import classify


# ---- vuln_types.classify ----
def test_classify_detects_command_injection():
    _, cwe = classify("import os\ndef run(c):\n    os.system('ping ' + c)")
    assert cwe and family_of(cwe) == "command", cwe


def test_classify_detects_sql():
    _, cwe = classify('cur.execute("SELECT * FROM u WHERE id=" + uid)')
    assert cwe and family_of(cwe) == "sql", cwe


# ---- cwe_contracts.check_bleed ----
def test_bleed_passes_consistent_trace():
    ok, _ = check_bleed("the username is concatenated into a SQL query via execute()", "CWE-89")
    assert ok


def test_bleed_flags_wrong_family():
    # labelled SQLi but the text is purely about innerHTML/XSS -> should flag
    ok, why = check_bleed("the value is written to innerHTML and rendered into the DOM as XSS", "CWE-89")
    assert not ok, why


def test_bleed_lenient_when_cwe_unknown():
    ok, _ = check_bleed("anything", "CWE-99999")
    assert ok  # unknown CWE -> don't flag


# ---- template_reason.build_vuln_trace ----
def test_build_vuln_trace_grounds_sink():
    code = 'def q(uid):\n    sql = "SELECT * FROM u WHERE id=" + uid\n    cur.execute(sql)'
    txt, ok = build_vuln_trace(code, "", "CWE-89")
    assert ok
    assert "status: confirmed" in txt and "CWE-89" in txt
    assert "trace:" in txt


def test_build_vuln_trace_declines_without_sink():
    # no recognizable SQL sink -> assembler should decline rather than fabricate
    txt, ok = build_vuln_trace("def add(a, b):\n    return a + b", "", "CWE-89")
    assert not ok


def test_type_to_cwe_map():
    assert type_to_cwe("SQL Injection") == "CWE-89"
    assert type_to_cwe("Command Injection") == "CWE-78"


# ---- postprocess.clean_scan_output ----
def test_safe_coherence_strips_vuln_fields():
    raw = "<think>safe, parameterized.</think>\nstatus: safe\ncwe: CWE-89\nseverity: HIGH\nfix: do x"
    out = clean_scan_output(raw)
    assert "cwe: none" in out and "severity: none" in out and "fix: none" in out


def test_cwe_normalization():
    raw = "<think>x</think>\nstatus: confirmed\ncwe: 79\nseverity: HIGH\ntrace: a -> b\nfix: escape"
    assert "CWE-79" in clean_scan_output(raw)


def test_clean_leaves_good_trace_status():
    raw = ("<think>uid flows to execute</think>\nstatus: confirmed\ncwe: CWE-89\n"
           "severity: HIGH\nline: 3\ntrace: uid -> execute\nfix: parameterize")
    out = clean_scan_output(raw)
    assert "status: confirmed" in out and "CWE-89" in out


def test_trim_trace_degraded_prose():
    from cot.postprocess import _trim_trace
    out = _trim_trace("--label` The vulnerability is primarily related to the handling "
                      "of the `--label` argument in the `argparse.ParserArgument")
    assert "->" in out and "vulnerability" not in out.lower() and len(out) < 60, out


def test_trim_trace_keeps_arrow_chain():
    from cot.postprocess import _trim_trace
    # arrow chains with hyphenated tokens (f-string) must survive intact
    assert _trim_trace("uid → f-string → q → db.execute(q)") == "uid → f-string → q → db.execute(q)"


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn(); passed += 1; print(f"  PASS {fn.__name__}")
        except AssertionError as e:
            print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e:
            print(f"  ERROR {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    return passed == len(fns)


if __name__ == "__main__":
    sys.exit(0 if _run_all() else 1)
