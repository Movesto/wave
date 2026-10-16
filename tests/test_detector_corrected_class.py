"""Guard: a model's free-text class 'correction' can never bench a real finding.

Regression for the Langflow CVE-2025-3248 miss. The detector relabeled the unauthenticated-RCE sink
(POST /api/v1/validate/code -> exec) from `eval` to "code-injection" -- a class the prover does not
know. That blanked its CWE (prove._CLASS_CWE.get -> "") AND floored its severity to 1 (prove._SEV's
default), so the budget-capped prove stage sorted it to the bottom and dropped it before it was ever
attempted, while its `eval` siblings (rank 9) were proved. The fix normalizes every corrected_class
back to the known taxonomy and drops anything that doesn't resolve (keeping the original label).
"""
from agent.orchestrator import detector, oracle, prove


def test_known_synonyms_map_to_pipeline_classes():
    assert detector._canonical_class("code-injection") == "eval"
    assert detector._canonical_class("code_injection") == "eval"
    assert detector._canonical_class("rce") == "eval"
    assert detector._canonical_class("command-injection") == "cmd"
    assert detector._canonical_class("sql-injection") == "sqli"
    assert detector._canonical_class("path-traversal") == "path"
    assert detector._canonical_class("insecure-deserialization") == "deser"
    assert detector._canonical_class("open-redirect") == "redirect"
    assert detector._canonical_class("template-injection") == "ssti"


def test_an_already_canonical_class_passes_through():
    for c in ("eval", "cmd", "sqli", "ssrf", "path", "xss", "deser", "idor"):
        assert detector._canonical_class(c) == c


def test_unknown_correction_is_dropped_not_passed_through():
    # a label the pipeline doesn't know must resolve to "" so the caller KEEPS the original class
    assert detector._canonical_class("madeupclass") == ""
    assert detector._canonical_class("totally-novel-bug") == ""
    assert detector._canonical_class("") == ""


def test_every_normalizer_output_is_rankable_and_provable():
    # THE invariant: any non-empty normalized class is one the prover both RANKS above the budget-cut
    # floor (rank 1) and has a RECIPE (CWE) for. This is what stops a relabel from benching a finding.
    labels = ["code-injection", "command-injection", "sql-injection", "nosql", "path-traversal",
              "cross-site-scripting", "deserialization", "open-redirect", "template-injection",
              "prototype-pollution", "eval", "cmd", "sqli"]
    for lb in labels:
        c = detector._canonical_class(lb)
        assert c, f"{lb!r} should normalize to a known class, got empty"
        assert c in prove._CLASS_CWE, f"{c!r} missing from prove._CLASS_CWE (no recipe)"
        assert c in prove._SEV and prove._SEV[c] > 1, f"{c!r} would floor to the prove budget cut line"


def test_the_exact_cve_relabel_keeps_top_severity():
    # eval -> "code-injection" must NOT collapse from rank 9 to the floor.
    c = detector._canonical_class("code-injection")
    assert c == "eval"
    assert prove._SEV[c] == 9                     # top of the worklist, not 1
    assert prove._CLASS_CWE[c] == "CWE-95"        # intrinsic-dangerous exec recipe restored
    assert "eval" in oracle.CLASS_WITNESS         # and it has witness tokens to grade with


def test_detector_sev_knows_every_known_class_above_floor():
    # the detector's own re-rank (used to order wave_candidates.jsonl) must not floor a recognized class
    # either -- every canonical class except the catch-all "other" scores above 1.
    for c in detector._KNOWN_CLASSES:
        if c == "other":
            continue
        assert detector._SEV.get(c, 1) > 1, f"detector._SEV floors {c!r}"
