# ============================================================
# eval/scoring.py
#
# Layer-1 deterministic metrics. No judge calls here.
#
# - SHAPE 1: vuln-vs-safe classification — FPR(safe) is the
#   HEADLINE metric per the workflow.
# - SHAPE 2: ask-don't-guess rate + correct-symbol rate.
# - SHAPE 3: confirm/dismiss accuracy + multi-hop correctness.
# - SHAPE 4: structural sanity (dedup, severity-monotonicity,
#   no hallucinated findings).
#
# Every metric is also sliced by CWE class and language.
# ============================================================
from collections import Counter, defaultdict
from typing import Iterable, Optional


# -----------------------------
# small math helpers
# -----------------------------

def _safe_div(num: int | float, den: int | float) -> float:
    return float(num) / den if den > 0 else 0.0


def _classify(gt_label: str, pred_status: Optional[str]) -> str:
    """Map (ground truth, prediction) to one of TP/FP/FN/TN for binary vuln-vs-safe."""
    if pred_status == "confirmed":
        return "TP" if gt_label == "vuln" else "FP"
    if pred_status == "safe":
        return "FN" if gt_label == "vuln" else "TN"
    return "MISS"  # parse failed / wrong shape


# -----------------------------
# SHAPE 1
# -----------------------------

def score_shape1(predictions: list[dict]) -> dict:
    """
    predictions = [{ground_truth, parsed, ...}, ...] for shape1.
    Headline: FPR on safe subset.
    """
    counts = Counter()
    cwe_hits = []   # per-flagged item: did we get the right CWE class?
    per_cwe = defaultdict(Counter)
    per_lang = defaultdict(Counter)

    for p in predictions:
        gt = p["ground_truth"]
        parsed = p["parsed"]
        cls = _classify(gt["label"], parsed.get("status"))
        counts[cls] += 1

        lang = gt.get("language") or "unknown"
        per_lang[lang][cls] += 1

        # For each (label=vuln) item, track per-CWE
        gt_cwes = gt.get("cwes") or []
        primary_cwe = gt_cwes[0] if gt_cwes else None

        if gt["label"] == "vuln":
            if primary_cwe:
                per_cwe[primary_cwe][cls] += 1
            # CWE accuracy on TP
            if cls == "TP":
                pred_cwe = parsed.get("cwe")
                cwe_hits.append(int(pred_cwe is not None and pred_cwe == primary_cwe))

    tp, fp, fn, tn = counts["TP"], counts["FP"], counts["FN"], counts["TN"]
    fpr = _safe_div(fp, fp + tn)
    recall = _safe_div(tp, tp + fn)
    precision = _safe_div(tp, tp + fp)
    f1 = _safe_div(2 * precision * recall, precision + recall)

    return {
        "total":      len(predictions),
        "parse_miss": counts["MISS"],
        "headline_fpr_on_safe": fpr,
        "recall_on_vuln":       recall,
        "precision":            precision,
        "f1":                   f1,
        "cwe_accuracy_when_flagged": _safe_div(sum(cwe_hits), len(cwe_hits)),
        "confusion": {"TP": tp, "FP": fp, "FN": fn, "TN": tn},
        "by_language": {l: dict(c) for l, c in per_lang.items()},
        "by_cwe":      {c: dict(d) for c, d in per_cwe.items()},
    }


# -----------------------------
# SHAPE 2 (ask-don't-guess)
# -----------------------------

def score_shape2(predictions: list[dict]) -> dict:
    correct_ask = 0
    correct_symbol = 0
    hallucinated_verdict = 0
    parse_miss = 0
    per_lang = defaultdict(Counter)

    for p in predictions:
        gt = p["ground_truth"]
        parsed = p["parsed"]
        lang = gt.get("language") or "unknown"
        helper_fn = (gt.get("helper_fn") or "").lower()

        status = parsed.get("status")
        if status is None:
            parse_miss += 1
            per_lang[lang]["MISS"] += 1
            continue

        if status == "needs_context":
            correct_ask += 1
            per_lang[lang]["ASK"] += 1
            refs_text = " ".join(parsed.get("open_refs") or []).lower()
            if helper_fn and helper_fn in refs_text:
                correct_symbol += 1
        else:
            # The failure mode: model HALLUCINATED a verdict instead of asking.
            hallucinated_verdict += 1
            per_lang[lang]["HALLUCINATED"] += 1

    n = len(predictions)
    return {
        "total":      n,
        "parse_miss": parse_miss,
        "ask_dont_guess_rate":   _safe_div(correct_ask, n),
        "correct_symbol_rate":   _safe_div(correct_symbol, n),
        "hallucinated_verdict":  hallucinated_verdict,
        "hallucination_rate":    _safe_div(hallucinated_verdict, n),
        "by_language": {l: dict(c) for l, c in per_lang.items()},
    }


# -----------------------------
# SHAPE 3 (cross-file)
# -----------------------------

def score_shape3(predictions: list[dict]) -> dict:
    confirm = {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "MISS": 0}
    dismiss = {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "MISS": 0}
    multi_hop_total = 0
    multi_hop_correct_open_ref = 0
    parse_miss = 0
    per_lang = defaultdict(Counter)
    per_cwe = defaultdict(Counter)

    for p in predictions:
        gt = p["ground_truth"]
        parsed = p["parsed"]
        lang = gt.get("language") or "unknown"
        primary_cwe = (gt.get("cwes") or [None])[0]

        disposition = gt.get("disposition")
        expected_status = "confirmed" if disposition == "confirm" else "safe"
        bucket = confirm if disposition == "confirm" else dismiss

        status = parsed.get("status")
        if status is None:
            bucket["MISS"] += 1
            parse_miss += 1
            per_lang[lang]["MISS"] += 1
            continue

        cls = _classify(
            gt_label=("vuln" if disposition == "confirm" else "safe"),
            pred_status=status,
        )
        bucket[cls] += 1
        per_lang[lang][cls] += 1
        if primary_cwe:
            per_cwe[primary_cwe][cls] += 1

        # Multi-hop: model must emit at least one follow_up_ref
        if gt.get("multi_hop"):
            multi_hop_total += 1
            if parsed.get("follow_up_refs"):
                multi_hop_correct_open_ref += 1

    def acc(b):
        denom = b["TP"] + b["FP"] + b["FN"] + b["TN"]
        return _safe_div(b["TP"] + b["TN"], denom)

    return {
        "total":      len(predictions),
        "parse_miss": parse_miss,
        "confirm_accuracy":   acc(confirm),
        "dismiss_accuracy":   acc(dismiss),
        "multi_hop_correct_ref_rate": _safe_div(multi_hop_correct_open_ref, multi_hop_total),
        "confirm_bucket": confirm,
        "dismiss_bucket": dismiss,
        "by_language": {l: dict(c) for l, c in per_lang.items()},
        "by_cwe":      {c: dict(d) for c, d in per_cwe.items()},
    }


# -----------------------------
# SHAPE 4 (synthesis)
# -----------------------------

def score_shape4(predictions: list[dict]) -> dict:
    """Layer-1 structural checks. Judge handles fuzzy synthesis quality."""
    well_formed = 0
    sev_monotonic = 0
    no_hallucination = 0
    dedup_acknowledged = 0
    parse_miss = 0

    for p in predictions:
        gt = p["ground_truth"]
        parsed = p["parsed"]
        ranked = parsed.get("ranked") or []

        if not parsed.get("think") or not parsed.get("executive_summary"):
            parse_miss += 1
            continue

        if ranked:
            well_formed += 1

        # Severity non-increasing
        sev_seq = [{"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(r["severity"], 0) for r in ranked]
        if sev_seq and all(sev_seq[i] >= sev_seq[i + 1] for i in range(len(sev_seq) - 1)):
            sev_monotonic += 1

        # Anti-hallucination: every ranked title substring-matches an input finding title.
        # Ground truth carries the actual finding-set on the record via user message side.
        # We can recover it from the prediction's stored input.
        user_text = p.get("user_input", "").lower()
        if ranked and all(r["title"].lower() in user_text or
                          user_text.find(r["title"].lower()[:30]) >= 0
                          for r in ranked):
            no_hallucination += 1

        # Dedup: if input has a near-duplicate pattern (foo.py + foo_v2.py), the
        # response's dedup_notes should not be 'none'.
        import re
        has_dup_pattern = bool(re.search(r"_v\d+\.", user_text))
        dedup_match = re.search(r"dedup_notes\s*:\s*(.+?)$", p.get("raw_text", ""), re.IGNORECASE | re.MULTILINE)
        if has_dup_pattern and dedup_match and dedup_match.group(1).strip().lower() != "none":
            dedup_acknowledged += 1

    n = len(predictions)
    return {
        "total":         n,
        "parse_miss":    parse_miss,
        "well_formed":   well_formed,
        "well_formed_rate":     _safe_div(well_formed, n),
        "severity_monotonic_rate": _safe_div(sev_monotonic, n),
        "no_hallucination_rate":   _safe_div(no_hallucination, n),
        "dedup_acknowledged":      dedup_acknowledged,
    }


SHAPE_SCORERS = {
    "shape1": score_shape1,
    "shape2": score_shape2,
    "shape3": score_shape3,
    "shape4": score_shape4,
    # Language-coverage variants are shape1-format (status/cwe verdict).
    "shape1_ts": score_shape1,
    "shape1_react": score_shape1,
    "shape_react_syn": score_shape1,
    "shape1_ts_safe": score_shape1,
    "shape1_react_safe": score_shape1,
    "shape1_verified": score_shape1,
    "shape1_verified_safe": score_shape1,
}
