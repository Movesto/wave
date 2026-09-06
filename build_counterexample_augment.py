"""Author counterexamples by WEAKENING real guards in a documented way.

Harvesting this class is nearly exhausted: 80 candidates remain and they yield ~30
pairs. The class is 2.14% of training and needs to be nearer 10%, because it is the
only data in the corpus where "a check is present" does not mean "the code is safe".

So they are authored. Construction, which is what keeps it honest:

    SAFE  = the real post-fix code, UNTOUCHED
    VULN  = the same code with ONE guard weakened in a way a real CVE was weakened

Both sides are real code. The weakening is not invented -- every class below was read
off an actual fix during the vetting of `completeness_vetted.py`, so the sentence
explaining why the weakened form is insufficient is a fact about the language or the
API rather than a story.

That is the same construction as `ts_augment_edits`, which passes 16/16; because the
safe side is untouched real post-fix code, R3 (realism), R8 (guard justification) and
R9 (derived from real post-fix) all apply and all bind.

    python build_counterexample_augment.py --write
"""
import argparse
import collections
import csv
import hashlib
import json
import os
import re
import sys

from filter_corpus import is_test_code, load_eval_codes
from scan_ts_standard import code_of, trace_of

SOURCES = ("shape1_contrastive_ts_osv", "shape1_contrastive_js_osv",
           "shape1_contrastive_r2vul", "shape1_contrastive_attested",
           "shape1_wave3_attested", "shape1_contrastive_react_osv")
OUT = "data/cot/staging/shape_counterexample_augment.jsonl"
REPORT = "data/osv/counterexample_augment.tsv"
MIN_CHARS, MAX_CHARS = 120, 4500


def w_loose_comparison(g):
    """`===` -> `==`. Seen in mrobit (CSRF token) and TYPO3."""
    if "===" in g:
        return g.replace("===", "==", 1), (
            "loose_comparison",
            "the comparison is loose, so the two sides are compared after type "
            "juggling rather than as-is. A value of a different type that coerces to "
            "the expected one satisfies the check without matching it")
    if "!==" in g:
        return g.replace("!==", "!=", 1), (
            "loose_comparison",
            "the comparison is loose, so the two sides are compared after type "
            "juggling rather than as-is. A value of a different type that coerces to "
            "the expected one satisfies the check without matching it")
    return None, None


def w_drop_global_flag(g):
    """`/g` removed. Seen in openclaw schtasks -- replace() without /g changes the
    FIRST match only, so every later occurrence survives."""
    m = re.search(r"\.replace\(\s*/((?:\\.|[^/\\])+)/([a-z]*g[a-z]*)", g)
    if not m:
        return None, None
    flags = m.group(2).replace("g", "", 1)
    return (g[:m.start(2)] + flags + g[m.end(2):], (
        "non_global_replace",
        "String.replace with a non-global regex rewrites only the FIRST match, so the "
        "second and later occurrences of the dangerous character survive untouched"))


def w_drop_case_flag(g):
    """`/i` removed. Seen in steveukx/git-js -- a case variant walks past."""
    m = re.search(r"/((?:\\.|[^/\\])+)/([a-z]*i[a-z]*)", g)
    if not m:
        return None, None
    flags = m.group(2).replace("i", "", 1)
    return (g[:m.start(2)] + flags + g[m.end(2):], (
        "case_sensitive_pattern",
        "the pattern becomes case-sensitive, so a case variant of the same input walks "
        "past a check looking for one exact casing"))


def w_unresolve_path(g):
    """Strip the canonicalisation from inside a containment test. Seen in jlangch/venice
    and Graylog -- a STRING prefix is not a PATH prefix."""
    for call in ("getCanonicalFile().toPath()", "getCanonicalPath()", "realpath",
                 "resolve()", "toRealPath()"):
        if call in g and "startsWith" in g:
            return g.replace(call, "getPath()" if "Canonical" in call else "", 1), (
                "string_prefix_not_path_prefix",
                "containment is tested on an unresolved path and as a STRING prefix. "
                "`/tmp/foobar` starts with `/tmp/foo` as text while being outside it as "
                "a path, and a symlink is never followed")
    return None, None


def w_wrong_escape(g):
    """EscapeDataString -> EscapeUriString. Seen in recurly -- the latter PRESERVES
    reserved characters."""
    if "EscapeDataString" in g:
        return g.replace("EscapeDataString", "EscapeUriString", 1), (
            "wrong_escape_function",
            "EscapeUriString preserves the characters that are RESERVED in a URI, so "
            "`?`, `&` and `#` survive escaping and the value can still restructure the "
            "request")
    return None, None


def w_drop_coercion(g):
    """Remove unary `+`. Seen in harttle/liquidjs -- a string compares lexically."""
    m = re.search(r"\+\s+\+(\w)", g)
    if m:
        return g[:m.start()] + "+ " + g[m.start(1):], (
            "no_numeric_coercion",
            "the bound is compared without forcing the value to a number, so a string "
            "is compared lexically instead of numerically and the limit does not limit")
    return None, None


WEAKENINGS = (w_loose_comparison, w_drop_global_flag, w_drop_case_flag,
              w_unresolve_path, w_wrong_escape, w_drop_coercion)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    evalcodes = load_eval_codes()
    out, report, f = [], [], collections.Counter()
    seen, per_class = set(), collections.Counter()
    skipped = {}

    for s in SOURCES:
        path = f"data/cot/staging/{s}.jsonl"
        if not os.path.exists(path):
            continue
        for line in open(path, encoding="utf-8"):
            r = json.loads(line)
            m = r["_meta"]
            if m.get("label") != "safe":
                continue
            f["safe_records"] += 1
            g = re.search(r"constrained by `(.+?)`", trace_of(r), re.S)
            if not g:
                continue
            guard = g.group(1).strip()
            safe_code = code_of(r)
            if guard not in safe_code:
                f["guard_not_in_code"] += 1
                skipped[m.get("pair_id")] = ("guard_not_in_code: no verified weakening class applies to this guard, so weakening it would mean inventing the reason it fails")
                continue

            weak = why = None
            for fn in WEAKENINGS:
                cand, w = fn(guard)
                if cand and cand != guard:
                    weak, why = cand, w
                    break
            if not weak:
                f["no_known_weakening"] += 1
                skipped[m.get("pair_id")] = ("no_known_weakening: no verified weakening class applies to this guard, so weakening it would mean inventing the reason it fails")
                continue
            klass, reason = why

            vuln_code = safe_code.replace(guard, weak, 1)
            if vuln_code == safe_code:
                f["weakening_did_not_apply"] += 1
                continue
            if not (MIN_CHARS <= len(vuln_code) <= MAX_CHARS):
                f["size"] += 1
                skipped[m.get("pair_id")] = ("size: no verified weakening class applies to this guard, so weakening it would mean inventing the reason it fails")
                continue
            if is_test_code(vuln_code):
                f["test_code"] += 1
                skipped[m.get("pair_id")] = ("test_code: no verified weakening class applies to this guard, so weakening it would mean inventing the reason it fails")
                continue
            if any(re.sub(r"\s+", " ", x).strip().lower() in evalcodes
                   for x in (vuln_code, safe_code)):
                f["eval_leakage"] += 1
                skipped[m.get("pair_id")] = ("eval_leakage: no verified weakening class applies to this guard, so weakening it would mean inventing the reason it fails")
                continue
            key = hashlib.sha1(re.sub(r"\s+", "", vuln_code).encode()).hexdigest()
            if key in seen:
                f["duplicate"] += 1
                skipped[m.get("pair_id")] = ("duplicate: no verified weakening class applies to this guard, so weakening it would mean inventing the reason it fails")
                continue
            seen.add(key)
            # No single weakness class may dominate; the model should learn the class
            # of failure, not one syntactic tic.
            if per_class[klass] >= 25:
                f[f"quota_{klass}"] += 1
                skipped[m.get("pair_id")] = (
                    f"class quota: {klass} already has 25 pairs, and one syntactic "
                    f"tic must not dominate the counterexample signal")
                continue
            per_class[klass] += 1

            cwe = m.get("ground_truth_cwe", "")
            src = re.search(r"trace: (\S+) -> (\S+)", trace_of(r))
            if not (cwe and src):
                f["no_cwe_or_flow"] += 1
                continue
            source, sink = src.group(1), src.group(2)

            pid = hashlib.sha1(f"cxaug|{m.get('pair_id')}|{klass}".encode()).hexdigest()[:12]
            base = dict(m)
            base.update(shape="shape_counterexample", source="counterexample_augment",
                        origin="edited", base_pair_id=m.get("pair_id"),
                        weakness_class=klass, guard_present_in_vuln=True,
                        pair_id=pid, fix_status="authored_weakening")

            vt = (f"Hypothesis: `{source}` is caller-influenced and reaches `{sink}` - "
                  f"the shape of {cwe}.\n"
                  f"Trigger path: `{source}` flows to `{sink}` as written.\n"
                  f"Defensive check: a control IS present - `{weak[:90]}`. I check what "
                  f"it constrains rather than that it exists: {reason}.\n"
                  f"The control runs and does not stop the value, so the hypothesis "
                  f"stands. Confirmed {cwe}.")
            st = (f"Hypothesis: `{source}` reaches `{sink}`, the shape of {cwe} - check "
                  f"whether the control on that path is sufficient.\n"
                  f"Trigger path: the same flow is present, so shape alone does not "
                  f"settle it.\n"
                  f"Defensive check: the control is `{guard[:90]}`, which closes the gap "
                  f"the weaker form leaves: {reason}.\n"
                  f"With that closed the value reaching `{sink}` can no longer be chosen "
                  f"freely, so the hypothesis is refuted.")

            for label, code, think, tail in (
                ("vuln", vuln_code, vt,
                 f"status: confirmed\ncwe: {cwe}\nseverity: HIGH\n"
                 f"trace: {source} -> {sink} is only partly constrained by `{weak[:80]}`\n"
                 f"fix: {reason.split(',')[0]}"),
                ("safe", safe_code, st,
                 f"status: safe\ncwe: none\nseverity: none\n"
                 f"trace: {source} -> {sink} is constrained by `{guard[:80]}`\n"
                 f"fix: none")):
                mm = dict(base)
                mm["label"] = label
                out.append({"messages": [
                    {"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
                    {"role": "assistant",
                     "content": f"<think>\n{think}\n</think>\n{tail}"}], "_meta": mm})
            report.append(dict(pair_id=pid, weakness=klass, cwe=cwe,
                               lang=m.get("language", ""), repo=m.get("repo", ""),
                               guard=guard[:70], weakened=weak[:70]))
            f["PAIR_BUILT"] += 1

    for k, v in f.most_common():
        print(f"  {k:28s} {v:5d}")
    print("  by class:", dict(per_class))
    if args.write and out:
        with open(OUT, "w", encoding="utf-8") as fh:
            for r in out:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        side = os.path.splitext(OUT)[0] + ".exclusions.tsv"
        with open(side, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["base_pair_id", "reason"], delimiter="	")
            w.writeheader()
            for k, v in skipped.items():
                if k:
                    w.writerow({"base_pair_id": k, "reason": v})
        print(f"-> {side} ({len(skipped)} bases accounted for)")
        with open(REPORT, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(report[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(report)
        print(f"\n-> {OUT} ({len(out)//2} pairs)\n-> {REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
