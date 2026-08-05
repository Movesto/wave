"""Build completeness pairs: the guard is PRESENT in the vulnerable side and insufficient.

This is the class the project exists to teach and it held 33 pairs. Every builder was
throwing these away: `guard in vuln` reads as "the fix did not add a control", which is
right for an ordinary contrastive pair and exactly wrong here.

Only WEAKNESS CLASSES WITH A MECHANICAL EXPLANATION are built. The teaching value of a
completeness record is the sentence saying why a control that looks adequate is not, and
that sentence has to be true. Where the diff shows a recognisable weakness the story is a
fact about the language:

    ==  -> ===        PHP/JS compare after type juggling; "0e123" == "0" is true
    add ` -- `        a value beginning with `-` is parsed as an option, not an operand
    add /i            a case variant walks past a case-sensitive pattern
    add unary +       a numeric bound compared against a string does not bound anything

`identifier_changed_in_guard` (611 candidates) is deliberately NOT built: the guard did
change, but why the old identifier was wrong cannot be read off the diff, and inventing
that sentence is the thing this project refuses to do.

    python build_completeness_pairs.py --write
"""
import argparse
import collections
import csv
import hashlib
import json
import os
import re
import sys

from build_r2vul_pairs import MAX_CODE_CHARS, pick_sink, pick_source, standalone
from filter_corpus import is_test_code, load_eval_codes
from completeness_vetted import lookup as vetted_weakness
from scan_ts_standard import code_of

CANDS = "data/osv/completeness_candidates.tsv"
OUT = "data/cot/staging/shape_completeness_osv.jsonl"
REPORT = "data/osv/completeness_build.tsv"
MIN_CHARS = 120

# Sources whose CWE is authoritative. The classifier-derived ones agree with CISA/OSV
# 19.7% of the time, and a completeness record with a wrong CWE teaches two errors.
TRUSTED = {"attested", "ts_osv", "js_osv", "r2vul_map_id"}


def weakness(old, new):
    """(class, why-it-was-insufficient) or None if the diff does not explain itself."""
    o, n = old.strip(), new.strip()
    # The OLD side must be loose and NOT already strict. Checking only the new side
    # matched TYPO3 (both forms already strict -- the fix REMOVED a condition) and
    # vite (already `!==`; the real change was adding cleanUrl()). In both the
    # type-juggling explanation would have been false.
    o_loose = bool(re.search(r"(?<![!=<>])==(?!=)", o) or re.search(r"!=(?!=)", o))
    o_strict = "===" in o or "!==" in o
    n_strict = "===" in n or "!==" in n
    if o_loose and n_strict and not o_strict and len(n) >= len(o) - 4:
        return ("loose_comparison",
                "the comparison was loose (`==`/`!=`), so the two sides were compared "
                "after type juggling rather than as-is. A value of a different type "
                "that coerces to the expected one satisfies the check without matching "
                "it, so the control ran and decided nothing")
    if " -- " in n and " -- " not in o:
        return ("option_injection",
                "the value was escaped but not separated from the option list. Escaping "
                "stops metacharacters, it does not stop a value that BEGINS with `-` "
                "from being read as a flag, so the argument was parsed as an option "
                "rather than as data")
    om = re.search(r"/([a-z]*)$", o.split("/")[-1]) if "/" in o else None
    nm = re.search(r"/([a-z]*)$", n.split("/")[-1]) if "/" in n else None
    if ("/" in o and "/" in n and "i" in (n.rsplit("/", 1)[-1] or "")
            and "i" not in (o.rsplit("/", 1)[-1] or "")):
        return ("case_sensitive_pattern",
                "the pattern was case-sensitive, so a case variant of the same input "
                "walked past a check that was looking for the exact casing")
    if re.search(r"\+\s*\+", n) and not re.search(r"\+\s*\+", o):
        return ("no_numeric_coercion",
                "the bound was compared without forcing the value to a number, so a "
                "string was compared lexically instead of numerically and the limit "
                "did not limit anything")
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--all-sources", action="store_true",
                    help="include classifier-CWE sources (not recommended)")
    args = ap.parse_args()

    evalcodes = load_eval_codes()
    cands = [r for r in csv.DictReader(open(CANDS, encoding="utf-8"), delimiter="\t")
             if r["signature"] == "SECOND_PATH"]
    if not args.all_sources:
        cands = [r for r in cands if r["source"] in TRUSTED]
    print(f"candidates: {len(cands)}", flush=True)

    # index every paired record so a candidate can be resolved back to its code
    byid = {}
    for path, name in (("data/cot/staging/shape1_contrastive_attested.jsonl", "attested"),
                       ("data/cot/staging/shape1_contrastive_ts_osv.jsonl", "ts_osv"),
                       ("data/cot/staging/shape1_contrastive_js_osv.jsonl", "js_osv")):
        if not os.path.exists(path):
            continue
        for line in open(path, encoding="utf-8"):
            r = json.loads(line)
            byid.setdefault((name, r["_meta"]["pair_id"]), {})[r["_meta"]["label"]] = r

    out, report, f = [], [], collections.Counter()
    seen_code = set()          # one pair per distinct vulnerable excerpt
    for c in cands:
        # The hand-vetted reading wins: it covers cases where the WHY is a fact about
        # the API rather than a shape in the diff (EscapeUriString preserving reserved
        # characters, a string prefix not being a path prefix).
        w = vetted_weakness(c["existing_guard"]) or weakness(c["existing_guard"],
                                                             c["added_guard"])
        if w and vetted_weakness(c["existing_guard"]):
            f["from_vetting"] += 1
        if not w:
            f["no_mechanical_explanation"] += 1
            continue
        klass, why = w
        sides = byid.get((c["source"], c["pair_id"]))
        if not sides or "vuln" not in sides or "safe" not in sides:
            f["pair_not_resolvable"] += 1
            continue
        v, s = sides["vuln"], sides["safe"]
        vc, sc = code_of(v), code_of(s)
        if not (MIN_CHARS <= len(vc) <= MAX_CODE_CHARS
                and MIN_CHARS <= len(sc) <= MAX_CODE_CHARS):
            f["size"] += 1
            continue
        if is_test_code(vc) or is_test_code(sc):
            f["test_code"] += 1
            continue
        if any(re.sub(r"\s+", " ", x).strip().lower() in evalcodes for x in (vc, sc)):
            f["eval_leakage"] += 1
            continue

        present = c["existing_guard"].strip()
        if not standalone(present.split("(")[0].split()[-1] if "(" in present
                          else present.split()[-1], vc):
            pass  # the head token check is advisory; the full-line check below is binding
        if present not in vc:
            f["present_guard_not_in_excerpt"] += 1
            continue

        src = pick_source(present, vc, sc)
        snk = pick_sink(vc, src) if src else None
        if not (src and snk and snk != src
                and standalone(snk, vc) and standalone(snk, sc)):
            f["no_grounded_flow"] += 1
            continue

        cwe = v["_meta"].get("ground_truth_cwe", "")
        if not cwe:
            f["no_cwe"] += 1
            continue

        key = hashlib.sha1(re.sub(r"\s+", "", vc).encode()).hexdigest()
        if key in seen_code:
            f["duplicate_excerpt"] += 1
            continue
        seen_code.add(key)
        pid = hashlib.sha1(f"completeness|{c['source']}|{c['pair_id']}".encode()).hexdigest()[:12]
        meta = dict(v["_meta"])
        meta.update(shape="shape_completeness", source="completeness_osv",
                    weakness_class=klass, guard_present_in_vuln=True,
                    fix_status="completeness_from_second_path")

        vuln_think = (
            f"Hypothesis: `{src}` is caller-influenced and reaches `{snk}` - the shape "
            f"of {cwe}.\n"
            f"Trigger path: `{src}` flows to `{snk}` as written.\n"
            f"Defensive check: a control IS present - `{present[:90]}`. I check what it "
            f"actually constrains rather than that it exists: {why}.\n"
            f"The control runs and does not stop the value, so the hypothesis stands."
        )
        safe_think = (
            f"Hypothesis: `{src}` reaches `{snk}`, the shape of {cwe} - check whether "
            f"the control on that path is sufficient.\n"
            f"Trigger path: the same flow exists here, so shape alone does not settle it.\n"
            f"Defensive check: the control is `{c['added_guard'][:90]}`, which closes the "
            f"gap the previous form left: {why}.\n"
            f"With that closed, the value arriving at `{snk}` can no longer be chosen "
            f"freely, so the hypothesis is refuted."
        )
        for label, code, think, tail in (
            ("vuln", vc, vuln_think,
             f"status: confirmed\ncwe: {cwe}\nseverity: HIGH\n"
             f"trace: {src} -> {snk} is only partly constrained by `{present[:80]}`\n"
             f"fix: close the gap - {klass.replace('_', ' ')}"),
            ("safe", sc, safe_think,
             f"status: safe\ncwe: none\nseverity: none\n"
             f"trace: {src} -> {snk} is constrained by `{c['added_guard'][:80]}`\n"
             f"fix: none")):
            m = dict(meta)
            m["label"] = label
            m["pair_id"] = pid
            out.append({"messages": [
                {"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
                {"role": "assistant", "content": f"<think>\n{think}\n</think>\n{tail}"}],
                "_meta": m})
        report.append(dict(pair_id=pid, weakness=klass, cwe=cwe, cve=meta.get("cve", ""),
                           lang=meta.get("language", ""), repo=meta.get("repo", ""),
                           present=present[:80], strengthened=c["added_guard"][:80]))
        f["PAIR_BUILT"] += 1

    for k, v in f.most_common():
        print(f"  {k:30s} {v:5d}")
    if args.write and out:
        with open(OUT, "w", encoding="utf-8") as fh:
            for r in out:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        with open(REPORT, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(report[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(report)
        print(f"\n-> {OUT} ({len(out)//2} pairs)\n-> {REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
