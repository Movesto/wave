"""Build augmentation PAIRS by editing real post-fix code. See docs/TS_DATA_STANDARD.md.

Emits one vuln + one safe record per edit under a shared pair_id, both derived
from the real POST-FIX code, carrying the base record's full provenance and CWE.

Run `python scan_ts_standard.py <out>` afterwards. Do not ship on a FAIL.
"""
import collections
import hashlib
import json
import os
import sys

from ts_augment_edits import COMPLETENESS_EDITS, EDITS

REAL = "data/cot/staging/shape1_contrastive_ts_osv.jsonl"
OUT = "data/cot/staging/shape1_ts_augment_edits.jsonl"


def code_of(r):
    return r["messages"][0]["content"].replace("<SCAN>", "").replace("</SCAN>", "").strip()


def vuln_trace(source, sink, cwe, why):
    return ("<think>\n"
            f"Hypothesis: `{source}` is influenced by the caller and reaches `{sink}` - "
            f"a possible {cwe}.\n"
            f"Trigger path: {why}.\n"
            f"Defensive check: I look along the path from `{source}` to `{sink}` for anything that "
            "constrains the value, and there is nothing between them that does.\n"
            f"The mechanism is intact and the value is attacker-chosen, so this is exploitable. "
            f"Confirmed {cwe}.\n"
            "</think>\n"
            f"status: confirmed\ncwe: {cwe}\nseverity: HIGH\n"
            f"trace: {source} -> {sink}\n"
            f"fix: constrain `{source}` before it reaches `{sink}`")


def safe_trace(source, sink, cwe, why, because):
    return ("<think>\n"
            f"Hypothesis: a value reaches `{sink}` in the shape associated with {cwe}, so check "
            "whether the mechanism is actually present here.\n"
            "Trigger path: the call structure is the dangerous one and no control has been added, "
            "so the shape alone does not settle the question - what matters is where the value "
            "comes from.\n"
            f"Defensive check: {why}.\n"
            f"Because {because}, nothing an attacker controls reaches `{sink}`, so the mechanism "
            f"{cwe} depends on is absent and the hypothesis is refuted.\n"
            "</think>\n"
            "status: safe\ncwe: none\nseverity: none\n"
            f"trace: {source} -> {sink} is not exploitable ({because})\n"
            "fix: none")


def partial_trace(source, sink, cwe, present_guard, why):
    """A guard IS present and the code is still exploitable.

    The trace must NAME the guard, because the corpus's existing traces claim no
    control exists even when one sits three lines away -- which is what taught the
    model that a guard token means safe.
    """
    return ("<think>\n"
            f"Hypothesis: `{source}` is influenced by the caller and reaches `{sink}` - the shape "
            f"of {cwe}.\n"
            f"Defensive check: a control IS present here - `{present_guard}` - so the question is "
            "not whether one exists but whether it covers this path.\n"
            f"Coverage: {why}.\n"
            f"The control is present but does not cover the path `{source}` takes to `{sink}`, so "
            f"the mechanism survives it. Confirmed {cwe} despite the guard.\n"
            "</think>\n"
            f"status: confirmed\ncwe: {cwe}\nseverity: HIGH\n"
            f"trace: {source} -> {sink} (guard `{present_guard}` present but does not cover it)\n"
            f"fix: extend the existing control to cover `{source}`")


def complete_trace(source, sink, cwe, present_guard, why):
    return ("<think>\n"
            f"Hypothesis: `{source}` reaches `{sink}`, the shape of {cwe} - check whether the "
            "control here covers that path.\n"
            f"Defensive check: the control is `{present_guard}`, and unlike the incomplete version "
            f"it applies to every path reaching `{sink}`.\n"
            f"Coverage: {why}.\n"
            f"Because the control covers every position and input state that reaches `{sink}`, the "
            f"mechanism {cwe} depends on is neutralised and the hypothesis is refuted.\n"
            "</think>\n"
            "status: safe\ncwe: none\nseverity: none\n"
            f"trace: {source} -> {sink} is covered by `{present_guard}`\n"
            "fix: none")


def make(code, trace, cwe, label, pid, kind, base, source):
    bm = base["_meta"]
    return {
        "messages": [
            {"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
            {"role": "assistant", "content": trace},
        ],
        "_meta": {
            "shape": "shape1", "source": "ts_augment_edits", "origin": "edited_real",
            "language": "typescript", "label": label,
            "cwes": [cwe] if label == "vuln" else [], "ground_truth_cwe": cwe,
            "pair_id": pid, "contrastive": True, "synthetic": True,
            "record_kind": kind, "derived_from": "real_safe",
            "flow_source": source,
            # R4: full provenance, carried from the base record
            "cve": bm.get("cve", ""), "ghsa": bm.get("ghsa", ""), "repo": bm.get("repo", ""),
            "sha": bm.get("sha", ""), "src_file": bm.get("src_file", ""),
            "fix_status": bm.get("fix_status", ""), "cwe_source": bm.get("cwe_source", ""),
            "base_pair_id": bm["pair_id"], "base_cve": bm.get("cve", ""),
            "cleaned": True,
        },
    }


def main():
    real = [json.loads(l) for l in open(REAL, encoding="utf-8") if l.strip()]
    byp = collections.defaultdict(dict)
    for r in real:
        byp[r["_meta"]["pair_id"]][r["_meta"]["label"]] = r

    out, f, problems = [], collections.Counter(), []
    for e in EDITS:
        cands = [p for p in byp.values()
                 if "safe" in p and "vuln" in p
                 and p["vuln"]["_meta"].get("repo") == e["repo"]
                 and p["vuln"]["_meta"]["ground_truth_cwe"] == e["cwe_hint"]
                 # several bases share a repo+CWE, so disambiguate by file when given
                 and (not e.get("base_file")
                      or e["base_file"] in p["vuln"]["_meta"].get("src_file", ""))]
        if not cands:
            problems.append(("no_base", e["repo"], e["cwe_hint"]))
            f["no_base"] += 1
            continue
        base_pair = cands[0]
        base_safe = base_pair["safe"]
        # R5: CWE comes from the base record, never from the edit definition
        cwe = base_pair["vuln"]["_meta"]["ground_truth_cwe"]
        src = code_of(base_safe)

        uf, ur = e["unsanitise"]
        if src.count(uf) != 1:
            problems.append(("unsanitise_matched_%dx" % src.count(uf), e["repo"]))
            f["unsanitise_bad_match"] += 1
            continue
        vuln_code = src.replace(uf, ur)

        df, dr = e["desource"]
        if vuln_code.count(df) != 1:
            problems.append(("desource_matched_%dx" % vuln_code.count(df), e["repo"]))
            f["desource_bad_match"] += 1
            continue
        safe_code = vuln_code.replace(df, dr)

        if safe_code == vuln_code:
            f["desource_noop"] += 1
            continue

        pid = hashlib.sha1((e["repo"] + cwe + uf[:60]).encode()).hexdigest()[:12]
        out.append(make(vuln_code, vuln_trace(e["vuln_source"], e["sink"], cwe, e["vuln_why"]),
                        cwe, "vuln", pid, "variant_vuln", base_safe, e["vuln_source"]))
        out.append(make(safe_code, safe_trace(e["safe_source"], e["sink"], cwe, e["safe_why"],
                                              e["safe_because"]),
                        cwe, "safe", pid, "nearmiss_safe", base_safe, e["safe_source"]))
        f["PAIR_BUILT"] += 1

    # ---- guard-completeness pairs: guard visibly present, still exploitable ----
    for e in COMPLETENESS_EDITS:
        cands = [p for p in byp.values()
                 if "safe" in p and "vuln" in p
                 and p["vuln"]["_meta"].get("repo") == e["repo"]
                 and p["vuln"]["_meta"]["ground_truth_cwe"] == e["cwe_hint"]
                 # several bases share a repo+CWE, so disambiguate by file when given
                 and (not e.get("base_file")
                      or e["base_file"] in p["vuln"]["_meta"].get("src_file", ""))]
        if not cands:
            problems.append(("no_base_completeness", e["repo"]))
            f["no_base_completeness"] += 1
            continue
        base_pair = cands[0]
        base_safe = base_pair["safe"]
        cwe = base_pair["vuln"]["_meta"]["ground_truth_cwe"]
        complete_code = code_of(base_safe)

        pf, pr = e["partial"]
        if complete_code.count(pf) != 1:
            problems.append(("partial_matched_%dx" % complete_code.count(pf), e["repo"]))
            f["partial_bad_match"] += 1
            continue
        partial_code = complete_code.replace(pf, pr)
        if partial_code == complete_code:
            f["partial_noop"] += 1
            continue

        # include the file AND the edit text: repo+cwe alone collided for the two
        # openclaw CWE-22 bases, producing one pair_id with four records.
        pid = hashlib.sha1(
            (e["repo"] + cwe + e.get("base_file", "") + pf[:80] + "completeness").encode()
        ).hexdigest()[:12]
        out.append(make(partial_code,
                        partial_trace(e["source"], e["sink"], cwe,
                                      e.get("present_guard_partial", e["present_guard"]),
                                      e["partial_why"]),
                        cwe, "vuln", pid, "partial_fix_vuln", base_safe, e["source"]))
        out.append(make(complete_code,
                        complete_trace(e["source"], e["sink"], cwe,
                                       e.get("present_guard_complete", e["present_guard"]),
                                       e["complete_why"]),
                        cwe, "safe", pid, "complete_fix_safe", base_safe, e["source"]))
        f["COMPLETENESS_PAIR"] += 1

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        for r in out:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    for k, v in f.most_common():
        print(f"  {k:24s} {v}")
    print(f"\npairs: {f['PAIR_BUILT']}  records: {len(out)} -> {OUT}")
    for p in problems:
        print("  PROBLEM:", p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
