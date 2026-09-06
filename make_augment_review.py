"""Render the augmentation pilot as readable markdown for human review.

JSONL is not reviewable by eye, and reviewing this data by eye is the step that
has caught every defect that automated gates missed today.
"""
import collections
import json
import re

FENCE = "```"
REAL = "data/cot/staging/shape1_contrastive_ts_osv.jsonl"
AUG = "data/cot/staging/shape1_ts_augment_pilot.jsonl"
OUT = "docs/TS_AUGMENT_REVIEW.md"
AUG_CWES = ["CWE-770", "CWE-22", "CWE-78", "CWE-863"]


def load(p):
    return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]


def code_of(r):
    return r["messages"][0]["content"].replace("<SCAN>", "").replace("</SCAN>", "").strip()


def think_of(r):
    m = re.search(r"<think>(.*?)</think>", r["messages"][1]["content"], re.S)
    return m.group(1).strip() if m else ""


def verdict_of(r):
    m = re.search(r"status: \w+", r["messages"][1]["content"])
    return m.group(0) if m else "status: ?"


def main():
    real, aug = load(REAL), load(AUG)
    L = [
        "# TypeScript augmentation pilot - review",
        "",
        "For each CWE: the **real CVE pair** first, then **authored variants** (same flaw,",
        "written differently) and **near-misses** (looks vulnerable, is not exploitable).",
        "",
        "The question to answer while reading: **does the authored code read like real",
        "project code?** If it reads like a tutorial, that is the failure mode that made",
        "`shape_react_syn` score 100% while real React scored 41% - and we should stop.",
        "",
        "Near-misses deliberately change the **source**, never the guard, so the label is",
        "checkable by reading rather than a judgement call.",
        "",
    ]

    for cwe in AUG_CWES:
        L += ["---", "", "# " + cwe, ""]
        rp = [r for r in real if r["_meta"]["ground_truth_cwe"] == cwe]
        byp = collections.defaultdict(dict)
        for r in rp:
            byp[r["_meta"]["pair_id"]][r["_meta"]["label"]] = r
        pairs = list(byp.values())
        if pairs and "vuln" in pairs[0]:
            p0 = pairs[0]
            m = p0["vuln"]["_meta"]
            L += [
                "## REAL CVE - %s (%s)" % (m.get("cve", "?"), m.get("repo", "?")),
                "",
                "file: `%s` - fix verified: %s - CWE from: %s"
                % (m.get("src_file", "?"), m.get("fix_status", "?"), m.get("cwe_source", "?")),
                "",
            ]
            for lab in ("vuln", "safe"):
                if lab in p0:
                    L += ["### %s (real code from the CVE)" % lab.upper(),
                          FENCE + "typescript", code_of(p0[lab])[:1200], FENCE, ""]

        for kind, title in (
            ("variant_vuln", "AUTHORED VARIANTS - same flaw, different surface"),
            ("nearmiss_safe", "AUTHORED NEAR-MISSES - vulnerable shape, NOT exploitable"),
        ):
            items = [r for r in aug
                     if r["_meta"]["ground_truth_cwe"] == cwe
                     and r["_meta"]["record_kind"] == kind]
            if not items:
                continue
            L += ["## " + title, ""]
            for i, r in enumerate(items, 1):
                L += ["### %s #%d - %s" % (kind, i, verdict_of(r)),
                      FENCE + "typescript", code_of(r), FENCE, "", "**Reasoning taught:**", ""]
                for ln in think_of(r).splitlines():
                    if ln.strip():
                        L.append("> " + ln.strip())
                L.append("")

    # coverage table -- the honest gap
    rv = collections.Counter()
    for r in real:
        if r["_meta"]["label"] == "vuln":
            rv[r["_meta"]["ground_truth_cwe"]] += 1
    av = collections.Counter()
    for r in aug:
        if r["_meta"]["label"] == "vuln":
            av[r["_meta"]["ground_truth_cwe"]] += 1
    allc = sorted(set(rv) | set(av))
    L += ["---", "", "# Coverage - the gap", "",
          "| CWE | real vuln | authored vuln | total |", "|---|---|---|---|"]
    for c in allc:
        L.append("| %s | %d | %d | %d |" % (c, rv[c], av[c], rv[c] + av[c]))
    only1 = sum(1 for c in allc if rv[c] + av[c] < 2)
    L += ["",
          "**%d CWEs total. %d still have only ONE vulnerable example.** %d augmented."
          % (len(allc), only1, len([c for c in allc if av[c]])), ""]

    open(OUT, "w", encoding="utf-8").write("\n".join(L))
    print("wrote %s (%d chars)" % (OUT, len("\n".join(L))))


if __name__ == "__main__":
    main()
