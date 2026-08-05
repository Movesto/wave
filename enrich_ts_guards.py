"""Enrich the TS guard set with CISA vulnrichment CWEs, provenance, and fix labels.

Three things this fixes:

1. CWE PRECISION. Where CISA disagrees with the advisory CWE it is consistently
   MORE SPECIFIC, and specific in the direction we want: CWE-22 -> CWE-59
   ("path traversal" -> "symlink following"), CWE-287 -> CWE-303, CWE-400 ->
   CWE-789. Ours name a CATEGORY; CISA's name a MECHANISM. Since the goal is to
   teach the model a vulnerability rather than a class, we take CISA's.

2. PROVENANCE. The existing 324 TS records carry no CVE, repo, sha or file --
   they cannot be audited against anything, which is why the fix/CWE comparison
   was impossible on them. Every row here keeps its full lineage.

3. NOTHING IS SILENTLY DROPPED. Rows we cannot resolve get an explicit
   `fix_status` so they become a triage queue instead of a silence.

    python enrich_ts_guards.py
"""
import collections
import csv
import json
import os
import re
import sys

CLEAN = "data/osv/ts_guard_clean.tsv"
OUT = "data/osv/ts_guard_enriched.tsv"
VR = "data/downloads/vulnrichment"
UNRESOLVED = "data/osv/ts_fix_unresolved.tsv"

_COMMIT = re.compile(r"github\.com/[^/\s]+/[^/\s]+/commit/([0-9a-fA-F]{7,40})")


def vr_path(cve):
    m = re.match(r"CVE-(\d{4})-(\d+)$", cve)
    if not m:
        return None
    yr, num = m.group(1), m.group(2)
    bucket = (num[:-3] if len(num) > 3 else "0") + "xxx"
    return os.path.join(VR, yr, bucket, cve + ".json")


def cisa_record(cve):
    """(cwes, commit_shas, n_refs) from a vulnrichment record, or None."""
    p = vr_path(cve)
    if not p or not os.path.exists(p):
        return None
    try:
        j = json.load(open(p, encoding="utf-8"))
    except Exception:
        return None
    conts = j.get("containers", {})
    blocks = [conts.get("cna", {})] + (conts.get("adp") or [])
    cwes, refs = set(), []
    for b in blocks:
        for pt in b.get("problemTypes", []) or []:
            for d in pt.get("descriptions", []) or []:
                if d.get("cweId"):
                    cwes.add(d["cweId"])
        refs += [x.get("url", "") for x in b.get("references", []) or []]
    shas = {m.group(1).lower()[:12] for u in refs for m in [_COMMIT.search(u)] if m}
    return cwes, shas, len(refs)



def sha_matches(ours, theirs):
    """Git shas are abbreviated to different lengths by different sources.

    CISA listed `281cefa00cd4` where our record carries `281cefa` -- the SAME
    commit, reported as a mismatch because both sides were truncated to 12 chars
    before comparing. Compare by PREFIX in whichever direction is shorter.
    """
    a = (ours or "").lower()
    for b in theirs:
        b = (b or "").lower()
        if not a or not b:
            continue
        n = min(len(a), len(b))
        if n >= 7 and a[:n] == b[:n]:
            return True
    return False

def main():
    ghsa2cve = json.load(open("data/osv/ghsa_to_cve.json", encoding="utf-8"))
    sha2id = {}
    with open("data/osv/npm_candidates.tsv", encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            sha2id[row["sha"].lower()] = row["id"]

    rows = list(csv.DictReader(open(CLEAN, encoding="utf-8"), delimiter="\t"))
    f = collections.Counter()
    out, unresolved = [], []

    for r in rows:
        stem = os.path.splitext(os.path.basename(r["patch"]))[0]
        sha = stem.rsplit("__", 1)[-1].lower() if "__" in stem else ""
        ghsa = sha2id.get(sha, "")
        cve = ghsa2cve.get(ghsa, "")
        adv = [c for c in r["cwe"].split("|") if c.startswith("CWE-")]

        cwe_cisa, status = [], ""
        if not cve:
            status = "no_cve_alias"
        else:
            got = cisa_record(cve)
            if got is None:
                status = "not_in_vulnrichment"
            else:
                cwes, shas, _ = got
                cwe_cisa = sorted(cwes)
                if not shas:
                    status = "cisa_no_commit"        # we have one, CISA does not
                elif sha_matches(sha, shas):
                    status = "verified_same_commit"
                else:
                    status = "different_commit"      # needs a human look
        f[status] += 1

        # CISA's CWE wins when present -- it names the mechanism, not the family.
        if cwe_cisa and set(cwe_cisa) != set(adv):
            f["cwe_replaced_with_cisa"] += 1
        cwe_final = cwe_cisa or adv

        rec = dict(
            n=r["n"], guard=r["guard"], file=r["file"], repo=r["repo"], patch=r["patch"],
            sha=sha, ghsa=ghsa, cve=cve,
            cwe_advisory="|".join(adv), cwe_cisa="|".join(cwe_cisa),
            cwe_final="|".join(cwe_final), fix_status=status,
        )
        out.append(rec)
        if status in ("no_cve_alias", "not_in_vulnrichment", "different_commit"):
            unresolved.append(rec)

    cols = ["n", "cve", "ghsa", "repo", "sha", "file", "cwe_final", "cwe_advisory",
            "cwe_cisa", "fix_status", "guard", "patch"]
    for path, data in ((OUT, out), (UNRESOLVED, unresolved)):
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, delimiter="\t", extrasaction="ignore")
            w.writeheader()
            w.writerows(data)

    print("=== fix_status ===")
    for k, v in f.most_common():
        print(f"  {k:26s} {v}")
    print()
    print(f"enriched : {len(out)} -> {OUT}")
    print(f"unresolved (needs research): {len(unresolved)} -> {UNRESOLVED}")
    # what did adopting CISA change?
    ch = [r for r in out if r["cwe_cisa"] and r["cwe_cisa"] != r["cwe_advisory"]]
    print()
    print(f"CWE changed by adopting CISA: {len(ch)}")
    for r in ch[:10]:
        print(f"  {r['cve']:18s} {r['cwe_advisory']:16s} -> {r['cwe_cisa']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
