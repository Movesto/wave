"""Enrich the JS guard set with CWEs, provenance and explicit labels.

Follows docs/TS_DATA_STANDARD.md (R4 provenance, R5 CWE from an authoritative
source, R13 nothing silently dropped).

Two things this does differently from the TS pass, at the user's direction:

  LABEL, DON'T DROP. A guard with no resolvable CWE gets `cwe_status: none` and
  stays in the table. Dropping it would hide a gap we could close later; the TS
  run already showed 17/223 GHSA advisories carry no CVE alias at all.

  COMPLETE A PARTIAL CWE. CWEs are collected from EVERY source that has them --
  the OSV advisory, CISA's CNA container and CISA's ADP container -- and the union
  is kept in `cwe_all`, with the most specific single value promoted to
  `cwe_final`. The TS pass took CISA-or-advisory and discarded the rest, which
  loses information when one source lists a family and another the mechanism.

    python enrich_js_guards.py
"""
import collections
import csv
import json
import os
import re
import sys

CLEAN = "data/osv/js_guard_clean.tsv"
OUT = "data/osv/js_guard_enriched.tsv"
UNRESOLVED = "data/osv/js_cwe_unresolved.tsv"
VR = "data/downloads/vulnrichment"

_COMMIT = re.compile(r"github\.com/[^/\s]+/[^/\s]+/commit/([0-9a-fA-F]{7,40})")

# Parent -> child. When both are present the child names the MECHANISM, which is
# what the data is meant to teach, so it wins.
_MORE_SPECIFIC = {
    "CWE-22": {"CWE-23", "CWE-59", "CWE-36", "CWE-73"},
    "CWE-20": {"CWE-1284", "CWE-129", "CWE-183", "CWE-184"},
    "CWE-287": {"CWE-290", "CWE-294", "CWE-303", "CWE-306", "CWE-307", "CWE-345"},
    "CWE-284": {"CWE-862", "CWE-863", "CWE-639", "CWE-732"},
    "CWE-400": {"CWE-770", "CWE-789", "CWE-1333", "CWE-834"},
    "CWE-74": {"CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-1321"},
    "CWE-664": {"CWE-668", "CWE-367", "CWE-459"},
    "CWE-693": {"CWE-346", "CWE-352", "CWE-1021"},
}


def vr_path(cve):
    m = re.match(r"CVE-(\d{4})-(\d+)$", cve or "")
    if not m:
        return None
    yr, num = m.group(1), m.group(2)
    bucket = (num[:-3] if len(num) > 3 else "0") + "xxx"
    return os.path.join(VR, yr, bucket, cve + ".json")


def cisa(cve):
    """(cwes, commit shas) from vulnrichment, or None if not present."""
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
    return cwes, shas



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

def promote(cwes):
    """Pick the most specific CWE from a set, else the first stable one."""
    if not cwes:
        return ""
    s = set(cwes)
    for parent, children in _MORE_SPECIFIC.items():
        if parent in s and (s & children):
            s.discard(parent)
    return sorted(s, key=lambda c: int(c.split("-")[1]))[0]


def main():
    ghsa2cve = json.load(open("data/osv/ghsa_to_cve.json", encoding="utf-8"))
    sha2id, sha2cwes = {}, {}
    with open("data/osv/npm_candidates.tsv", encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            k = row["sha"].lower()[:12]
            sha2id[k] = row["id"]
            sha2cwes[k] = [c for c in row["cwes"].split("|") if c.startswith("CWE-")]

    rows = list(csv.DictReader(open(CLEAN, encoding="utf-8"), delimiter="\t"))
    f = collections.Counter()
    out, unresolved = [], []

    for r in rows:
        sha = (r.get("sha") or "").lower()[:12]
        ghsa = sha2id.get(sha, "")
        cve = ghsa2cve.get(ghsa, "")
        adv = set(sha2cwes.get(sha, []))

        cisa_cwes, shas, status = set(), set(), ""
        if not cve:
            status = "no_cve_alias"
        else:
            got = cisa(cve)
            if got is None:
                status = "not_in_vulnrichment"
            else:
                cisa_cwes, shas = got
                if not shas:
                    status = "cisa_no_commit"
                elif sha_matches(r.get('sha',''), shas):
                    status = "verified_same_commit"
                else:
                    status = "different_commit"
        f[status] += 1

        # union across every source that had anything (the "complete the rest" step)
        all_cwes = adv | cisa_cwes
        if cisa_cwes and adv and cisa_cwes != adv:
            f["cwe_completed_from_two_sources"] += 1
        cwe_final = promote(cisa_cwes) or promote(adv)
        cwe_status = ("cisa" if cisa_cwes else "advisory" if adv else "none")
        f[f"cwe_{cwe_status}"] += 1

        rec = dict(
            n=r["n"], guard=r["guard"], file=r["file"], repo=r["repo"], patch=r["patch"],
            sha=r.get("sha", ""), ghsa=ghsa, cve=cve,
            cwe_final=cwe_final,
            cwe_all="|".join(sorted(all_cwes, key=lambda c: int(c.split("-")[1]))),
            cwe_advisory="|".join(sorted(adv)), cwe_cisa="|".join(sorted(cisa_cwes)),
            cwe_status=cwe_status, fix_status=status,
        )
        out.append(rec)
        # R13 discipline: anything not fully resolved is QUEUED, never discarded
        if cwe_status == "none" or status in ("no_cve_alias", "not_in_vulnrichment",
                                              "different_commit"):
            unresolved.append(rec)

    cols = ["n", "cve", "ghsa", "repo", "sha", "file", "cwe_final", "cwe_all",
            "cwe_advisory", "cwe_cisa", "cwe_status", "fix_status", "guard", "patch"]
    for path, data in ((OUT, out), (UNRESOLVED, unresolved)):
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, delimiter="\t", extrasaction="ignore")
            w.writeheader()
            w.writerows(data)

    print("=== status ===")
    for k, v in f.most_common():
        print(f"  {k:34s} {v}")
    print(f"\nenriched  : {len(out)} -> {OUT}")
    print(f"unresolved (labelled, kept): {len(unresolved)} -> {UNRESOLVED}")
    cw = collections.Counter(r["cwe_final"] for r in out if r["cwe_final"])
    print("\nCWE spread:", dict(cw.most_common(12)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
