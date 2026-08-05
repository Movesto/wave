"""Resolve commit SHA -> (CVE, authoritative CWE) from CISA vulnrichment, locally.

The contrastive rebuild recovered repo+sha for 5,130 pairs but no CVE, so R4 still
fails and the CWEs are still the classifier's guesses. Both are fixed by the same
lookup: vulnrichment CVE records cite their fix commits in `references[].url`, so
the mapping already exists on disk -- it just has to be inverted.

This is deliberately NOT a network job. Resolving a CVE from an authority we hold
locally is reproducible; scraping GitHub for 5,130 shas is neither, and would put
a rate limit between us and a rebuild.

Short SHAs matter: advisories cite 7-, 8- and 12-character prefixes as often as
full ones, so the index keys on the first 7 characters and the match is confirmed
by prefix comparison -- the same fix the JS enrichment needed when `281cefa` never
matched `281cefa00cd4`.

    python resolve_sha_to_cve.py --write
"""
import argparse
import collections
import csv
import glob
import json
import os
import re
import sys

OUT = "data/osv/sha_to_cve.tsv"
PROV = "data/osv/contrastive_provenance.tsv"
_COMMIT = re.compile(r"/commit(?:s)?/([0-9a-f]{7,40})", re.I)


def cwes_of(doc):
    out = []
    c = doc.get("containers", {})
    for cont in [c.get("cna", {})] + (c.get("adp") or []):
        for p in (cont or {}).get("problemTypes", []):
            for d in p.get("descriptions", []):
                cid = d.get("cweId")
                if cid and cid.startswith("CWE-"):
                    out.append(cid)
    return sorted(set(out))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    files = glob.glob("data/downloads/vulnrichment/*/*/CVE-*.json")
    print(f"scanning {len(files)} vulnrichment records...", flush=True)

    idx = collections.defaultdict(list)     # sha7 -> [(full_sha, cve, cwes)]
    for n, f in enumerate(files):
        if n % 20000 == 0:
            print(f"  {n}/{len(files)}  keys={len(idx)}", flush=True)
        try:
            doc = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        cve = doc.get("cveMetadata", {}).get("cveId") or os.path.basename(f)[:-5]
        c = doc.get("containers", {})
        urls = []
        for cont in [c.get("cna", {})] + (c.get("adp") or []):
            for r in (cont or {}).get("references", []):
                u = r.get("url") or ""
                if u:
                    urls.append(u)
        if not urls:
            continue
        cw = cwes_of(doc)
        for u in urls:
            m = _COMMIT.search(u)
            if m:
                sha = m.group(1).lower()
                idx[sha[:7]].append((sha, cve, "|".join(cw)))

    print(f"\nsha index: {len(idx)} 7-char keys", flush=True)

    if not os.path.exists(PROV):
        print(f"missing {PROV}")
        return 1
    rows = list(csv.DictReader(open(PROV, encoding="utf-8"), delimiter="\t"))

    out, tally = [], collections.Counter()
    seen = {}
    for r in rows:
        sha = (r.get("sha") or "").lower()
        if len(sha) < 7:
            tally["no_sha"] += 1
            continue
        cands = idx.get(sha[:7], [])
        # confirm by prefix in BOTH directions: an advisory may cite a short sha
        hits = [c for c in cands
                if sha.startswith(c[0]) or c[0].startswith(sha)]
        if not hits:
            tally["unresolved"] += 1
            continue
        cves = {h[1] for h in hits}
        if len(cves) > 1:
            tally["ambiguous_multiple_cves"] += 1
            continue
        sha_f, cve, cw = hits[0]
        tally["RESOLVED"] += 1
        seen.setdefault(r["pair_id"], True)
        out.append(dict(pair_id=r["pair_id"], label=r["label"], repo=r["repo"],
                        sha=sha, cve=cve, cwe_authoritative=cw,
                        cwe_derived=r.get("cwe_derived", ""),
                        src_file=r.get("src_file", ""),
                        agrees=str(bool(cw and r.get("cwe_derived") in cw.split("|")))))

    for k, v in tally.most_common():
        print(f"  {k:26s} {v:6d}")
    if out:
        pairs = len({r['pair_id'] for r in out})
        withcwe = sum(1 for r in out if r["cwe_authoritative"])
        agree = sum(1 for r in out if r["agrees"] == "True")
        print(f"\n  distinct pairs resolved : {pairs}")
        print(f"  carrying a CISA CWE     : {withcwe}")
        print(f"  derived CWE agreed      : {agree}/{withcwe} "
              f"({100*agree/withcwe:.1f}%)" if withcwe else "")
    if args.write and out:
        with open(OUT, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(out[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(out)
        print(f"\n-> {OUT} ({len(out)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
