"""Resolve commit SHA -> CVE via the OSV query API, for the pairs vulnrichment missed.

Local vulnrichment resolved only 633 of 5,130 pairs, because most fix commits are
never cited in an advisory's reference list. OSV indexes the other direction --
`POST /v1/query {"commit": sha}` returns every advisory whose affected ranges
contain that commit -- which is exactly the question we have.

Cached and resumable: every response is written to data/osv/sha_cache/ before it is
used, so an interrupted run resumes for free and a rebuild never re-queries. This
is the same shape as the OSV bulk harvest, for the same reason -- network work that
cannot be repeated cheaply must not be repeated at all.

2,433 distinct shas at ~1s -> roughly 40 minutes.

    python osv_resolve_shas.py --write
"""
import argparse
import collections
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request

PROV = "data/osv/contrastive_provenance.tsv"
DONE = "data/osv/sha_to_cve.tsv"
CACHE = "data/osv/sha_cache"
OUT = "data/osv/sha_to_cve_osv.tsv"
API = "https://api.osv.dev/v1/query"
DELAY = 0.9


def query(sha):
    """Cached OSV lookup. Returns the parsed response, or None on a hard failure."""
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, f"{sha}.json")
    if os.path.exists(path):
        try:
            return json.load(open(path, encoding="utf-8"))
        except Exception:
            pass
    body = json.dumps({"commit": sha}).encode()
    req = urllib.request.Request(API, data=body,
                                 headers={"Content-Type": "application/json"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                d = json.loads(r.read().decode("utf-8", "replace"))
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(d, fh)
            return d
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(5 * (attempt + 1))
                continue
            if e.code == 404:
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump({}, fh)
                return {}
            return None
        except Exception:
            time.sleep(2 * (attempt + 1))
    return None


def _fix_commits(vuln):
    """Commit SHAs this advisory records as the FIX."""
    out = []
    for aff in vuln.get("affected") or []:
        for rng in aff.get("ranges") or []:
            if rng.get("type") != "GIT":
                continue
            for ev in rng.get("events") or []:
                fx = ev.get("fixed") or ev.get("last_affected")
                if fx:
                    out.append(str(fx).lower())
    return out


def cve_and_cwe(doc, sha=""):
    """(cve, cwes) taken from ONE advisory -- the one this commit actually fixes.

    A commit query returns every advisory whose affected range CONTAINS the commit,
    and 79% of our commits matched more than one. Taking the CVE from the first and
    the CWEs from all of them paired a CVE with another advisory's labels, which is
    how `CVE-2023-39964` ended up carrying eight CWEs and one record carried 51.

    The advisory a commit FIXES names it in `ranges.events[].fixed`, so that is the
    only one whose CVE and CWE belong together. If no advisory claims the commit as
    its fix, or several do, the answer is "unresolved" -- not a blended guess.
    """
    vulns = doc.get("vulns") or []
    sha = (sha or "").lower()

    def pick(v):
        ids = [v.get("id", "")] + (v.get("aliases") or [])
        cve = next((i for i in ids if i.startswith("CVE-")), "")
        cw = (v.get("database_specific") or {}).get("cwe_ids") or []
        return cve, sorted({c for c in cw if str(c).startswith("CWE-")})

    if sha:
        owners = [v for v in vulns
                  if any(f.startswith(sha) or sha.startswith(f) for f in _fix_commits(v))]
        if len(owners) == 1:
            return pick(owners[0])
        if len(owners) > 1:
            cves = {pick(v)[0] for v in owners}
            if len(cves) == 1:
                return pick(owners[0])
            return "", []
    # No fix-commit attribution: only trust a response naming a single advisory.
    if len(vulns) == 1:
        return pick(vulns[0])
    return "", []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    prov = list(csv.DictReader(open(PROV, encoding="utf-8"), delimiter="\t"))
    done = set()
    if os.path.exists(DONE):
        done = {r["pair_id"] for r in csv.DictReader(open(DONE, encoding="utf-8"),
                                                     delimiter="\t")}
    todo = [r for r in prov if r["pair_id"] not in done and r.get("sha")]
    shas = sorted({r["sha"] for r in todo})
    if args.limit:
        shas = shas[:args.limit]
    print(f"{len(todo)} records / {len(shas)} distinct shas to resolve", flush=True)

    resolved, tally = {}, collections.Counter()
    for n, sha in enumerate(shas):
        cached = os.path.exists(os.path.join(CACHE, f"{sha}.json"))
        d = query(sha)
        if not cached:
            time.sleep(DELAY)
        if n % 100 == 0:
            print(f"  {n}/{len(shas)}  resolved={len(resolved)}", flush=True)
        if d is None:
            tally["query_failed"] += 1
            continue
        cve, cwes = cve_and_cwe(d, sha)
        if not cve:
            tally["no_advisory_for_commit"] += 1
            continue
        resolved[sha] = (cve, "|".join(cwes))
        tally["RESOLVED_SHA"] += 1

    out = []
    for r in todo:
        got = resolved.get(r["sha"])
        if not got:
            continue
        cve, cwes = got
        out.append(dict(pair_id=r["pair_id"], label=r["label"], repo=r["repo"],
                        sha=r["sha"], cve=cve, cwe_authoritative=cwes,
                        cwe_derived=r.get("cwe_derived", ""),
                        src_file=r.get("src_file", ""),
                        agrees=str(bool(cwes and r.get("cwe_derived") in cwes.split("|")))))

    for k, v in tally.most_common():
        print(f"  {k:26s} {v:6d}")
    if out:
        pairs = len({r["pair_id"] for r in out})
        withcwe = [r for r in out if r["cwe_authoritative"]]
        agree = sum(1 for r in withcwe if r["agrees"] == "True")
        print(f"\n  records resolved : {len(out)}")
        print(f"  distinct pairs   : {pairs}")
        if withcwe:
            print(f"  with a CWE       : {len(withcwe)}  "
                  f"derived agreed {agree}/{len(withcwe)} "
                  f"({100*agree/len(withcwe):.1f}%)")
    if args.write and out:
        with open(OUT, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(out[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(out)
        print(f"\n-> {OUT} ({len(out)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
