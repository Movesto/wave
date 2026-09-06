"""Harvest React-family fix commits from the OSV npm dump.

The earlier count of 58 was the wrong denominator: it filtered on commits touching
`.ts`/`.tsx`, which misses React fixes that land in `.js` and misses whole packages
whose commits were never pulled. Searching by PACKAGE instead finds 108 react-family
advisories, 53 of them with a fix commit.

React is worth the effort out of proportion to its size: it scored MCC 0.620 and
REGRESSED in v12.1b, and its only volume today is 600 synthetic records that were
measured not to transfer (100% on themselves, 41.2% on real react).

Stage 1 fetches the patches (cached, resumable, no key needed); stage 2 gates them.
Reuses the existing OSV harvest machinery rather than reimplementing it.

    python harvest_react_osv.py --stage advisories
    python harvest_react_osv.py --stage patches
"""
import argparse
import collections
import csv
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import zipfile

DUMP = "data/osv/npm_all.zip"
OUT = "data/osv/react_targets.tsv"
PATCHES = "data/osv/patches"

# React family, by package name. `jsx` catches the odd tooling package; `next` is
# included because Next.js auth middleware fixes are React-ecosystem authorization
# code and exactly the guard shape our picker handles best.
REACT = re.compile(r"(^|[-/@])react([-/.]|$)|preact|next\.?js|gatsby|remix|jsx", re.I)
_COMMIT = re.compile(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})", re.I)
REACT_EXT = (".jsx", ".tsx", ".js", ".ts", ".mjs", ".cjs")


def advisories():
    z = zipfile.ZipFile(DUMP)
    rows, seen = [], set()
    for n in z.namelist():
        if not n.endswith(".json"):
            continue
        try:
            d = json.loads(z.read(n))
        except Exception:
            continue
        pkgs = {a.get("package", {}).get("name", "") for a in (d.get("affected") or [])}
        if not any(REACT.search(p or "") for p in pkgs):
            continue
        # The npm feed is 97% malicious-package reports; they are not code fixes.
        if "malicious" in (d.get("summary") or "").lower():
            continue
        cwes = (d.get("database_specific") or {}).get("cwe_ids") or []
        aliases = d.get("aliases") or []
        cve = next((a for a in aliases if a.startswith("CVE-")), "")
        for r in d.get("references") or []:
            m = _COMMIT.search(r.get("url") or "")
            if not m:
                continue
            owner, repo, sha = m.group(1), m.group(2), m.group(3).lower()
            key = (owner, repo, sha)
            if key in seen:
                continue
            seen.add(key)
            rows.append(dict(id=d.get("id", ""), cve=cve, owner=owner, repo=repo,
                             sha=sha, cwes="|".join(c for c in cwes if str(c).startswith("CWE-")),
                             pkg=sorted(p for p in pkgs if REACT.search(p or ""))[:1][0]
                             if pkgs else "",
                             summary=(d.get("summary") or "")[:120]))
    with open(OUT, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), delimiter="\t")
        w.writeheader()
        w.writerows(rows)
    print(f"react advisories with a fix commit: {len(rows)} -> {OUT}")
    print("  with a CWE:", sum(1 for r in rows if r["cwes"]))
    print("  with a CVE:", sum(1 for r in rows if r["cve"]))


def fetch(owner, repo, sha):
    """Cached .patch fetch. `gh` is not installed here and the REST API is 60/hr
    unauthenticated, so the web .patch endpoint is what makes this feasible."""
    os.makedirs(PATCHES, exist_ok=True)
    path = os.path.join(PATCHES, f"{owner}__{repo}__{sha[:12]}.patch")
    if os.path.exists(path):
        return path, "cached"
    url = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
    try:
        with urllib.request.urlopen(url, timeout=45) as r:
            data = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return None, f"http_{e.code}"
    except Exception as e:
        return None, type(e).__name__
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(data)
    return path, "fetched"


def patches():
    rows = list(csv.DictReader(open(OUT, encoding="utf-8"), delimiter="\t"))
    tally = collections.Counter()
    keep = []
    for i, r in enumerate(rows):
        path, how = fetch(r["owner"], r["repo"], r["sha"])
        tally[how] += 1
        if how == "fetched":
            time.sleep(1.2)
        if not path:
            continue
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        files = [m.group(2) for m in re.finditer(r"^diff --git a/(.+?) b/(.+?)\s*$",
                                                 text, re.M)]
        src = [f for f in files if f.endswith(REACT_EXT)
               and not re.search(r"(^|/)(tests?|__tests__|spec|dist|build|node_modules)/", f)
               and not re.search(r"\.(test|spec|min)\.", f)]
        if not src:
            tally["no_react_source"] += 1
            continue
        r["files"] = "|".join(src[:6])
        r["patch"] = path
        keep.append(r)
        if (i + 1) % 10 == 0:
            print(f"  [{i+1}/{len(rows)}] {len(keep)} usable", flush=True)
    with open(OUT, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(keep[0].keys()), delimiter="\t")
        w.writeheader()
        w.writerows(keep)
    for k, v in tally.most_common():
        print(f"  {k:20s} {v}")
    print(f"\nusable react fix commits: {len(keep)} -> {OUT}")
    ext = collections.Counter(f.rsplit(".", 1)[-1]
                              for r in keep for f in r["files"].split("|"))
    print("  by extension:", dict(ext.most_common()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=("advisories", "patches"), required=True)
    args = ap.parse_args()
    (advisories if args.stage == "advisories" else patches)()
    return 0


if __name__ == "__main__":
    sys.exit(main())
