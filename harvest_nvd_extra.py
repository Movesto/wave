"""Small probe: do the NVD-only TypeScript CVEs add usable guards?

Of the 112 GitHub commits behind NVD's 180 `keyword=typescript` CVEs, 80 were
already in the OSV/npm harvest. This processes ONLY the ~32 that were not, through
the same gates, to measure whether a second source is worth pursuing before
scaling anything.

Deliberately small. NVD's real value was never the keyword search -- it is that
its records point at populations OSV's npm feed cannot reach (runtimes and
applications rather than published packages).

    python harvest_nvd_extra.py
"""
import collections
import csv
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

import ts_guard_gates as G
from harvest_osv_ts import find_local_clone, patch_from_clone

NVD = "data/osv/nvd_typescript_commits.json"
OSV_CAND = "data/osv/npm_candidates.tsv"
PATCH_DIR = "data/osv/nvd_patches"
OUT = "data/osv/nvd_extra_guards.tsv"

_COMMIT = re.compile(r"github\.com/([^/\s]+)/([^/\s]+)/commit/([0-9a-fA-F]{7,40})")
_FILE = re.compile(r"^\+\+\+ b/(.+)$", re.M)


def fetch_patch(owner, repo, sha):
    os.makedirs(PATCH_DIR, exist_ok=True)
    dest = os.path.join(PATCH_DIR, f"{owner}__{repo}__{sha}.patch")
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        return open(dest, encoding="utf-8", errors="replace").read(), "cached"
    clone = find_local_clone(owner, repo)
    if clone:
        txt = patch_from_clone(clone, sha)
        if txt:
            open(dest, "w", encoding="utf-8").write(txt)
            return txt, "clone"
    url = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
    req = urllib.request.Request(url, headers={"User-Agent": "wave-nvd-probe"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            txt = r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return None, f"http_{e.code}"
    except Exception:
        return None, "fetch_failed"
    open(dest, "w", encoding="utf-8").write(txt)
    return txt, "http"


def ts_added(patch):
    """Added lines belonging to real (non-test) TS source files."""
    out, ok = [], False
    for line in patch.splitlines():
        if line.startswith("+++ b/"):
            ok = G.is_ts_source(line[6:])
        elif line.startswith(("diff --git", "--- ")):
            ok = False
        elif ok and line.startswith("+") and not line.startswith("+++"):
            out.append(line[1:])
    return out


def main():
    nvd = json.load(open(NVD, encoding="utf-8"))
    have = set()
    with open(OSV_CAND, encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            have.add(row["sha"].lower()[:12])

    # the NVD-only commits
    todo = []
    for r in nvd:
        for u in r["commits"]:
            m = _COMMIT.search(u)
            if not m:
                continue
            owner, repo, sha = m.group(1), m.group(2), m.group(3)
            if repo.endswith(".git"):
                repo = repo[:-4]
            if sha.lower()[:12] in have:
                continue
            todo.append((r["cve"], owner, repo, sha))
    # dedupe on sha
    seen, uniq = set(), []
    for t in todo:
        if t[3].lower()[:12] in seen:
            continue
        seen.add(t[3].lower()[:12])
        uniq.append(t)
    print(f"NVD-only commits to probe: {len(uniq)}", flush=True)

    f = collections.Counter()
    rows = []
    for cve, owner, repo, sha in uniq:
        patch, how = fetch_patch(owner, repo, sha)
        f[how] += 1
        if not patch:
            continue
        files = [x.strip() for x in _FILE.findall(patch)]
        ts = [x for x in files if G.is_ts_source(x)]
        if not ts:
            f["no_ts_source_file"] += 1
            continue
        f["has_ts_source"] += 1
        added = ts_added(patch)
        if not added:
            f["no_added_ts_lines"] += 1
            continue
        if len(added) > 400:
            f["too_many_added_lines"] += 1
            continue
        guard = G.pick_ts_guard(added)
        if not guard:
            f["no_quotable_guard"] += 1
            continue
        f["GUARD_FOUND"] += 1
        rows.append(dict(cve=cve, repo=f"{owner}/{repo}", sha=sha,
                         file=ts[0][:70], guard=guard[:150],
                         patch=os.path.join(PATCH_DIR, f"{owner}__{repo}__{sha}.patch")))
        if how == "http":
            time.sleep(1.0)

    cols = ["cve", "repo", "sha", "file", "guard", "patch"]
    with open(OUT, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, delimiter="\t", extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    print("\n=== funnel ===")
    for k, v in f.most_common():
        print(f"  {k:24s} {v}")
    print(f"\nguards: {len(rows)} -> {OUT}")
    if rows:
        print("\nsample:")
        for r in rows[:10]:
            print(f"  {r['cve']:16s} {r['repo'][:26]:26s} {r['guard'][:60]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
