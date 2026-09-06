"""Harvest JavaScript guards from the already-cached npm patches.

No network: the npm harvest fetched 3,798 patches and they were filtered to
.ts/.tsx only, discarding the JavaScript. 1,787 of those same commits carry JS
source, with the same OSV -> GHSA -> CVE -> repo -> sha provenance chain.

Writes a funnel and a candidate table. NOTHING is trusted here -- the next step is
hand-inspection of a sample to find the leak classes, exactly as the TS gates were
derived.

    python harvest_js_guards.py [--sample N]
"""
import argparse
import collections
import csv
import os
import re
import sys

import js_guard_gates as G

PATCH_DIR = "data/osv/patches"
OUT = "data/osv/js_guard_candidates.tsv"
_FILE = re.compile(r"^\+\+\+ b/(.+)$", re.M)


def js_added_by_file(patch):
    """{path: [added lines]} for real JS source files only."""
    out, cur = {}, None
    for line in patch.splitlines():
        if line.startswith("+++ b/"):
            p = line[6:].strip()
            cur = p if G.is_js_source(p) else None
            if cur:
                out.setdefault(cur, [])
        elif line.startswith(("diff --git", "--- ")):
            cur = None
        elif cur and line.startswith("+") and not line.startswith("+++"):
            out[cur].append(line[1:])
    return {k: v for k, v in out.items() if v}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=0, help="stop after N patches")
    a = ap.parse_args()

    pats = sorted(os.listdir(PATCH_DIR))
    pats = [p for p in pats if p.endswith(".patch")]
    if a.sample:
        pats = pats[: a.sample]
    print(f"patches to scan: {len(pats)}", flush=True)

    f = collections.Counter()
    rows = []
    for name in pats:
        path = os.path.join(PATCH_DIR, name)
        try:
            patch = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            f["unreadable"] += 1
            continue
        byfile = js_added_by_file(patch)
        if not byfile:
            f["no_js_source_file"] += 1
            continue
        f["has_js_source"] += 1

        # generated-file banner in the added lines -> not hand-written code
        blob = "\n".join(l for v in byfile.values() for l in v)
        if G.looks_generated(blob):
            f["generated_banner"] += 1
            continue

        total_added = sum(len(v) for v in byfile.values())
        if total_added > 400:
            f["too_many_added_lines"] += 1
            continue

        # pick the guard from the file with the most added lines, so the excerpt
        # anchors on the file the fix actually changed
        best_file = max(byfile, key=lambda k: len(byfile[k]))
        guard = G.pick_js_guard(byfile[best_file], best_file)
        if not guard:
            # try the other changed files before giving up
            for p2, added in sorted(byfile.items(), key=lambda kv: -len(kv[1])):
                if p2 == best_file:
                    continue
                guard = G.pick_js_guard(added, p2)
                if guard:
                    best_file = p2
                    break
        if not guard:
            f["no_quotable_guard"] += 1
            continue

        f["GUARD_FOUND"] += 1
        stem = os.path.splitext(name)[0]
        sha = stem.rsplit("__", 1)[-1] if "__" in stem else ""
        owner_repo = stem.rsplit("__", 1)[0].replace("__", "/", 1) if "__" in stem else ""
        rows.append(dict(n=len(rows) + 1, guard=guard[:200], file=best_file[:90],
                         repo=owner_repo, sha=sha, patch=path,
                         n_js_files=len(byfile), added=total_added))

    cols = ["n", "guard", "file", "repo", "sha", "n_js_files", "added", "patch"]
    with open(OUT, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, delimiter="\t", extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    print("\n=== funnel ===")
    for k, v in f.most_common():
        print(f"  {k:24s} {v}")
    print(f"\ncandidates: {len(rows)} -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
