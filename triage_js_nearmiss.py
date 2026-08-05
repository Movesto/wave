"""Which hand-vetted JS guards did NOT become pairs, and how close were they?

These 44 all passed hand-vetting, so they are genuine security controls aligned
with the goal. Some then failed a MECHANICAL gate in the pair builder. Per the
instruction "dropping shouldn't be the case", this classifies each near-miss by
what it failed and how much work it would take to recover, so the salvageable ones
can be worked rather than lost.

    python triage_js_nearmiss.py
"""
import collections
import csv
import json
import sys

import build_js_contrastive as B
import js_guard_gates as JG
from build_ts_contrastive import changed_line_texts, file_at, parse_hunks
from harvest_osv_ts import find_local_clone

OUT = "data/osv/js_nearmiss_triage.tsv"

# how much work each failure represents, and whether it is worth it
EFFORT = {
    "guard_already_in_vuln": ("HIGH VALUE - not a defect",
                              "guard present in BOTH sides = the guard-present-but-"
                              "exploitable class the corpus lacks; rebuild as a "
                              "completeness pair rather than a contrastive one"),
    "vuln_size": ("EASY", "excerpt outside 120-4500 chars; widen or narrow extraction"),
    "fixed_size": ("EASY", "excerpt outside 120-4500 chars; widen or narrow extraction"),
    "no_source": ("MEDIUM", "no identifier from the guard occurs in BOTH sides outside "
                            "string literals; needs a better source derivation or a "
                            "wider excerpt"),
    "sink_not_in_both": ("MEDIUM", "sink absent from one side; usually the excerpt is "
                                   "cut too tight"),
    "no_distinct_sink": ("MEDIUM", "source and sink resolved to the same name"),
    "guard_hunk_not_found": ("HARD", "guard not located in any JS hunk of the patch"),
    "sides_identical": ("HARD", "the two revisions of the excerpt do not differ"),
    "patch_unreadable": ("HARD", "patch file missing"),
    "no_cwe": ("EASY", "no CWE resolved from any source; needs manual assignment"),
}


def outcome_for(r):
    """Re-run the builder's gates for one guard and report where it stops."""
    guard = r["guard"].strip()
    try:
        patch = open(r["patch"], encoding="utf-8", errors="replace").read()
    except OSError:
        return "patch_unreadable"

    by_file = collections.OrderedDict()
    for path, hunk in parse_hunks(patch):
        if JG.is_js_source(path):
            by_file.setdefault(path, []).append(hunk)
    chosen = next((p for p, hs in by_file.items()
                   if any(guard in l[1:] for h in hs for l in h if l.startswith("+"))), None)
    if not chosen:
        return "guard_hunk_not_found"

    vuln = fixed = None
    owner, repo = r["repo"].split("/", 1) if "/" in r["repo"] else (None, None)
    clone = find_local_clone(owner, repo) if owner else None
    sha = r.get("sha", "")
    if clone and sha:
        vp, fp, used = [], [], 0
        for p2 in [chosen] + [p for p in by_file if p != chosen]:
            if used > B.MAX_CODE_CHARS:
                break
            ft, vt = file_at(clone, sha, p2), file_at(clone, f"{sha}^", p2)
            if not (ft and vt):
                continue
            nd = changed_line_texts(by_file[p2])
            fr, vr = B.js_regions(ft, nd), B.js_regions(vt, nd)
            if not fr or not vr:
                continue
            vp.append(vr)
            fp.append(fr)
            used += len(fr) + len(vr)
        if vp and any(guard in x for x in fp) and not any(guard in x for x in vp):
            vuln, fixed = "\n\n".join(vp), "\n\n".join(fp)
    if vuln is None:
        vp, fp = [], []
        for p2, hunks in by_file.items():
            for h in hunks:
                v, fx = B.sides_from_hunk(h)
                if v.strip():
                    vp.append(v)
                if fx.strip():
                    fp.append(fx)
        vuln, fixed = "\n".join(vp), "\n".join(fp)

    if guard not in fixed:
        return "guard_not_in_fixed"
    if guard in vuln:
        return "guard_already_in_vuln"
    if B._norm(vuln) == B._norm(fixed):
        return "sides_identical"
    if not (B.MIN_CODE_CHARS <= len(vuln) <= B.MAX_CODE_CHARS):
        return "vuln_size"
    if not (B.MIN_CODE_CHARS <= len(fixed) <= B.MAX_CODE_CHARS):
        return "fixed_size"
    src = B.pick_source(guard, vuln, fixed)
    snk = B.pick_sink(vuln)
    if not src:
        return "no_source"
    if not snk or snk == src:
        return "no_distinct_sink"
    if snk not in vuln or snk not in fixed:
        return "sink_not_in_both"
    if not r.get("cwe_final"):
        return "no_cwe"
    return "BUILT"


def main():
    rows = list(csv.DictReader(open("data/osv/js_guard_enriched.tsv", encoding="utf-8"),
                               delimiter="\t"))
    out, tally = [], collections.Counter()
    for r in rows:
        why = outcome_for(r)
        tally[why] += 1
        if why == "BUILT":
            continue
        eff, note = EFFORT.get(why, ("UNKNOWN", ""))
        out.append(dict(n=r["n"], cwe=r.get("cwe_final", ""), repo=r["repo"],
                        file=r["file"], failed=why, effort=eff, note=note,
                        cve=r.get("cve", ""), guard=r["guard"][:120]))

    order = {"HIGH VALUE - not a defect": 0, "EASY": 1, "MEDIUM": 2, "HARD": 3, "UNKNOWN": 4}
    out.sort(key=lambda r: (order.get(r["effort"], 9), r["cwe"]))
    cols = ["effort", "failed", "cwe", "cve", "repo", "file", "note", "guard", "n"]
    with open(OUT, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, delimiter="\t", extrasaction="ignore")
        w.writeheader()
        w.writerows(out)

    print("=== outcome of all 44 vetted guards ===")
    for k, v in tally.most_common():
        print(f"  {k:24s} {v}")
    print(f"\nnear-misses: {len(out)} -> {OUT}\n")
    grp = collections.defaultdict(list)
    for r in out:
        grp[r["effort"]].append(r)
    for eff in sorted(grp, key=lambda e: order.get(e, 9)):
        rs = grp[eff]
        cwes = collections.Counter(r["cwe"] for r in rs if r["cwe"])
        print(f"--- {eff}  ({len(rs)}) ---")
        print(f"    CWEs: {dict(cwes.most_common())}")
        for r in rs[:6]:
            print(f"    [{r['failed']:22s}] {r['cwe']:9s} {r['repo'][:26]:26s} {r['guard'][:52]}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
