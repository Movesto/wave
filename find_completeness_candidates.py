"""Find pairs where the VULNERABLE side already contains a control.

The counterexample class -- guard present and the code still exploitable -- is 33
pairs, and it is the class the whole project exists to teach. No weight fixes 33.

Every builder discards these. `guard in vuln` is treated as a defect ("the fix did
not actually ADD the control") and the pair is dropped. For an ordinary contrastive
pair that is right. But a fix whose vulnerable side ALREADY has a control of the same
class is exactly the shape we are missing: the guard is there, it looks adequate, and
the CVE proves it was not.

Two signatures, both checkable rather than judged:

  SAME-CLASS   the fix strengthens a control that already exists -- the vuln side
               holds a guard hitting the same security vocabulary as the added one.
               `set-in` is this: a POLLUTED_KEYS assert existed for CVE-2020-28273
               and covered only the final assignment.

  SECOND-PATH  the added guard is a near-duplicate of one already present elsewhere
               in the vuln side, i.e. the control existed and one entry point
               lacked it.

Reports candidates for reading. It does not build -- these need a human to say WHY
the present guard is insufficient, and that sentence is the entire teaching value.

    python find_completeness_candidates.py
"""
import collections
import csv
import difflib
import json
import os
import re
import sys

from build_r2vul_pairs import _SECVOCAB, added_lines, pick_guard
from scan_ts_standard import code_of

OUT = "data/osv/completeness_candidates.tsv"


def vocab(line):
    return {m.group(0).lower() for m in _SECVOCAB.finditer(line or "")}


def existing_guards(code):
    """Lines in this revision that look like controls."""
    out = []
    for l in code.splitlines():
        s = l.strip()
        if len(s) < 12 or s.startswith(("//", "#", "*", "/*")):
            continue
        if re.match(r"^\s*(if|assert|require|guard|when)\b", s) or re.search(
                r"\b(validate|verify|sanitiz|escap|check|allow|deny|filter)\w*\s*\(", s, re.I):
            out.append(s)
    return out


def similar(a, b):
    return difflib.SequenceMatcher(None, a, b).ratio()


def scan_pairs(pairs, source):
    rows = []
    for pid, sides in pairs.items():
        v, s = sides.get("vuln"), sides.get("safe")
        if not v or not s:
            continue
        vc, sc = code_of(v), code_of(s)
        guard = pick_guard(vc, sc)
        if not guard:
            continue
        gv = vocab(guard)
        if not gv:
            continue
        pre = existing_guards(vc)
        if not pre:
            continue

        # SECOND-PATH: the added guard already exists nearly verbatim in the vuln side
        near = max((similar(guard, p) for p in pre), default=0)
        # SAME-CLASS: an existing guard hits the same security vocabulary
        same = [p for p in pre if gv & vocab(p)]
        if near < 0.6 and not same:
            continue

        m = v["_meta"]
        rows.append(dict(
            source=source, pair_id=pid, language=m.get("language", ""),
            cwe=m.get("ground_truth_cwe", ""), cve=m.get("cve", ""),
            repo=m.get("repo", ""),
            signature="SECOND_PATH" if near >= 0.6 else "SAME_CLASS",
            similarity=round(near, 2),
            added_guard=guard[:110],
            existing_guard=(max(same, key=len) if same
                            else max(pre, key=lambda p: similar(guard, p)))[:110]))
    return rows


def main():
    rows = []

    # 1. every paired set we hold
    for path, name in (("data/cot/staging/shape1_contrastive.jsonl", "contrastive_original"),
                       ("data/cot/staging/shape1_contrastive_attested.jsonl", "attested"),
                       ("data/cot/staging/shape1_contrastive_rebuilt.jsonl", "rebuilt_held"),
                       ("data/cot/staging/shape1_contrastive_ts_osv.jsonl", "ts_osv"),
                       ("data/cot/staging/shape1_contrastive_js_osv.jsonl", "js_osv")):
        if not os.path.exists(path):
            continue
        p = collections.defaultdict(dict)
        for line in open(path, encoding="utf-8"):
            r = json.loads(line)
            p[r["_meta"]["pair_id"]][r["_meta"]["label"]] = r
        got = scan_pairs(p, name)
        print(f"  {name:22s} {len(p):5d} pairs -> {len(got)} candidates", flush=True)
        rows.extend(got)

    # 2. r2vul map_id pairs, straight from the dataset
    try:
        from datasets import load_from_disk
        ds = load_from_disk("data/r2vul_dataset")
        g = collections.defaultdict(lambda: collections.defaultdict(list))
        for sp in ds:
            for r in ds[sp]:
                g[r.get("map_id")][r.get("vulnerable")].append(r)
        n = 0
        for mid, sides in g.items():
            if 1 not in sides or 0 not in sides:
                continue
            vf = sides[1][0].get("function") or ""
            sf = sides[0][0].get("function") or ""
            if not (120 <= len(vf) <= 4500 and 120 <= len(sf) <= 4500):
                continue
            guard = pick_guard(vf, sf)
            if not guard:
                continue
            gv = vocab(guard)
            pre = existing_guards(vf)
            if not gv or not pre:
                continue
            near = max((similar(guard, p) for p in pre), default=0)
            same = [p for p in pre if gv & vocab(p)]
            if near < 0.6 and not same:
                continue
            cw = sides[1][0].get("cwe_id") or []
            rows.append(dict(source="r2vul_map_id", pair_id=str(mid),
                             language=sides[1][0].get("lang", ""),
                             cwe=next((c for c in cw if str(c).startswith("CWE-")), ""),
                             cve=sides[1][0].get("cve_id", ""),
                             repo=sides[1][0].get("repo", ""),
                             signature="SECOND_PATH" if near >= 0.6 else "SAME_CLASS",
                             similarity=round(near, 2),
                             added_guard=guard[:110],
                             existing_guard=(max(same, key=len) if same else pre[0])[:110]))
            n += 1
        print(f"  {'r2vul_map_id':22s} {len(g):5d} groups -> {n} candidates", flush=True)
    except Exception as e:
        print(f"  r2vul skipped ({type(e).__name__}: {e})")

    if not rows:
        print("\nno candidates")
        return 0
    with open(OUT, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), delimiter="\t")
        w.writeheader()
        w.writerows(rows)
    sig = collections.Counter(r["signature"] for r in rows)
    lang = collections.Counter(r["language"] for r in rows)
    print(f"\ntotal candidates: {len(rows)}  {dict(sig)}")
    print("by language:", dict(lang.most_common(8)))
    print(f"-> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
