"""Recover provenance for corpus records that were built without it.

~40K records descend from real commits but store no repo/sha/cve, so they cannot
be audited against anything. The upstream datasets they came from DO carry those
fields, and we hold them locally. Rejoining on the code itself puts the lineage
back without re-harvesting.

Matching is on code with all whitespace removed: reformatting is not a difference
in identity, but any token change is. Ambiguous matches -- the same function text
appearing under several CVEs -- are reported, never silently resolved to one.

    python reidentify_corpus.py --measure      # match rates only, writes nothing
    python reidentify_corpus.py --write        # emit the provenance map
"""
import argparse
import collections
import csv
import hashlib
import json
import os
import re
import sys

OUT = "data/osv/corpus_provenance.tsv"
CORPUS_DIRS = ("data/cot/pilot/", "data/cot/staging/")


def norm(code):
    return hashlib.sha1(re.sub(r"\s+", "", code).encode("utf-8", "replace")).hexdigest()


def scan_body(user_content):
    """The code inside <SCAN>...</SCAN>, or the whole message if unwrapped."""
    m = re.search(r"<SCAN>\n?(.*?)\n?</SCAN>", user_content, re.S)
    return m.group(1) if m else user_content


def build_r2vul_index():
    from datasets import load_from_disk
    ds = load_from_disk("data/r2vul_dataset")
    idx = collections.defaultdict(list)
    for split in ds:
        for r in ds[split]:
            fn = r.get("function") or ""
            if len(fn) < 40:
                continue
            cwes = r.get("cwe_id") or []
            idx[norm(fn)].append({
                "repo": r.get("repo", ""),
                "sha": r.get("parent_commit_sha", ""),
                "cve": r.get("cve_id", ""),
                "cwe": "|".join(cwes) if isinstance(cwes, list) else str(cwes),
                "file": r.get("file", ""),
                "upstream": f"r2vul:{split}",
                "vulnerable": r.get("vulnerable", ""),
            })
    return idx


def build_cvefixes_index(limit_mb=900):
    """CVEFixes.csv is large; stream it and keep only the code->provenance map."""
    path = "data/downloads/CVEfixes/CVEFixes.csv"
    if not os.path.exists(path):
        return {}
    idx = collections.defaultdict(list)
    try:
        csv.field_size_limit(sys.maxsize)
    except OverflowError:
        csv.field_size_limit(2**31 - 1)
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        rd = csv.DictReader(fh)
        cols = {c.lower(): c for c in (rd.fieldnames or [])}
        code_col = next((cols[c] for c in ("code", "func_before", "function", "code_before")
                         if c in cols), None)
        if not code_col:
            return {}
        for row in rd:
            code = row.get(code_col) or ""
            if len(code) < 40:
                continue
            idx[norm(code)].append({
                "repo": row.get(cols.get("repo_name", ""), "") or row.get(cols.get("repo", ""), ""),
                "sha": row.get(cols.get("hash", ""), ""),
                "cve": row.get(cols.get("cve_id", ""), ""),
                "cwe": row.get(cols.get("cwe_id", ""), ""),
                "file": row.get(cols.get("filename", ""), ""),
                "upstream": "cvefixes",
                "vulnerable": "",
            })
    return idx


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    print("building upstream indexes...", flush=True)
    idx = build_r2vul_index()
    print(f"  r2vul: {len(idx)} distinct function texts", flush=True)
    try:
        cf = build_cvefixes_index()
        for k, v in cf.items():
            idx[k].extend(v)
        print(f"  cvefixes: +{len(cf)} distinct", flush=True)
    except Exception as e:
        print(f"  cvefixes: skipped ({type(e).__name__}: {e})", flush=True)

    per_shape = collections.defaultdict(lambda: collections.Counter())
    rows = []
    for d in CORPUS_DIRS:
        for f in sorted(os.listdir(d)):
            if not f.endswith(".jsonl"):
                continue
            shape = f[:-6]
            for i, line in enumerate(open(d + f, encoding="utf-8")):
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                m = r.get("_meta") or {}
                msgs = r.get("messages") or []
                if not msgs:
                    continue
                if m.get("repo") or m.get("sha") or m.get("cve"):
                    per_shape[shape]["already_had"] += 1
                    continue
                code = scan_body(msgs[0].get("content", ""))
                hits = idx.get(norm(code))
                if not hits:
                    per_shape[shape]["no_match"] += 1
                    continue
                repos = {h["repo"] for h in hits}
                cves = {h["cve"] for h in hits}
                if len(repos) > 1 or len(cves) > 1:
                    per_shape[shape]["ambiguous"] += 1
                    status = "ambiguous"
                else:
                    per_shape[shape]["matched"] += 1
                    status = "matched"
                h = hits[0]
                rows.append(dict(shape=shape, line=i, status=status,
                                 repo=h["repo"], sha=h["sha"], cve=h["cve"],
                                 cwe_upstream=h["cwe"], file=h["file"],
                                 upstream=h["upstream"],
                                 corpus_cwe=m.get("ground_truth_cwe", ""),
                                 n_candidates=len(hits)))

    print(f"\n{'shape':30s} {'matched':>8s} {'ambig':>7s} {'no match':>9s} {'had':>6s}")
    print("-" * 66)
    tm = ta = tn = 0
    for shape in sorted(per_shape, key=lambda s: -sum(per_shape[s].values())):
        c = per_shape[shape]
        if not sum(c.values()):
            continue
        print(f"  {shape:28s} {c['matched']:8d} {c['ambiguous']:7d} "
              f"{c['no_match']:9d} {c['already_had']:6d}")
        tm += c["matched"]; ta += c["ambiguous"]; tn += c["no_match"]
    print("-" * 66)
    tot = tm + ta + tn
    print(f"  {'TOTAL':28s} {tm:8d} {ta:7d} {tn:9d}")
    if tot:
        print(f"\n  re-identified: {tm + ta}/{tot} = {100 * (tm + ta) / tot:.1f}%")

    # Free audit: the match gives us an independent CWE for each record.
    agree = collections.Counter()
    for r in rows:
        ours = (r["corpus_cwe"] or "").strip()
        up = set(x.strip() for x in (r["cwe_upstream"] or "").split("|") if x.strip())
        if not ours or not up:
            agree["one_side_missing"] += 1
        elif ours in up:
            agree["agree"] += 1
        else:
            agree["DISAGREE"] += 1
    n = sum(agree.values())
    if n:
        print("\n  CWE cross-check against upstream (independent label):")
        for k, v in agree.most_common():
            print(f"    {k:20s} {v:6d}  {100*v/n:5.1f}%")

    if args.write and rows:
        with open(OUT, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(rows)
        print(f"\n-> {OUT} ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
