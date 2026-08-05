"""Put repo+sha back on shape1_verified / shape1_verified_safe, then resolve the CVE.

`probe_ctier_provenance.py` measured these two shapes at 99% and 100% recoverable
against the raw patch corpus -- 1,416 records, 6.8% of sampling. I had reported their
provenance as unrecoverable after checking `morefixes_pairs.jsonl` (messages-only) and
`CVEFixes.csv` (no provenance columns) and never checking
`data/downloads/morefixes-patches/cvedataset-patches`, which is where it actually lives
and which had already been used to attest wave3 at 99.8%.

Two stages, because they have different costs:

  --match    build the hunk index (32,008 patches, ~6 min) and cache repo+sha per
             record to a TSV. Offline.
  --resolve  turn the cached shas into CVE + authoritative CWE via OSV. Network.

The OSV rule that has already burned this project once: a commit query returns EVERY
advisory containing that commit, and 79% of shas matched more than one. The CVE and the
CWE must both be taken from the advisory that names the sha in `ranges.events[].fixed`,
never from whichever advisory came back first.

    python recover_verified_provenance.py --match
    python recover_verified_provenance.py --resolve --write
"""
import argparse
import collections
import csv
import json
import os
import re
import sys
import time

CACHE = "data/osv/verified_provenance.tsv"
SHAPES = ("shape1_verified", "shape1_verified_safe")


def path_of(shape):
    for d in ("pilot", "staging"):
        p = f"data/cot/{d}/{shape}.jsonl"
        if os.path.exists(p):
            return p
    return None


def do_match():
    from recover_contrastive_provenance import build_index, norm
    from scan_ts_standard import code_of

    print("building patch index (32,008 patches)...", flush=True)
    idx = build_index()
    print(f"index: {len(idx)} hunks", flush=True)

    rows = []
    for shape in SHAPES:
        recs = [json.loads(l) for l in open(path_of(shape), encoding="utf-8")
                if l.strip()]
        hit = 0
        for i, r in enumerate(recs):
            if r["_meta"].get("held"):
                continue
            got = idx.get(norm(code_of(r)))
            if not got:
                continue
            # build_index yields (repo, sha, path) -- the file path comes free, so
            # src_file is recovered alongside the commit rather than left blank.
            repo, sha, src_file = got
            rows.append(dict(shape=shape, index=i, repo=repo, sha=sha,
                             src_file=src_file, label=r["_meta"].get("label", "")))
            hit += 1
        print(f"  {shape:22s} {hit} matched")

    with open(CACHE, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["shape", "index", "repo", "sha", "src_file", "label"],
                           delimiter="\t")
        w.writeheader()
        w.writerows(rows)
    print(f"-> {CACHE} ({len(rows)} rows, {len({r['sha'] for r in rows})} distinct shas)")


def load_known():
    """sha -> (cve, authoritative cwe) from resolvers already run."""
    out = {}
    for p in ("data/osv/sha_to_cve_osv.tsv", "data/osv/sha_to_cve.tsv"):
        if not os.path.exists(p):
            continue
        for r in csv.DictReader(open(p, encoding="utf-8"), delimiter="\t"):
            sha = (r.get("sha") or "").lower()
            if sha and r.get("cve"):
                out[sha] = (r["cve"], r.get("cwe_authoritative", ""))
    return out


def osv_lookup(sha, session):
    """(cve, cwes) from the advisory that names THIS sha as a fix, or None.

    An OSV commit query returns every advisory whose ranges contain the commit. Taking
    the first one pairs a CVE with another advisory's CWEs -- that error cut a previous
    attested set from 398 to 223 before it was caught.
    """
    try:
        resp = session.post("https://api.osv.dev/v1/query",
                            json={"commit": sha}, timeout=30)
        if resp.status_code != 200:
            return None
        vulns = resp.json().get("vulns") or []
    except Exception:
        return None
    for v in vulns:
        names_sha = False
        for rng in v.get("affected", []):
            for r in rng.get("ranges", []):
                for ev in r.get("events", []):
                    if (ev.get("fixed") or "").lower().startswith(sha[:12].lower()):
                        names_sha = True
        if not names_sha:
            continue
        cve = v.get("id", "")
        if not cve.startswith("CVE-"):
            cve = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), cve)
        cwes = [c for c in (v.get("database_specific", {}) or {}).get("cwe_ids", [])]
        return cve, ";".join(cwes)
    return None


def do_resolve(write):
    import requests

    rows = list(csv.DictReader(open(CACHE, encoding="utf-8"), delimiter="\t"))
    known = load_known()
    shas = sorted({r["sha"] for r in rows})
    print(f"{len(rows)} records, {len(shas)} distinct shas; "
          f"{sum(1 for s in shas if s in known)} already resolved locally")

    session = requests.Session()
    resolved, f = dict(known), collections.Counter()
    todo = [s for s in shas if s not in resolved]
    for n, sha in enumerate(todo):
        if n % 50 == 0:
            print(f"  osv {n}/{len(todo)} (+{f['hit']} resolved)", flush=True)
        got = osv_lookup(sha, session)
        if got:
            resolved[sha] = got
            f["hit"] += 1
        else:
            f["miss"] += 1
        time.sleep(0.05)
    print(f"  osv done: {f['hit']} resolved, {f['miss']} unresolved")

    byshape = collections.defaultdict(list)
    for r in rows:
        byshape[r["shape"]].append(r)

    for shape, rs in byshape.items():
        p = path_of(shape)
        recs = [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
        n_prov = n_cwe = 0
        for r in rs:
            m = recs[int(r["index"])]["_meta"]
            m["repo"], m["sha"] = r["repo"], r["sha"]
            m["src_file"] = r.get("src_file", "")
            m["upstream_origin"] = "morefixes_patch"
            n_prov += 1
            got = resolved.get(r["sha"])
            if not got:
                continue
            cve, cwe = got
            m["cve"] = cve
            if cwe:
                # OSV joins multiple classes with `|` as well as `;`
                # (`CWE-22|CWE-23`). Splitting on `;` alone left a compound string as
                # the single ground-truth label, which is not a CWE.
                first = re.split(r"[;|]", cwe)[0].strip()
                # Only OVERWRITE an upstream_dataset label; never downgrade a CISA/OSV
                # one, and never touch a safe record's (a safe side has no CWE).
                if m.get("label") != "safe" and m.get("cwe_source") in (
                        None, "", "upstream_dataset"):
                    m["cwe_was"] = m.get("ground_truth_cwe", "")
                    m["ground_truth_cwe"] = first
                    m["cwe_source"] = "osv_advisory"
                    n_cwe += 1
        print(f"  {shape:22s} repo+sha on {n_prov}, authoritative CWE on {n_cwe}")
        if write:
            with open(p, "w", encoding="utf-8") as fh:
                for rec in recs:
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    if write:
        print("written")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--match", action="store_true")
    ap.add_argument("--resolve", action="store_true")
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()
    if args.match:
        do_match()
    if args.resolve:
        do_resolve(args.write)
    return 0


if __name__ == "__main__":
    sys.exit(main())
