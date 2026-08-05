"""Rebuild the wave3 shapes to the standard.

6,275 records with zero provenance and the sft/wave3 boilerplate template ("The fix
adds a control the vulnerable code lacks"), which is 51% of them. But the code came
from the same `cvedataset-patches` corpus as everything else -- 99.8% of it matches
a hunk in those files -- so repo+sha are recoverable and the CVE follows.

That matters more than the trace does. A wave3 record's CWE is present on the vuln
side only and was derived the same way the contrastive set's was; that classifier
agreed with CISA/OSV on 19.7% of 3,215 checked records. Fixing the trace while
keeping a label that is wrong four times in five would be polishing the wrong half.

So: recover repo+sha by code match, resolve the CVE and an authoritative CWE from
the sha, and REBUILD the pair from the two revisions rather than repairing prose.
Anything whose label cannot be established is HELD, not shipped.

    python rebuild_wave3.py --write
"""
import argparse
import collections
import csv
import hashlib
import json
import os
import re
import sys

from build_r2vul_pairs import (MAX_CODE_CHARS, added_lines, pick_guard, pick_sink,
                               pick_source, standalone)
from build_r2vul_pairs import record as guard_record
from build_crossfile_restructure import _CWE_FOR
from build_r2vul_restructure import pick_removal
from build_r2vul_restructure import record as restructure_record
from filter_corpus import is_test_code, load_eval_codes
from recover_contrastive_provenance import build_index, norm
from scan_ts_standard import code_of

SRCS = ("data/cot/pilot/shape1_wave3_other.jsonl",
        "data/cot/pilot/shape1_wave3_jsts.jsonl")
OUT_ATT = "data/cot/staging/shape1_wave3_attested.jsonl"
OUT_RESTR = "data/cot/staging/shape_restructure_wave3.jsonl"
HELD = "data/osv/wave3_held.tsv"
MIN_CHARS = 120


def load_sha_lineage():
    """sha -> (cve, authoritative cwes), from the resolvers already run."""
    out = {}
    for path in ("data/osv/sha_to_cve_osv.tsv", "data/osv/sha_to_cve.tsv"):
        if not os.path.exists(path):
            continue
        for r in csv.DictReader(open(path, encoding="utf-8"), delimiter="\t"):
            sha = (r.get("sha") or "").lower()
            if sha:
                out[sha] = (r.get("cve", ""), r.get("cwe_authoritative", ""))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    evalcodes = load_eval_codes()
    lineage = load_sha_lineage()
    print(f"sha lineage: {len(lineage)} shas", flush=True)
    print("building patch index...", flush=True)
    idx = build_index()
    print(f"index: {len(idx)} hunks", flush=True)

    # Group the two sides of a fix by the (repo, sha, file) they came from: wave3
    # stores no pair_id, so the patch is what tells us which vuln and safe belong
    # together.
    groups = collections.defaultdict(dict)
    f = collections.Counter()
    for src in SRCS:
        for line in open(src, encoding="utf-8"):
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            m = r.get("_meta") or {}
            code = code_of(r)
            hit = idx.get(norm(code))
            f["total"] += 1
            if not hit:
                f["no_patch_match"] += 1
                continue
            repo, sha, path = hit
            groups[(repo, sha, path)][m.get("label")] = (r, code, m)

    # One CVE must not dominate. A single multi-file PHP commit (CVE-2022-45962)
    # produced 8 of the first 33 pairs -- 24% -- and its CWE-89 label was stamped on
    # every hunk it touched, including an `echo "<FORM ..."` and an `if ($index_count)`.
    # The CVE's CWE describes the vulnerability, not each file the commit edited.
    MAX_PER_CVE = 2
    per_cve = collections.Counter()

    # SINGLE-FILE COMMITS ONLY. On a multi-file commit the CVE's CWE describes the
    # vulnerability, not whichever hunk we happened to pick -- which is how a
    # session-existence check ended up labelled CWE-89 (SQL injection) and a
    # hardcoded bcrypt hash became the guard for CWE-674. When the commit touches
    # one source file, the CVE's CWE has to be about that file. 64% of the patch
    # corpus qualifies, so this is a real constraint rather than a token one.
    files_per_sha = {}
    if os.path.exists("/tmp/files_per_sha.json"):
        files_per_sha = json.load(open("/tmp/files_per_sha.json"))

    out_att, out_restr, held = [], [], []
    for (repo, sha, path), sides in groups.items():
        if "vuln" not in sides or "safe" not in sides:
            f["side_missing"] += 1
            continue
        (_, vc, vm), (_, sc, _sm) = sides["vuln"], sides["safe"]
        lang = vm.get("language", "")
        pid = hashlib.sha1(f"wave3|{repo}|{sha}|{path}".encode()).hexdigest()[:12]

        if not (MIN_CHARS <= len(vc) <= MAX_CODE_CHARS
                and MIN_CHARS <= len(sc) <= MAX_CODE_CHARS):
            f["size"] += 1
            held.append(dict(pair_id=pid, reason="size", repo=repo, sha=sha, lang=lang))
            continue
        if is_test_code(vc) or is_test_code(sc):
            f["test_code"] += 1
            held.append(dict(pair_id=pid, reason="test_code", repo=repo, sha=sha, lang=lang))
            continue
        if any(re.sub(r"\s+", " ", x).strip().lower() in evalcodes for x in (vc, sc)):
            f["eval_leakage"] += 1
            continue
        if not (1 <= len(added_lines(vc, sc)) <= 24):
            f["diff_too_large_or_empty"] += 1
            held.append(dict(pair_id=pid, reason="diff_size", repo=repo, sha=sha, lang=lang))
            continue

        nfiles = files_per_sha.get(sha.lower()) or files_per_sha.get(sha)
        if nfiles is not None and nfiles > 1:
            f["multi_file_commit_cwe_unsafe"] += 1
            held.append(dict(pair_id=pid, reason="multi_file_commit", repo=repo,
                             sha=sha, lang=lang))
            continue
        cve, auth = lineage.get(sha.lower(), ("", ""))
        auth_cwes = [c for c in auth.split("|") if c.startswith("CWE-")]
        meta = dict(language=lang, cve=cve, repo=repo.replace("_", "/", 1), sha=sha,
                    src_file=path, upstream_origin="wave3_patch",
                    fix_status="rebuilt_from_patch")

        guard = pick_guard(vc, sc)
        if guard:
            if len(auth_cwes) != 1:
                f["no_trustworthy_cwe"] += 1
                held.append(dict(pair_id=pid, reason="cwe_unresolved", repo=repo,
                                 sha=sha, lang=lang))
                continue
            cwe = auth_cwes[0]
            src = pick_source(guard, vc, sc)
            snk = pick_sink(vc, src) if src else None
            if not (src and snk and snk != src
                    and standalone(snk, vc) and standalone(snk, sc)):
                f["no_grounded_flow"] += 1
                held.append(dict(pair_id=pid, reason="no_grounded_flow", repo=repo,
                                 sha=sha, lang=lang))
                continue
            if per_cve[cve] >= MAX_PER_CVE:
                f["cve_quota_reached"] += 1
                held.append(dict(pair_id=pid, reason="cve_quota", repo=repo,
                                 sha=sha, lang=lang))
                continue
            per_cve[cve] += 1
            meta["cwe_source"] = "osv_or_cisa"
            out_att.append(guard_record(vc, "vuln", cwe, src, snk, guard, meta, pid))
            out_att.append(guard_record(sc, "safe", cwe, src, snk, guard, meta, pid))
            f["GUARD_PAIR"] += 1
            continue

        construct, _ = pick_removal(vc, sc)
        if construct and standalone(construct, vc):
            # For a removal the CWE follows from the construct itself.
            cwe = _CWE_FOR.get(re.split(r"[.(=]", construct)[0].lower())
            if not cwe:
                f["no_cwe_for_construct"] += 1
                held.append(dict(pair_id=pid, reason="no_construct_cwe", repo=repo,
                                 sha=sha, lang=lang))
                continue
            src = pick_source(construct, vc, sc)
            snk = pick_sink(sc, src) if src else None
            if src and snk and snk != src and src != construct:
                meta["cwe_source"] = "removed_construct_class"
                out_restr.append(restructure_record(vc, "vuln", cwe, src, construct,
                                                    construct, meta, pid))
                out_restr.append(restructure_record(sc, "safe", cwe, src, construct,
                                                    snk, meta, pid))
                f["RESTRUCTURE_PAIR"] += 1
                continue
        f["no_guard_no_removal"] += 1
        held.append(dict(pair_id=pid, reason="no_guard_no_removal", repo=repo,
                         sha=sha, lang=lang))

    for k, v in f.most_common():
        print(f"  {k:26s} {v:6d}")
    if args.write:
        for path, rows in ((OUT_ATT, out_att), (OUT_RESTR, out_restr)):
            if rows:
                with open(path, "w", encoding="utf-8") as fh:
                    for r in rows:
                        fh.write(json.dumps(r, ensure_ascii=False) + "\n")
                print(f"  -> {path} ({len(rows)//2} pairs)")
        if held:
            with open(HELD, "w", encoding="utf-8", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=list(held[0].keys()), delimiter="\t")
                w.writeheader()
                w.writerows(held)
            print(f"  -> {HELD} ({len(held)} pairs held, none dropped)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
