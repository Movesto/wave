"""Build React contrastive pairs from the OSV react-family fix commits.

53 usable commits, every one carrying an authoritative CWE from its advisory and 93%
a CVE -- so unlike the corpus's older react data these labels are not guessed.

React is worth this out of proportion to its size. It scored MCC 0.620 and REGRESSED
in v12.1b, and its only volume today is 600 synthetic records that were measured not
to transfer: shape_react_syn scored 100% on itself while real react scored 41.2% in
the same eval.

Language is decided by the FILE the guard is in, not by the package: a fix in a
react-family package that lands in a `.ts` file is TypeScript, and mislabelling it
react would corrupt the per-language slices the eval reports.

    python build_react_pairs.py --write
"""
import argparse
import collections
import csv
import hashlib
import json
import os
import re
import sys

import js_guard_gates as JG
import ts_guard_gates as TG
from build_r2vul_pairs import (MAX_CODE_CHARS, added_lines, pick_sink, pick_source,
                               standalone)
from build_r2vul_pairs import record as guard_record
from build_r2vul_restructure import pick_removal
from build_r2vul_restructure import record as restructure_record
from build_crossfile_restructure import _CWE_FOR
from build_ts_contrastive import (changed_line_texts, file_at, parse_hunks,
                                  regions_for_file, sides_from_hunk)
from filter_corpus import is_test_code, is_test_path, load_eval_codes
from harvest_osv_ts import find_local_clone
from react_vetted import VETTED, lookup

TARGETS = "data/osv/react_targets.tsv"
OUT = "data/cot/staging/shape1_contrastive_react_osv.jsonl"
OUT_RESTR = "data/cot/staging/shape_restructure_react.jsonl"
REPORT = "data/osv/react_build.tsv"
MIN_CHARS = 120

_LANG = {".tsx": "react", ".jsx": "react", ".ts": "typescript",
         ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript"}


def lang_of(path):
    return _LANG.get("." + path.rsplit(".", 1)[-1], "javascript")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    evalcodes = load_eval_codes()
    rows = list(csv.DictReader(open(TARGETS, encoding="utf-8"), delimiter="\t"))
    print(f"react fix commits: {len(rows)}", flush=True)

    out, restr, report, f = [], [], [], collections.Counter()
    seen = set()

    for r in rows:
        cwes = [c for c in (r.get("cwes") or "").split("|") if c.startswith("CWE-")]
        # A multi-CWE advisory is only usable if the vetting picked which one applies
        # to THIS file -- resolved by reading the fix, the same way the contrastive
        # ambiguities were.
        override = next((v[3] for k, v in VETTED.items()
                         if k[0] == r["id"] and len(v) > 3), None)
        if override:
            cwe = override
            f["cwe_disambiguated_by_vetting"] += 1
        elif len(cwes) == 1:
            cwe = cwes[0]
        else:
            f["cwe_missing_or_ambiguous"] += 1
            continue
        try:
            patch = open(r["patch"], encoding="utf-8", errors="replace").read()
        except OSError:
            f["patch_unreadable"] += 1
            continue

        by_file = collections.OrderedDict()
        for path, hunk in parse_hunks(patch):
            if (path.endswith(tuple(_LANG)) and not is_test_path(path)
                    and not re.search(r"(^|/)(dist|build|node_modules)/|\.min\.", path)):
                by_file.setdefault(path, []).append(hunk)
        if not by_file:
            f["no_react_source"] += 1
            continue

        clone = find_local_clone(r["owner"], r["repo"])
        sha = r["sha"]
        built_files = set()
        for path, hunks in by_file.items():
            vuln = fixed = None
            if clone:
                ft, vt = file_at(clone, sha, path), file_at(clone, f"{sha}^", path)
                if ft and vt:
                    nd = changed_line_texts(hunks)
                    fr, vr = regions_for_file(ft, nd), regions_for_file(vt, nd)
                    if fr and vr:
                        vuln, fixed = vr, fr
            if vuln is None:
                vp, fp = [], []
                for h in hunks:
                    v, fx = sides_from_hunk(h)
                    if v.strip():
                        vp.append(v)
                    if fx.strip():
                        fp.append(fx)
                vuln, fixed = "\n".join(vp).rstrip(), "\n".join(fp).rstrip()
            if not vuln or not fixed:
                continue
            if len(vuln) < MIN_CHARS or len(fixed) < MIN_CHARS:
                # A hunk-only excerpt can be a couple of lines (openURLMiddleware.ts
                # came out at 92 chars). The enclosing function from the clone is the
                # same code with the context a reader would actually have.
                if clone:
                    ft, vt = file_at(clone, sha, path), file_at(clone, f"{sha}^", path)
                    if ft and vt:
                        nd = changed_line_texts(hunks)
                        fr, vr = regions_for_file(ft, nd), regions_for_file(vt, nd)
                        if fr and vr and len(vr) >= MIN_CHARS and len(fr) >= MIN_CHARS:
                            vuln, fixed = vr, fr
                            f["widened_from_clone"] += 1
            if not (MIN_CHARS <= len(vuln) <= MAX_CODE_CHARS
                    and MIN_CHARS <= len(fixed) <= MAX_CODE_CHARS):
                f["size"] += 1
                continue
            if is_test_code(vuln) or is_test_code(fixed):
                f["test_code"] += 1
                continue
            if any(re.sub(r"\s+", " ", x).strip().lower() in evalcodes
                   for x in (vuln, fixed)):
                f["eval_leakage"] += 1
                continue
            key = hashlib.sha1(re.sub(r"\s+", "", vuln).encode()).hexdigest()
            if key in seen:
                f["dup"] += 1
                continue

            lang = lang_of(path)
            added = added_lines(vuln, fixed)
            # The HAND-VETTED line wins over the wordlist. React fixes name their own
            # helpers -- toSafeRedirect, hasInvalidProtocol, htmlEscapeJsonString --
            # and pick_ts_guard scores none of them, so it found 1 guard in 53 commits.
            vet = lookup(r["id"], os.path.basename(path))
            forced_restructure = False
            if vet:
                kind, line = vet[0], vet[1]
                if kind == "restructure":
                    guard, forced_restructure = None, True
                else:
                    guard = line
                    f["guard_from_vetting"] += 1
            else:
                # Unvetted fallback stays, but a `throw` is the CONSEQUENCE of a
                # failed check, not the check. It produced the one bad pair in the
                # first react build (`throw new Error('No access token available')`
                # quoted as the guard for CWE-200).
                cand = [l for l in added
                        if not re.match(r"\s*(throw|return\s+reject|reject\s*\()", l)]
                guard = TG.pick_ts_guard(cand)
            pid = hashlib.sha1(f"react|{r['owner']}/{r['repo']}|{sha}|{path}"
                               .encode()).hexdigest()[:12]
            meta = dict(language=lang, cve=r.get("cve", ""), ghsa=r.get("id", ""),
                        repo=f"{r['owner']}/{r['repo']}", sha=sha, src_file=path,
                        cwe_source="osv_advisory", package=r.get("pkg", ""),
                        fix_status="react_osv_harvest")

            if guard and guard not in vuln and guard in fixed:
                src = pick_source(guard, vuln, fixed)
                snk = pick_sink(vuln, src) if src else None
                if (src and snk and snk != src
                        and standalone(snk, vuln) and standalone(snk, fixed)):
                    seen.add(key)
                    out.append(guard_record(vuln, "vuln", cwe, src, snk, guard, meta, pid))
                    out.append(guard_record(fixed, "safe", cwe, src, snk, guard, meta, pid))
                    report.append(dict(pair_id=pid, kind="guard", lang=lang, cwe=cwe,
                                       cve=meta["cve"], repo=meta["repo"],
                                       source=src, sink=snk, guard=guard[:90]))
                    f["GUARD_PAIR"] += 1
                    built_files.add(path)
                    continue
                f["no_grounded_flow"] += 1
                continue

            construct, _ = pick_removal(vuln, fixed)
            if forced_restructure and vet:
                construct = vet[1]          # the vetted removed construct
            if construct and standalone(construct, vuln) and not standalone(construct, fixed):
                ccwe = _CWE_FOR.get(re.split(r"[.(=]", construct)[0].lower()) or cwe
                src = pick_source(construct, vuln, fixed)
                snk = pick_sink(fixed, src) if src else None
                if src and snk and snk != src and src != construct:
                    seen.add(key)
                    meta["cwe_source"] = "removed_construct_class"
                    restr.append(restructure_record(vuln, "vuln", ccwe, src, construct,
                                                    construct, meta, pid))
                    restr.append(restructure_record(fixed, "safe", ccwe, src, construct,
                                                    snk, meta, pid))
                    report.append(dict(pair_id=pid, kind="restructure", lang=lang,
                                       cwe=ccwe, cve=meta["cve"], repo=meta["repo"],
                                       source=src, sink=snk, guard=construct[:90]))
                    f["RESTRUCTURE_PAIR"] += 1
                    built_files.add(path)
                    continue
            f["no_guard_no_removal"] += 1

    print("\n=== funnel ===")
    for k, v in f.most_common():
        print(f"  {k:28s} {v:5d}")
    if args.write:
        for path, rows_ in ((OUT, out), (OUT_RESTR, restr)):
            if rows_:
                with open(path, "w", encoding="utf-8") as fh:
                    for x in rows_:
                        fh.write(json.dumps(x, ensure_ascii=False) + "\n")
                print(f"  -> {path} ({len(rows_)//2} pairs)")
        if report:
            with open(REPORT, "w", encoding="utf-8", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=list(report[0].keys()), delimiter="\t")
                w.writeheader()
                w.writerows(report)
            print(f"  -> {REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
