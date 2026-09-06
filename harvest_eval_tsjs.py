"""TS/JS eval pairs from HAND-VETTED guards in repos absent from training.

The PrimeVul backbone is C/C++, but TS/JS is the weakness worth measuring -- TS
scored MCC 0.000 on the retired bench. Holding out existing pairs would shrink an
already small training set, so these come from a separate pool.

WHY THE VETTED SET AND NOT A FRESH HARVEST. A raw pass over 864 unseen commits was
tried first and produced 23 pairs of which a hand-read judged ~4 sound: thrown
errors, error callbacks, assignments and switch cases quoted as controls. That is
the documented behaviour of this pipeline -- the regex pre-filter is 100% recall and
~70% precision BY DESIGN, and the training set only reached quality because all 410
candidates were hand-judged down to 244. Skipping that step does not work, and an
eval built from noise measures noise.

`ts_guard_enriched.tsv` / `js_guard_enriched.tsv` already carry that judgment. 38 of
those guards come from repos no training shape touches, which is the pool used here.

REPO-LEVEL separation: two functions from one project share idioms and helper names,
so code-level dedup is not enough.

    python harvest_eval_tsjs.py --write
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
from build_r2vul_pairs import pick_sink, pick_source, standalone
from build_r2vul_pairs import record as guard_record
from build_ts_contrastive import (changed_line_texts, file_at, parse_hunks,
                                  regions_for_file, sides_from_hunk)
from filter_corpus import is_test_code
from harvest_osv_ts import find_local_clone

SOURCES = (("data/osv/ts_guard_enriched.tsv", "typescript", TG.is_ts_source),
           ("data/osv/js_guard_enriched.tsv", "javascript", JG.is_js_source))
OUT = "data/cot/eval_v2/shape1_eval_tsjs.jsonl"
REPORT = "data/osv/eval_tsjs_funnel.tsv"
MIN_CHARS, MAX_CHARS = 120, 12000        # eval ceiling, see build_eval_primevul


def training_repos():
    repos = set()
    for d in ("data/cot/staging/", "data/cot/pilot/"):
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if not f.endswith(".jsonl"):
                continue
            for line in open(d + f, encoding="utf-8"):
                try:
                    m = json.loads(line).get("_meta") or {}
                except json.JSONDecodeError:
                    continue
                if m.get("repo"):
                    repos.add(m["repo"].lower())
    return repos


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    used = training_repos()
    print(f"repos used in training: {len(used)}", flush=True)

    out, report, f = [], [], collections.Counter()
    seen = set()

    for path_tsv, lang_default, is_src in SOURCES:
        if not os.path.exists(path_tsv):
            continue
        for r in csv.DictReader(open(path_tsv, encoding="utf-8"), delimiter="\t"):
            repo = (r.get("repo") or "").strip()
            if not repo or repo.lower() in used:
                f["repo_in_training"] += 1
                continue
            cwes = [c for c in (r.get("cwe_final") or "").split("|")
                    if c.startswith("CWE-")]
            if len(cwes) != 1:
                f["cwe_missing_or_ambiguous"] += 1
                continue
            cwe = cwes[0]
            guard = (r.get("guard") or "").strip()
            patch_path = r.get("patch") or ""
            if not guard or not os.path.exists(patch_path):
                f["patch_or_guard_missing"] += 1
                continue
            try:
                patch = open(patch_path, encoding="utf-8", errors="replace").read()
            except OSError:
                f["patch_unreadable"] += 1
                continue

            by_file = collections.OrderedDict()
            for p, hunk in parse_hunks(patch):
                if is_src(p):
                    by_file.setdefault(p, []).append(hunk)
            chosen = next((p for p, hs in by_file.items()
                           if any(guard in l[1:] for h in hs for l in h
                                  if l.startswith("+"))), None)
            if not chosen:
                f["guard_hunk_not_found"] += 1
                continue

            owner, name = repo.split("/", 1) if "/" in repo else (None, None)
            clone = find_local_clone(owner, name) if owner else None
            sha = (r.get("sha") or "").strip()
            vuln = fixed = None
            if clone and sha:
                ft, vt = file_at(clone, sha, chosen), file_at(clone, f"{sha}^", chosen)
                if ft and vt:
                    nd = changed_line_texts(by_file[chosen])
                    fr, vr = regions_for_file(ft, nd), regions_for_file(vt, nd)
                    if fr and vr:
                        vuln, fixed = vr, fr
            if vuln is None:
                vp, fp = [], []
                for h in by_file[chosen]:
                    v, fx = sides_from_hunk(h)
                    if v.strip():
                        vp.append(v)
                    if fx.strip():
                        fp.append(fx)
                vuln, fixed = "\n".join(vp).rstrip(), "\n".join(fp).rstrip()

            if not vuln or not fixed:
                f["no_sides"] += 1
                continue
            if guard not in fixed or guard in vuln:
                f["guard_not_added"] += 1
                continue
            if not (MIN_CHARS <= len(vuln) <= MAX_CHARS
                    and MIN_CHARS <= len(fixed) <= MAX_CHARS):
                f["size"] += 1
                continue
            if is_test_code(vuln) or is_test_code(fixed):
                f["test_code"] += 1
                continue
            src = pick_source(guard, vuln, fixed)
            snk = pick_sink(vuln, src) if src else None
            if not src or not snk or snk == src:
                f["no_grounded_flow"] += 1
                continue
            if not (standalone(snk, vuln) and standalone(snk, fixed)):
                f["sink_not_in_both"] += 1
                continue
            key = hashlib.sha1(re.sub(r"\s+", "", vuln).encode()).hexdigest()
            if key in seen:
                f["dup"] += 1
                continue
            seen.add(key)

            lang = "typescript" if chosen.endswith((".ts", ".tsx")) else (
                "javascript" if chosen.endswith((".js", ".jsx", ".mjs", ".cjs"))
                else lang_default)
            pid = hashlib.sha1(f"evaltsjs|{repo}|{sha}|{chosen}".encode()).hexdigest()[:12]
            meta = dict(language=lang, cve=r.get("cve", ""), ghsa=r.get("ghsa", ""),
                        repo=repo, sha=sha, src_file=chosen,
                        cwe_source=r.get("cwe_source", "advisory"), split="eval",
                        fix_status="eval_vetted_guard")
            out.append(guard_record(vuln, "vuln", cwe, src, snk, guard, meta, pid))
            out.append(guard_record(fixed, "safe", cwe, src, snk, guard, meta, pid))
            report.append(dict(pair_id=pid, repo=repo, language=lang, cwe=cwe,
                               source=src, sink=snk, guard=guard[:100]))
            f["PAIR_BUILT"] += 1

    print("\n=== funnel ===")
    for k, v in f.most_common():
        print(f"  {k:30s} {v:5d}")

    if args.write and out:
        os.makedirs("data/cot/eval_v2", exist_ok=True)
        with open(OUT, "w", encoding="utf-8") as fh:
            for x in out:
                fh.write(json.dumps(x, ensure_ascii=False) + "\n")
        with open(REPORT, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(report[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(report)
        print(f"\n-> {OUT} ({len(out)//2} pairs)\n-> {REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
