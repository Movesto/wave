"""Build the held-out eval from PrimeVul's TEST split.

The 369-record bench is retired: it is drawn from provenance-free data (42 of ~1,600
records carry any), so a model that genuinely improved could show nothing on it and we
could not tell that apart from the data not working.

PrimeVul's test split is the replacement backbone -- 435 balanced pairs, every one
carrying `cve` and `commit_id`, 62 CWEs, manually curated with strict dedup. It was
already excluded from training by build_contrastive.py for exactly this reason.

Built with the SAME builder as training data, so eval and training are held to one
standard. An eval built to a laxer bar measures the bar, not the model.

    python build_eval_primevul.py --write
"""
import argparse
import collections
import hashlib
import json
import os
import re
import sys

from build_r2vul_pairs import (added_lines, pick_guard, pick_sink,
                               pick_source, standalone)
from build_r2vul_pairs import record as guard_record
from build_r2vul_restructure import pick_removal
from build_r2vul_restructure import record as restructure_record
from filter_corpus import is_test_code

SRC = "data/downloads/PrimeVul/primevul_test_paired.jsonl"

# The eval may hold LARGER excerpts than training. MAX_CODE_CHARS=4500 exists for
# label masking during training, which does not apply here -- and the standard's own
# principle is that the exam should look like code in the wild, not cleaner than it.
# PrimeVul's pairs have a median max-side of 2,436 chars but a p90 of 11,823, so a
# 4,500 cap discards 129 of 435 pairs for being realistically sized.
EVAL_MAX_CHARS = 12000
OUT = "data/cot/eval_v2/shape1_eval_primevul.jsonl"
OUT_RESTR = "data/cot/eval_v2/shape_restructure_eval_primevul.jsonl"
REPORT = "data/osv/eval_primevul_funnel.tsv"
MIN_CHARS = 120


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    rows = [json.loads(l) for l in open(SRC, encoding="utf-8") if l.strip()]
    print(f"primevul test split: {len(rows)} records", flush=True)

    guard_out, restr_out, report = [], [], []
    f = collections.Counter()

    for i in range(0, len(rows) - 1, 2):
        a, b = rows[i], rows[i + 1]
        if {a.get("target"), b.get("target")} != {0, 1}:
            f["not_a_pair"] += 1
            continue
        vrec = a if a.get("target") == 1 else b
        srec = b if a.get("target") == 1 else a
        vuln = (vrec.get("func") or "").strip()
        safe = (srec.get("func") or "").strip()
        f["candidate"] += 1

        if not (MIN_CHARS <= len(vuln) <= EVAL_MAX_CHARS
                and MIN_CHARS <= len(safe) <= EVAL_MAX_CHARS):
            f["size"] += 1
            continue
        if is_test_code(vuln) or is_test_code(safe):
            f["test_code"] += 1
            continue
        if not (1 <= len(added_lines(vuln, safe)) <= 24):
            f["diff_too_large_or_empty"] += 1
            continue

        cwes = vrec.get("cwe") or []
        cwe = next((c for c in cwes if str(c).startswith("CWE-")), "")
        if not cwe:
            f["no_cwe"] += 1
            continue
        if len([c for c in cwes if str(c).startswith("CWE-")]) > 1:
            # An eval label must be unambiguous or the score is unreadable.
            f["cwe_ambiguous"] += 1
            continue

        pid = hashlib.sha1(f"pvtest|{vrec.get('idx')}|{vrec.get('commit_id')}"
                           .encode()).hexdigest()[:12]
        meta = dict(language="c", cve=vrec.get("cve") or "",
                    repo=vrec.get("project") or "",
                    sha=vrec.get("commit_id") or "",
                    src_file=vrec.get("file_name") or "",
                    cwe_source="primevul_curated", split="eval",
                    fix_status="primevul_test_split")

        guard = pick_guard(vuln, safe)
        if guard:
            src = pick_source(guard, vuln, safe)
            snk = pick_sink(vuln, src) if src else None
            if src and snk and snk != src and standalone(snk, vuln) and standalone(snk, safe):
                guard_out.append(guard_record(vuln, "vuln", cwe, src, snk, guard, meta, pid))
                guard_out.append(guard_record(safe, "safe", cwe, src, snk, guard, meta, pid))
                f["GUARD_PAIR"] += 1
                report.append(dict(pair_id=pid, kind="guard", cve=meta["cve"],
                                   repo=meta["repo"], cwe=cwe, source=src,
                                   sink=snk, guard=guard[:100]))
                continue
            f["guard_found_but_no_grounded_flow"] += 1
            continue

        construct, _ = pick_removal(vuln, safe)
        if construct and standalone(construct, vuln):
            src = pick_source(construct, vuln, safe)
            snk = pick_sink(safe, src) if src else None
            if src and snk and snk != src and src != construct:
                restr_out.append(restructure_record(vuln, "vuln", cwe, src, construct,
                                                    construct, meta, pid))
                restr_out.append(restructure_record(safe, "safe", cwe, src, construct,
                                                    snk, meta, pid))
                f["RESTRUCTURE_PAIR"] += 1
                report.append(dict(pair_id=pid, kind="restructure", cve=meta["cve"],
                                   repo=meta["repo"], cwe=cwe, source=src,
                                   sink=snk, guard=construct[:100]))
                continue
        f["no_guard_no_removal"] += 1

    print("\n=== funnel ===")
    for k, v in f.most_common():
        print(f"  {k:34s} {v:5d}")

    if args.write:
        import csv
        os.makedirs("data/cot/eval_v2", exist_ok=True)
        for path, out in ((OUT, guard_out), (OUT_RESTR, restr_out)):
            if out:
                with open(path, "w", encoding="utf-8") as fh:
                    for r in out:
                        fh.write(json.dumps(r, ensure_ascii=False) + "\n")
                print(f"  -> {path} ({len(out)//2} pairs)")
        if report:
            with open(REPORT, "w", encoding="utf-8", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=list(report[0].keys()), delimiter="\t")
                w.writeheader()
                w.writerows(report)
            print(f"  -> {REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
