"""Report test code across every corpus file, shipped or held.

Test code carries a label and a CWE like anything else, so nothing downstream
notices it. `CVE-2023-27582` reached the contrastive set as a stub SASL server --
`t.Run`, `t.Error`, a fake callback -- and only surfaced because its advisory CWEs
made no sense against the diff.

Run after any rebuild. Shipped sets must report zero.

    python audit_test_code.py
"""
import collections
import json
import os
import sys

from filter_corpus import is_test_code
from scan_ts_standard import code_of

DIRS = ("data/cot/pilot/", "data/cot/staging/", "data/cot/filtered/",
        "data/cot/repaired/", "data/cot/eval/")

# Anything we would train or evaluate on must be clean, not merely measured.
SHIPPED = {
    "shape1_contrastive_ts_osv", "shape1_contrastive_js_osv",
    "shape1_ts_augment_edits", "shape_completeness_js",
    "shape1_contrastive_r2vul", "shape_restructure_r2vul",
    "shape1_contrastive_attested", "shape_restructure_contrastive",
    "shape1_r2vul_clean",
}


def main():
    rows, dirty_shipped = [], []
    for d in DIRS:
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if not f.endswith(".jsonl"):
                continue
            shape, n, hit = f[:-6], 0, 0
            examples = []
            for line in open(d + f, encoding="utf-8"):
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not r.get("messages") or len(r["messages"]) < 2:
                    continue
                n += 1
                if is_test_code(code_of(r)):
                    hit += 1
                    if len(examples) < 2:
                        examples.append((r["_meta"].get("pair_id", ""),
                                         r["_meta"].get("cve", "")))
            if not n:
                continue
            rows.append((d, shape, n, hit, examples))
            if hit and shape in SHIPPED:
                dirty_shipped.append((d + f, shape, hit, examples))

    print(f"{'file':46s} {'recs':>7s} {'test':>6s} {'%':>6s}")
    print("-" * 70)
    for d, shape, n, hit, _ in sorted(rows, key=lambda r: -r[3]):
        if hit:
            tag = "  <-- SHIPPED" if shape in SHIPPED else ""
            print(f"  {(d + shape)[:44]:44s} {n:7d} {hit:6d} {100*hit/n:5.1f}%{tag}")
    tot = sum(r[2] for r in rows)
    th = sum(r[3] for r in rows)
    print("-" * 70)
    print(f"  {'TOTAL':44s} {tot:7d} {th:6d} {100*th/tot:5.1f}%")

    if dirty_shipped:
        print("\nSHIPPED SETS CONTAINING TEST CODE -- must be rebuilt:")
        for path, shape, hit, ex in dirty_shipped:
            print(f"  {path}  ({hit} records)")
            for pid, cve in ex:
                print(f"      pair {pid} {cve}")
        return 1
    print("\nOK: no shipped set contains test code.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
