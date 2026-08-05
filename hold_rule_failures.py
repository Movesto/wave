"""Hold every wired record that still fails `filter_corpus.judge()`.

The standing rule on this project is that the data is fitted to the rules, not the rules
to the data. After the C-tier repair, 471 records across the wired shapes (1.4%) still
break one: R14 test code, R6a a ghost identifier the trace names but the excerpt does not
contain standalone, R7 reasoning too thin to be a chain of thought, R11 oversize.

They are held with the failing rule as the reason, not deleted, so any of them can be
recovered by fixing the cause rather than rebuilt from scratch.

Note this is deliberately conservative about what counts as a failure: R6b is excluded,
as everywhere else in the pipeline, because it flags a weaker second-order condition that
has never justified dropping a record on its own.

    python hold_rule_failures.py --write
"""
import argparse
import collections
import csv
import json
import os
import re
import sys

from filter_corpus import judge, load_eval_codes

MANIFEST = "data/osv/rule_failures_held.tsv"


def wired_shapes():
    src = re.sub(r"#[^\n]*", "", open("train_qwen_cot.py", encoding="utf-8").read())
    block = re.search(r'"shapes":\s*\[(.*?)\]', src, re.S).group(1)
    return re.findall(r'"([\w]+)"', block)


def path_of(shape):
    for d in ("pilot", "staging"):
        p = f"data/cot/{d}/{shape}.jsonl"
        if os.path.exists(p):
            return p
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    evalcodes = load_eval_codes()
    rows, f = [], collections.Counter()

    for shape in wired_shapes():
        path = path_of(shape)
        if not path:
            continue
        recs = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
        changed = 0
        for i, r in enumerate(recs):
            held = r.get("_meta", {}).get("held", "")
            # Re-running must reproduce the FULL manifest, not just what this run newly
            # held -- otherwise a second run truncates the file to its own few rows and
            # the held counts stop reconciling against the corpus.
            if held.startswith("rule_failure_") or held == "pair_partner_held":
                rows.append(dict(shape=shape, index=i, rule=held.replace(
                    "rule_failure_", ""), detail="(held by an earlier run)",
                    cwe=r["_meta"].get("ground_truth_cwe", "")))
                f[held.replace("rule_failure_", "")] += 1
                continue
            if held:
                continue
            bad = [b for b in judge(r, evalcodes, shape) if b[0] != "R6b"]
            if not bad:
                continue
            rule, detail = bad[0]
            r["_meta"]["held"] = f"rule_failure_{rule}"
            rows.append(dict(shape=shape, index=i, rule=rule, detail=str(detail)[:120],
                             cwe=r["_meta"].get("ground_truth_cwe", "")))
            f[rule] += 1
            changed += 1
        # A contrastive set only teaches anything as a PAIR: holding the vulnerable
        # side alone leaves its safe twin as an unanswerable single, and the model sees
        # safe code with no counterpart. So a held record takes its partner with it.
        orphans = {r["_meta"]["pair_id"] for r in recs
                   if r.get("_meta", {}).get("held") and r["_meta"].get("pair_id")}
        if orphans:
            for i, r in enumerate(recs):
                m = r.get("_meta", {})
                if m.get("pair_id") in orphans and not m.get("held"):
                    m["held"] = "pair_partner_held"
                    rows.append(dict(shape=shape, index=i, rule="pair",
                                     detail="partner side held, pair incomplete",
                                     cwe=m.get("ground_truth_cwe", "")))
                    f["pair_partner"] += 1
                    changed += 1

        if changed:
            print(f"  {shape:30s} {changed:5d} held")
            if args.write:
                with open(path, "w", encoding="utf-8") as fh:
                    for r in recs:
                        fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    print("\n  by rule:", dict(f.most_common()))
    print(f"  total held: {sum(f.values())}")
    if args.write and rows:
        with open(MANIFEST, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(rows)
        print(f"-> {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
