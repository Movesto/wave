"""Print each r2vul pair's trace and guard for hand-reading.

Automated gates catch only what was already thought of. Every builder in this
project passed its own checks and was still wrong on a fresh read, so this exists
to make that read cheap.
"""
import json
import re
import sys

PATH = "data/cot/staging/shape1_contrastive_r2vul.jsonl"

rows = [json.loads(l) for l in open(PATH, encoding="utf-8")]
n = int(sys.argv[1]) if len(sys.argv) > 1 else 12
shown = 0
for r in rows:
    m = r["_meta"]
    if m["label"] != "safe":
        continue
    t = r["messages"][1]["content"]
    tr = re.search(r"trace: (\S+) -> (\S+)", t)
    g = re.search(r"constrained by .(.+?).\nfix", t, re.S)
    print(f"{m['language']:10s} {m['ground_truth_cwe']:9s} {m['cve']:16s} "
          f"{tr.group(1)} -> {tr.group(2)}")
    print(f"      guard: {(g.group(1) if g else '?')[:100]}")
    shown += 1
    if shown >= n:
        break
