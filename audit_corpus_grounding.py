"""Run the standard's grounding test over the EXISTING corpus, not new data.

We have been using docs/TS_DATA_STANDARD.md to BUILD records. The same rules read
as a FILTER: R6 says every identifier a trace names must really occur in the code
it is reasoning about. That test needs no provenance, no diff and no harvest, so
unlike the rest of the standard it can be applied to all ~83K records we already
have -- including the ~40K with no path back to a source commit.

A trace that names something absent from the code is not reasoning about that
code. It is the defect we found in the TS traces (42% before fixes), and there is
no reason to expect it stopped at TS.

    python audit_corpus_grounding.py
"""
import collections
import csv
import json
import os
import re
import sys

from build_ts_contrastive import _STR_LIT

OUT = "data/osv/corpus_grounding.tsv"

# Identifiers a trace names, as `backticked` spans -- the convention every shape
# in this corpus uses to point at code.
_TICKED = re.compile(r"`([^`\n]{2,60})`")
# Prose that happens to sit in backticks; naming these proves nothing.
_PROSE = {"think", "vuln", "safe", "none", "true", "false", "null", "undefined",
          "int", "str", "string", "char", "bool", "void", "return", "if", "else",
          "for", "while", "yes", "no", "n/a", "cwe", "high", "low", "medium"}


def named_identifiers(text):
    """Code-like things the trace claims are present."""
    out = []
    for raw in _TICKED.findall(text):
        s = raw.strip()
        if not s or s.lower() in _PROSE:
            continue
        # a call/attr chain, an identifier, or a short expression: take the
        # longest bare identifier in it as the thing that must exist
        idents = re.findall(r"[A-Za-z_$][\w$]*", s)
        if not idents:
            continue
        cand = max(idents, key=len)
        if len(cand) < 3 or cand.lower() in _PROSE:
            continue
        out.append(cand)
    return out


def grounded(ident, code_bare):
    return re.search(r"(?<![\w])" + re.escape(ident) + r"(?![\w])", code_bare) is not None


def audit_file(path):
    tot = named = ghosts = recs_with_ghost = recs = 0
    worst = collections.Counter()
    for line in open(path, encoding="utf-8"):
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        msgs = r.get("messages")
        if not msgs or len(msgs) < 2:
            continue
        code = msgs[0].get("content", "")
        think = msgs[1].get("content", "")
        if "<think>" not in think:
            continue
        recs += 1
        bare = _STR_LIT.sub("''", code)
        idents = named_identifiers(think.split("</think>")[0])
        bad = [i for i in idents if not grounded(i, bare)]
        tot += 1
        named += len(idents)
        ghosts += len(bad)
        if bad:
            recs_with_ghost += 1
            worst.update(bad[:3])
    return recs, named, ghosts, recs_with_ghost, worst


def main():
    files = []
    for d in ("data/cot/pilot/", "data/cot/staging/"):
        for f in sorted(os.listdir(d)):
            if f.endswith(".jsonl"):
                files.append((d + f, f[:-6], d.split("/")[-2]))

    rows = []
    for path, shape, where in files:
        recs, named, ghosts, bad_recs, worst = audit_file(path)
        if not recs:
            continue
        rows.append(dict(shape=shape, where=where, records=recs,
                         idents_named=named, ghosts=ghosts,
                         records_with_ghost=bad_recs,
                         pct_records_with_ghost=round(100 * bad_recs / recs, 1),
                         pct_idents_ghost=round(100 * ghosts / named, 1) if named else 0.0,
                         top_ghosts="; ".join(f"{k}({v})" for k, v in worst.most_common(4))))

    rows.sort(key=lambda r: -r["records"])
    with open(OUT, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), delimiter="\t")
        w.writeheader()
        w.writerows(rows)

    print(f"{'shape':32s} {'recs':>6s} {'%recs w/ ghost':>15s} {'%idents ghost':>14s}")
    print("-" * 72)
    for r in rows:
        print(f"  {r['shape']:30s} {r['records']:6d} {r['pct_records_with_ghost']:14.1f}% "
              f"{r['pct_idents_ghost']:13.1f}%")
    tr = sum(r["records"] for r in rows)
    tb = sum(r["records_with_ghost"] for r in rows)
    ti = sum(r["idents_named"] for r in rows)
    tg = sum(r["ghosts"] for r in rows)
    print("-" * 72)
    print(f"  {'CORPUS':30s} {tr:6d} {100*tb/tr:14.1f}% {100*tg/ti:13.1f}%")
    print(f"\n-> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
