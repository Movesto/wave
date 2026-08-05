"""Can the 7,347 contrastive pairs be rebuilt to the standard?

These are the corpus's best-structured records -- 100% paired, exactly balanced,
100% CWE -- and its worst-reasoned: 50.8% carry a blocklisted template sentence
and the safe trace asserts "is neutralized" without naming what neutralised it.

What makes them repairable, unlike r2vul's single-sided records, is that BOTH
revisions are present. The guard can be re-derived by diffing them rather than
trusted from a trace that may have picked a type name or a switch label.

Two lessons carried over rather than re-learned:
  * these traces are OURS (cot/deep_trace.py), not a paper's, so regenerating
    them is legitimate -- the r2vul prose must never be edited, this may be
  * validate with the SCANNER's predicate, never a local looser one

    python triage_contrastive.py
"""
import collections
import csv
import json
import re
import sys

from build_r2vul_pairs import pick_guard, pick_sink, pick_source, standalone
from scan_ts_standard import code_of, trace_of

SRC = "data/cot/staging/shape1_contrastive.jsonl"
OUT = "data/osv/contrastive_triage.tsv"
MIN_CHARS, MAX_CHARS = 120, 4500


def main():
    pairs = collections.defaultdict(dict)
    for line in open(SRC, encoding="utf-8"):
        r = json.loads(line)
        pairs[r["_meta"]["pair_id"]][r["_meta"]["label"]] = r

    rows, verdicts, langs = [], collections.Counter(), collections.Counter()
    for pid, sides in pairs.items():
        v, s = sides.get("vuln"), sides.get("safe")
        if not v or not s:
            verdicts["INCOMPLETE_PAIR"] += 1
            continue
        vc, sc = code_of(v), code_of(s)
        m = v["_meta"]
        lang, cwe = m.get("language", ""), m.get("ground_truth_cwe", "")

        # what the EXISTING trace claims
        old = re.search(r"trace: (\S+) -> (\S+)", trace_of(v))
        old_src, old_snk = (old.group(1), old.group(2)) if old else ("", "")

        if not (MIN_CHARS <= len(vc) <= MAX_CHARS and MIN_CHARS <= len(sc) <= MAX_CHARS):
            verdict, guard, src, snk = "SIZE", "", "", ""
        else:
            guard = pick_guard(vc, sc)
            if not guard:
                verdict, src, snk = "NO_GUARD_IN_DIFF", "", ""
            else:
                src = pick_source(guard, vc, sc)
                snk = pick_sink(vc, src) if src else None
                if not src:
                    verdict, snk = "NO_GROUNDED_SOURCE", ""
                elif not snk or snk == src:
                    verdict = "NO_GROUNDED_SINK"
                elif not (standalone(snk, vc) and standalone(snk, sc)):
                    verdict = "SINK_NOT_IN_BOTH"
                elif not cwe:
                    verdict = "NO_CWE"
                else:
                    verdict = "REBUILDABLE"
        verdicts[verdict] += 1
        if verdict == "REBUILDABLE":
            langs[lang] += 1
        rows.append(dict(pair_id=pid, verdict=verdict, language=lang, cwe=cwe,
                         old_source=old_src, old_sink=old_snk,
                         new_source=src or "", new_sink=snk or "",
                         guard=(guard or "")[:120],
                         source_changed=str(bool(src and src != old_src)),
                         vuln_chars=len(vc), safe_chars=len(sc)))

    with open(OUT, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), delimiter="\t")
        w.writeheader()
        w.writerows(rows)

    n = sum(verdicts.values())
    print(f"contrastive pairs: {n}\n")
    for k, val in verdicts.most_common():
        print(f"  {k:22s} {val:6d}  {100*val/n:5.1f}%")
    print(f"\nrebuildable by language: {dict(langs.most_common())}")
    ch = sum(1 for r in rows if r["source_changed"] == "True")
    print(f"pairs where the re-derived source DIFFERS from the old trace: {ch}")
    print(f"\n-> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
