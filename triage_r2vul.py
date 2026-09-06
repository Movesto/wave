"""Label every r2vul record against the standard, and say what would repair it.

Same treatment the JS near-misses got: a record that breaks a rule is labelled
with WHICH rule and WHAT would fix it, never dropped on the strength of failing
one check. The point is a work queue, not a smaller corpus.

r2vul is the best large source we have -- 92% carry a CWE, 99% were re-identified
against the upstream dataset, and the upstream CWE agrees with ours 77.7% of the
time with 0.1% disagreement. Its defect is concentrated in the TRACE, and a trace
is the one part we can rebuild from the code itself.

    python triage_r2vul.py
"""
import collections
import csv
import json
import os
import re
import sys

from build_ts_contrastive import _STR_LIT
from filter_corpus import named_identifiers
from scan_ts_standard import BOILERPLATE, code_of, trace_of

OUT = "data/osv/r2vul_triage.tsv"
MIN_CHARS, MAX_CHARS = 120, 6000

_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
_CALLISH = re.compile(r"([A-Za-z_$][\w$.]*)\s*\(")
_KEYWORDS = {"if", "for", "while", "switch", "return", "new", "catch", "throw",
             "else", "try", "do", "case", "sizeof", "typeof", "await", "async",
             "function", "def", "class", "public", "private", "static", "void",
             "int", "char", "const", "struct", "printf", "print"}


def grounded(ident, code):
    return re.search(r"(?<![\w])" + re.escape(ident) + r"(?![\w])", code) is not None


def can_reground(code):
    """Could a trace be rebuilt with a source and sink that REALLY occur here?

    The regeneration we would do needs two distinct grounded names outside string
    literals -- a value and a call it reaches. If the excerpt cannot supply them,
    regenerating the trace would just invent a different fiction, so the record is
    not repairable this way and has to be said so.
    """
    bare = _STR_LIT.sub("''", code)
    calls = [m.group(1) for m in _CALLISH.finditer(bare)
             if m.group(1).split(".")[-1] not in _KEYWORDS
             and len(m.group(1).split(".")[-1]) >= 3]
    names = [n for n in _IDENT.findall(bare)
             if n not in _KEYWORDS and len(n) >= 3]
    return bool(calls) and len(set(names) - set(calls)) > 0


def load_provenance():
    p = {}
    if not os.path.exists("data/osv/corpus_provenance.tsv"):
        return p
    for r in csv.DictReader(open("data/osv/corpus_provenance.tsv", encoding="utf-8"),
                            delimiter="\t"):
        p[(r["shape"], int(r["line"]))] = r
    return p


def main():
    prov = load_provenance()
    rows, tally, verdicts = [], collections.Counter(), collections.Counter()

    for d in ("data/cot/pilot/", "data/cot/staging/"):
        for f in sorted(os.listdir(d)):
            if not f.endswith(".jsonl"):
                continue
            shape = f[:-6]
            for i, line in enumerate(open(d + f, encoding="utf-8")):
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                m = r.get("_meta") or {}
                if (m.get("source") or "").split(":")[0] != "r2vul":
                    continue
                if not r.get("messages") or len(r["messages"]) < 2:
                    continue

                code, t = code_of(r), trace_of(r)
                think = re.search(r"<think>(.*?)</think>", t, re.S)
                body = think.group(1) if think else t

                claim = re.search(r"^trace:.*$", t, re.M)
                claim_txt = claim.group(0) if claim else ""
                fails, ghost = [], ""
                for ident in named_identifiers(body):
                    if not grounded(ident, code):
                        fails.append("R6a" if ident in claim_txt else "R6b")
                        ghost = ident
                        break
                if any(b.lower() in t.lower() for b in BOILERPLATE):
                    fails.append("R7:boilerplate")
                elif not think or len(body.split()) < 45:
                    fails.append("R7:thin")
                if not (MIN_CHARS <= len(code) <= MAX_CHARS):
                    fails.append(f"R11:{len(code)}")
                if not m.get("ground_truth_cwe"):
                    fails.append("R5:no_cwe")

                pr = prov.get((shape, i))
                has_prov = bool(pr)
                tally.update([x.split(":")[0] if x.startswith("R11") else x
                              for x in fails] or ["CLEAN"])

                if not fails:
                    verdict = "PASSES"
                elif fails == ["R11:%d" % len(code)] or all(x.startswith("R11") for x in fails):
                    verdict = "RECUT_EXCERPT"
                elif fails == ["R6b"]:
                    verdict = "PROSE_BLEMISH_ONLY"
                elif any(x.startswith(("R6a", "R7")) for x in fails):
                    # the trace is the broken part; can it be rebuilt grounded?
                    if not can_reground(code):
                        verdict = "TRACE_UNREBUILDABLE"
                    elif not m.get("ground_truth_cwe") and not (pr and pr.get("cwe_upstream")):
                        verdict = "NEEDS_CWE_FIRST"
                    else:
                        verdict = "REGENERATE_TRACE"
                else:
                    verdict = "NEEDS_CWE_FIRST"
                verdicts[verdict] += 1

                rows.append(dict(
                    shape=shape, line=i, verdict=verdict,
                    rules="|".join(fails), ghost=ghost,
                    label=m.get("label", ""), cwe=m.get("ground_truth_cwe", ""),
                    cwe_upstream=(pr or {}).get("cwe_upstream", ""),
                    cve=(pr or {}).get("cve", ""), repo=(pr or {}).get("repo", ""),
                    sha=(pr or {}).get("sha", ""), file=(pr or {}).get("file", ""),
                    chars=len(code), provenance="yes" if has_prov else "no"))

    with open(OUT, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), delimiter="\t")
        w.writeheader()
        w.writerows(rows)

    n = len(rows)
    print(f"r2vul records: {n}\n")
    print("rule failures (a record can break more than one):")
    for k, v in tally.most_common():
        print(f"  {k:22s} {v:6d}  {100*v/n:5.1f}%")
    print("\nverdict -- what would repair each record:")
    for k, v in verdicts.most_common():
        print(f"  {k:22s} {v:6d}  {100*v/n:5.1f}%")
    print(f"\n-> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
