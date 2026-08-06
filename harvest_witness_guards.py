"""Phase 1 of witness-based data: harvest every REAL insufficient guard the battery can
PROVE, across the whole corpus (both labels), as raw material for verified completeness
pairs.

Each hit is a real guard (varied, not templated) that the witness defeats with a concrete
bypass -- the checkable seed of a `vuln` side. Phase 2 will harden each and verify the fix
blocks the bypass; Phase 3 attaches grounded traces.

    python harvest_witness_guards.py                 # scan data/cot/filtered/*.jsonl
    python harvest_witness_guards.py --repos data/juice-shop data/dvna

Writes witness_guards.jsonl (one hit per line) + a distribution summary on stdout.
"""
import argparse
import glob
import json
import sys
from collections import Counter

from guard_witness import witness_scan

_CWE_KIND = {
    "CWE-22": "path", "CWE-23": "path", "CWE-98": "path", "CWE-73": "path",
    "CWE-601": "redirect", "CWE-807": "redirect",
    "CWE-78": "command", "CWE-77": "command", "CWE-88": "command",
    "CWE-918": "ssrf",
    "CWE-1321": "proto", "CWE-1327": "proto", "CWE-915": "proto",
    "CWE-79": "xss", "CWE-80": "xss", "CWE-83": "xss",
}


def kinds_for(meta):
    cwes = list(meta.get("cwes") or [])
    gt = meta.get("ground_truth_cwe")
    if gt:
        cwes = [gt] + [c for c in cwes if c != gt]
    seen, out = set(), []
    for c in cwes:
        k = _CWE_KIND.get((c or "").upper())
        if k and k not in seen:
            seen.add(k)
            out.append((c, k))
    return out


def code_of(rec):
    for m in rec.get("messages", []):
        if m.get("role") == "user":
            return m["content"].replace("<SCAN>", "").replace("</SCAN>", "").strip()
    return ""


def trace_of(rec):
    for m in rec.get("messages", []):
        if m.get("role") == "assistant":
            return m["content"]
    return ""


def harvest_corpus(files):
    hits, seen_guard = [], set()
    n_records = n_eligible = 0
    for f in files:
        with open(f, encoding="utf-8") as fh:
            for ln, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                meta = rec.get("_meta", {})
                n_records += 1
                kinds = kinds_for(meta)
                if not kinds:
                    continue
                n_eligible += 1
                code = code_of(rec)
                for cwe, kind in kinds:
                    w = witness_scan(code, kind)
                    if not w:
                        continue
                    # dedup identical guards so variety, not repetition, is what we count
                    key = (kind, w["guard"], w["bypass"])
                    hits.append({
                        "source_file": f, "line": ln, "pair_id": meta.get("pair_id", ""),
                        "label": meta.get("label", ""), "origin": meta.get("source", ""),
                        "language": meta.get("language", ""), "cwe": cwe,
                        "kind": kind, "guard": w["guard"], "bypass": w["bypass"],
                        "why": w["why"], "duplicate": key in seen_guard, "code": code,
                    })
                    seen_guard.add(key)
                    break
    return hits, n_records, n_eligible


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--glob", default="data/cot/filtered/*.jsonl")
    ap.add_argument("--out", default="witness_guards.jsonl")
    args = ap.parse_args()

    files = sorted(glob.glob(args.glob))
    hits, n_records, n_eligible = harvest_corpus(files)

    with open(args.out, "w", encoding="utf-8") as out:
        for h in hits:
            out.write(json.dumps(h, ensure_ascii=False) + "\n")

    uniq = [h for h in hits if not h["duplicate"]]
    print(f"scanned {n_records} records ({n_eligible} in a witness CWE) across "
          f"{len(files)} file(s)")
    print(f"-> {len(hits)} insufficient-guard hits, {len(uniq)} with a DISTINCT "
          f"(kind, guard, bypass)\n")
    if not hits:
        print("no insufficient guards found.")
        return 0

    print("distinct hits by class:")
    for k, n in Counter(h["kind"] for h in uniq).most_common():
        print(f"  {k:9s} {n}")
    print("\ndistinct hits by label:")
    for k, n in Counter(h["label"] for h in uniq).most_common():
        print(f"  {k or '?':13s} {n}")
    print("\ndistinct hits by language:")
    for k, n in Counter(h["language"] for h in uniq).most_common():
        print(f"  {k or '?':13s} {n}")
    print("\nsample distinct guards:")
    for h in uniq[:14]:
        print(f"  [{h['kind']:8s}] {h['label']:5s} {h['language']:10s} "
              f"bypass={h['bypass']!r:26s} :: {h['guard'][:52]}")
    print(f"\nfull list -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
