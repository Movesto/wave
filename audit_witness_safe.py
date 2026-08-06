"""Verified-completeness audit: run the guard-witness battery over every SAFE-labelled
record in the live corpus and surface the ones whose guard is PROVABLY bypassable.

A record labelled `safe` for a CWE the battery covers claims "this code is not exploitable".
If witness_scan finds a concrete bypass, the label is in question -- either the record is
mislabelled, or (less often) the witness over-reached. Either way it is a REVIEW candidate,
never an auto-relabel. This script writes a review list; it changes nothing in the corpus.

    python audit_witness_safe.py                # audit data/cot/filtered/*.jsonl
    python audit_witness_safe.py data/cot/staging/*.jsonl

Output: witness_audit.csv (one row per hit) + a per-class / per-file summary on stdout.
"""
import csv
import glob
import json
import sys

from guard_witness import witness_scan

# CWE -> witness kind, mirroring scanner/pipeline._witness_kind but self-contained so the
# audit never drags in the model/torch stack.
_CWE_KIND = {
    "CWE-22": "path", "CWE-23": "path", "CWE-98": "path", "CWE-73": "path",
    "CWE-601": "redirect", "CWE-807": "redirect",
    "CWE-78": "command", "CWE-77": "command", "CWE-88": "command",
    "CWE-918": "ssrf",
    "CWE-1321": "proto", "CWE-1327": "proto", "CWE-915": "proto",
}


def kinds_for(meta):
    cwes = meta.get("cwes") or []
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
            return m["content"].replace("<SCAN>", "").replace("</SCAN>", "")
    return ""


def main():
    files = sys.argv[1:] or sorted(glob.glob("data/cot/filtered/*.jsonl"))
    hits, n_safe, n_eligible = [], 0, 0
    for f in files:
        with open(f, encoding="utf-8") as fh:
            for ln, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                meta = rec.get("_meta", {})
                if meta.get("label") != "safe":
                    continue
                n_safe += 1
                kinds = kinds_for(meta)
                if not kinds:
                    continue
                n_eligible += 1
                code = code_of(rec)
                for cwe, kind in kinds:
                    r = witness_scan(code, kind)
                    if r:
                        hits.append({
                            "file": f, "line": ln, "pair_id": meta.get("pair_id", ""),
                            "source": meta.get("source", ""),
                            "language": meta.get("language", ""),
                            "cwe": cwe, "kind": kind, "bypass": r["bypass"],
                            "why": r["why"], "guard": r["guard"],
                        })
                        break  # one class is enough to flag the record

    with open("witness_audit.csv", "w", newline="", encoding="utf-8") as out:
        w = csv.DictWriter(out, fieldnames=["file", "line", "pair_id", "source",
                                            "language", "cwe", "kind", "bypass",
                                            "why", "guard"])
        w.writeheader()
        w.writerows(hits)

    print(f"scanned {len(files)} file(s): {n_safe} safe records, "
          f"{n_eligible} in a witness-covered CWE")
    print(f"-> {len(hits)} SAFE records whose guard is provably bypassable "
          f"(review candidates)\n")
    if not hits:
        print("no mislabel candidates found.")
        return 0
    by_kind, by_file = {}, {}
    for h in hits:
        by_kind[h["kind"]] = by_kind.get(h["kind"], 0) + 1
        by_file[h["file"]] = by_file.get(h["file"], 0) + 1
    print("by class:")
    for k, n in sorted(by_kind.items(), key=lambda x: -x[1]):
        print(f"  {k:9s} {n}")
    print("\nby file:")
    for k, n in sorted(by_file.items(), key=lambda x: -x[1]):
        print(f"  {n:4d}  {k}")
    print("\nfirst 12 hits:")
    for h in hits[:12]:
        print(f"  [{h['kind']}] {h['cwe']} {h['language']:4s} {h['source'][:18]:18s} "
              f"bypass={h['bypass']!r} :: {h['guard'][:56]}")
    print("\nfull list -> witness_audit.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
