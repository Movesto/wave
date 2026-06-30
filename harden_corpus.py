"""Deeper hardening passes over pilot_clean. Reports what each changes.

  A. train/eval LEAKAGE  — code that also appears in data/cot/eval/ (normalized)
  B. near-DUPLICATE      — formatting-only twins (normalized hash) within train
  C. code<->CWE plausibility (REPORT ONLY) — does classify(code)'s family match
     the labelled CWE family? (classify isn't authoritative -> flag, don't drop)
  D. over-LENGTH         — code likely to exceed the training window (NaN risk)

A/B/D quarantine; C reports. Run validate_corpus.py afterwards.
"""
import io, json, re, glob, hashlib
from collections import Counter, defaultdict
from pathlib import Path

from cot.vuln_types import classify
from cot.cwe_contracts import family_of

CLEAN = "data/cot/pilot_clean"
EVAL = "data/cot/eval"
QUAR = Path("data/cot/quarantine")
MAXCHARS = 6000  # ~1600 tokens; over this risks the training window


def norm_code(text):
    t = re.sub(r"</?SCAN>", "", text)
    t = re.sub(r"#.*|//.*", "", t)                 # strip line comments
    t = re.sub(r"\s+", "", t).lower()              # whitespace-insensitive
    return hashlib.sha256(t.encode()).hexdigest()


def nlabel(l):
    return "vuln" if l in ("vuln", "confirmed") else ("safe" if l == "safe" else "context")


def main():
    eval_hashes = set()
    for p in glob.glob(f"{EVAL}/*.jsonl"):
        for line in io.open(p, encoding="utf-8"):
            if line.strip():
                try:
                    eval_hashes.add(norm_code(json.loads(line)["messages"][0]["content"]))
                except Exception:
                    pass

    leak_f = io.open(QUAR / "_leak.jsonl", "w", encoding="utf-8")
    ndup_f = io.open(QUAR / "_neardup.jsonl", "w", encoding="utf-8")
    long_f = io.open(QUAR / "_overlength.jsonl", "w", encoding="utf-8")
    seen = set()
    n_leak = n_ndup = n_long = n_keep = 0
    cwe_mismatch = []
    by_label_kept = Counter()

    for p in sorted(glob.glob(f"{CLEAN}/*.jsonl")):
        kept = []
        for line in io.open(p, encoding="utf-8"):
            if not line.strip():
                continue
            r = json.loads(line)
            code = r["messages"][0]["content"]
            h = norm_code(code)
            if h in eval_hashes:
                leak_f.write(line); n_leak += 1; continue
            if h in seen:
                ndup_f.write(line); n_ndup += 1; continue
            if len(code) > MAXCHARS:
                long_f.write(line); n_long += 1; continue
            seen.add(h)
            # C: plausibility (report only)
            lbl = nlabel(r["_meta"].get("label"))
            gt = r["_meta"].get("ground_truth_cwe")
            if lbl == "vuln" and gt:
                _, ccwe = classify(code)
                if ccwe and family_of(ccwe) and family_of(gt) and family_of(ccwe) != family_of(gt):
                    cwe_mismatch.append((gt, ccwe))
            kept.append(line.rstrip("\n"))
            n_keep += 1
            by_label_kept[lbl] += 1
        with io.open(p, "w", encoding="utf-8") as out:
            out.write("\n".join(kept) + ("\n" if kept else ""))
    leak_f.close(); ndup_f.close(); long_f.close()

    print("=== HARDENING RESULTS ===")
    print(f"  A. eval-leak removed:        {n_leak}")
    print(f"  B. near-duplicate removed:   {n_ndup}")
    print(f"  D. over-length removed:      {n_long}")
    print(f"  KEPT: {n_keep}   {dict(by_label_kept)}")
    print()
    print(f"  C. code<->CWE family mismatch (REPORT only): {len(cwe_mismatch)}")
    mm = Counter(f"{a}->{b}" for a, b in cwe_mismatch)
    for k, v in mm.most_common(10):
        print(f"     {k:<28}{v}")


if __name__ == "__main__":
    main()
