"""Final consistency pass over pilot_clean: remove cross-label contradictions
(same code labelled both safe & vuln) and exact-duplicate code blocks.
Removed records -> quarantine/_contradictions.jsonl / _duplicates.jsonl."""
import io, json, glob, hashlib
from collections import defaultdict
from pathlib import Path

CLEAN = "data/cot/pilot_clean"
QUAR = Path("data/cot/quarantine")


def norm(l):
    return "vuln" if l in ("vuln", "confirmed") else ("safe" if l == "safe" else "context")


def ch(r):
    return hashlib.sha256(r["messages"][0]["content"].strip().encode()).hexdigest()


def main():
    files = sorted(glob.glob(f"{CLEAN}/*.jsonl"))
    labels_by_hash = defaultdict(set)
    for p in files:
        for line in io.open(p, encoding="utf-8"):
            if line.strip():
                r = json.loads(line)
                labels_by_hash[ch(r)].add(norm(r["_meta"].get("label")))
    contradiction = {h for h, labs in labels_by_hash.items() if "safe" in labs and "vuln" in labs}

    seen = set()
    n_keep = n_contra = n_dup = 0
    cf = io.open(QUAR / "_contradictions.jsonl", "w", encoding="utf-8")
    df = io.open(QUAR / "_duplicates.jsonl", "w", encoding="utf-8")
    for p in files:
        kept = []
        for line in io.open(p, encoding="utf-8"):
            if not line.strip():
                continue
            r = json.loads(line)
            h = ch(r)
            if h in contradiction:
                cf.write(line)
                n_contra += 1
                continue
            if h in seen:
                df.write(line)
                n_dup += 1
                continue
            seen.add(h)
            kept.append(line.rstrip("\n"))
            n_keep += 1
        with io.open(p, "w", encoding="utf-8") as out:
            out.write("\n".join(kept) + ("\n" if kept else ""))
    cf.close()
    df.close()
    print(f"kept: {n_keep}")
    print(f"removed contradictions (same code both labels): {n_contra}")
    print(f"removed exact-duplicate code blocks: {n_dup}")


if __name__ == "__main__":
    main()
