"""Dedup + stage the contrastive set into pilot_clean (2026-07-24).

1. Split staging/shape1_contrastive.jsonl by origin into:
     pilot_clean/shape1_contrastive.jsonl      (real, high weight)
     pilot_clean/shape1_contrastive_syn.jsonl  (synthetic, low weight)
2. Remove from the EXISTING pilot_clean shape files any record whose (normalized)
   code matches a contrastive record — so the same code isn't represented twice
   (once unpaired-topic, once paired-guard). The paired version wins. Backs up
   each modified file to *.prededup_bak. Never touches the two contrastive files.
"""
import json, glob, os, re, collections, shutil

PILOT = "data/cot/pilot_clean"
STAGE = "data/cot/staging/shape1_contrastive.jsonl"
REAL_OUT = f"{PILOT}/shape1_contrastive.jsonl"
SYN_OUT = f"{PILOT}/shape1_contrastive_syn.jsonl"


def norm(s): return re.sub(r"\s+", " ", s or "").strip().lower()
def code_of(user):
    m = re.search(r"<SCAN>\n?(.*?)\n?</SCAN>", user, re.S)
    return m.group(1) if m else user
def rec_code(r): return norm(code_of(r["messages"][0]["content"]))


# --- 1. split by origin ---
con = [json.loads(l) for l in open(STAGE, encoding="utf-8")]
real = [r for r in con if r["_meta"]["origin"] == "real"]
syn = [r for r in con if r["_meta"]["origin"] == "vuln_fix_dataset"]
with open(REAL_OUT, "w", encoding="utf-8") as f:
    for r in real: f.write(json.dumps(r, ensure_ascii=False) + "\n")
with open(SYN_OUT, "w", encoding="utf-8") as f:
    for r in syn: f.write(json.dumps(r, ensure_ascii=False) + "\n")
print(f"split: real {len(real)} -> {REAL_OUT} | synthetic {len(syn)} -> {SYN_OUT}")

# --- 2. dedup existing files against the contrastive code set ---
contra_codes = {rec_code(r) for r in con}
print(f"contrastive distinct codes: {len(contra_codes)}")

CONTRA_FILES = {os.path.basename(REAL_OUT), os.path.basename(SYN_OUT)}
total_removed = 0
per_file = collections.Counter()
for path in sorted(glob.glob(f"{PILOT}/*.jsonl")):
    if os.path.basename(path) in CONTRA_FILES:
        continue
    recs = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    keep = [r for r in recs if rec_code(r) not in contra_codes]
    removed = len(recs) - len(keep)
    if removed:
        shutil.copy2(path, path + ".prededup_bak")
        with open(path, "w", encoding="utf-8") as f:
            for r in keep: f.write(json.dumps(r, ensure_ascii=False) + "\n")
        per_file[os.path.basename(path)] = removed
        total_removed += removed

print(f"\nremoved {total_removed} overlapping unpaired records from existing files:")
for f, n in per_file.most_common():
    print(f"  {f}: -{n}")
print(f"\nnet corpus change: +{len(con)} contrastive, -{total_removed} overlaps")
