#!/usr/bin/env python3
"""
Reformat the R2Vul dataset into Wave's Shape 1 (local scan + trace) schema.

R2Vul (MIT license): https://github.com/martin-wey/R2Vul
Data on Zenodo:      https://zenodo.org/records/16741648
  -> download and unzip, you want the `r2vul_dataset/` folder (the structured-
     reasoning training data). Put it at the R2VUL_DIR path below.

What R2Vul gives you (per the paper):
  - code function + language + label (vulnerable / non-vulnerable)
  - CWE / CVE metadata
  - VALID structured reasoning (chosen): faulty construct -> mechanism ->
    impact -> CWE/CVE
  - FLAWED structured reasoning (rejected): plausible-but-wrong (label-swapped)
  Teacher = Qwen2.5-Coder-32B. Languages = C#, JavaScript, Java, Python, C.
  NOTE: detection+explanation only -> no fix patch (we leave "fix: see reasoning").

This script:
  1) loads r2vul_dataset and PRINTS its schema + a sample  (confirm field names!)
  2) keeps only Python + JavaScript (your targets; no TS/React in R2Vul)
  3) builds shape-1 SFT records: <think> = valid reasoning, then the verdict
  4) ROUTES each through cot.shapes.shape1.verify() so malformed records get
     discarded (the same gate the rest of the pipeline uses)
  5) appends to data/cot/pilot/shape1.jsonl with checkpointing (idempotent re-runs)
  6) also emits valid/flawed pairs to data/cot/verifier_pairs_from_r2vul.jsonl
     for later use as preference data (chosen vs rejected reasoning).

IMPORTANT: the FIELD MAP below is a best guess. Run once, read the printed
schema, then edit F to match the real keys before trusting the output.
"""

import json
import os
import glob
import re
import sys
from collections import Counter

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from cot.shapes import shape1
from cot.checkpoint import CheckpointWriter
from cot.config import PILOT_DIR


# ---- paths ----
R2VUL_DIR = "data/r2vul_dataset"      # the HuggingFace-datasets format folder
COT_DIR = "data/cot"
PILOT_OUT = os.environ.get("WAVE_R2VUL_OUT", str(PILOT_DIR / "shape1.jsonl"))
VERIFIER_OUT = os.path.join(COT_DIR, "verifier_pairs_from_r2vul.jsonl")

# Which split(s) to convert. Train is the SFT target; you can add 'validation'
# and 'test' if you want everything, but be careful not to leak into eval.
SPLITS_TO_CONVERT = os.environ.get("WAVE_R2VUL_SPLITS", "train").split(",")

# ---- FIELD MAP — matches R2Vul's actual columns (verified from dataset_info.json) ----
F = {
    "code":     "function",            # source code of the function
    "language": "lang",                # 'python', 'javascript', 'java', 'csharp', 'c'
    "label":    "vulnerable",          # int64: 1 = vulnerable, 0 = safe
    "cwe":      "cwe_id",              # Sequence[string]: e.g. ["CWE-89"]
    "cve":      "cve_id",              # optional
    "valid":    "positive_reasoning",  # valid structured reasoning  -> SFT target
    "flawed":   "negative_reasoning",  # flawed reasoning            -> verifier negative
}

KEEP_LANGS = set(os.environ.get("WAVE_R2VUL_LANGS", "python,javascript").split(","))
VULN_VALUES = {"1", 1, True, "vulnerable", "vuln", "yes", "true"}

# CWE -> severity default. R2Vul has no severity; we infer a reasonable default
# so the verifier's HIGH/MEDIUM/LOW parser accepts the record. Tune to taste.
SEVERITY_FOR_CWE = {
    # Auth/identity/code-execution -> HIGH
    "CWE-78": "HIGH", "CWE-79": "HIGH", "CWE-89": "HIGH", "CWE-90": "HIGH",
    "CWE-94": "HIGH", "CWE-22": "HIGH", "CWE-502": "HIGH", "CWE-611": "HIGH",
    "CWE-918": "HIGH", "CWE-798": "HIGH", "CWE-639": "HIGH", "CWE-862": "HIGH",
    "CWE-863": "HIGH", "CWE-915": "HIGH", "CWE-269": "HIGH", "CWE-352": "HIGH",
    "CWE-119": "HIGH", "CWE-787": "HIGH", "CWE-125": "HIGH", "CWE-416": "HIGH",
    # Crypto/config/info-disclosure -> MEDIUM
    "CWE-327": "MEDIUM", "CWE-326": "MEDIUM", "CWE-330": "MEDIUM",
    "CWE-1004": "MEDIUM", "CWE-1321": "MEDIUM", "CWE-601": "MEDIUM",
    "CWE-208": "MEDIUM", "CWE-209": "MEDIUM", "CWE-295": "MEDIUM",
    "CWE-117": "MEDIUM", "CWE-770": "MEDIUM", "CWE-362": "MEDIUM",
    # Info exposure -> LOW
    "CWE-200": "LOW",
}


# ---- helpers ----

def load_r2vul(path: str):
    """Load R2Vul as a HuggingFace Arrow dataset and return records from the
    selected splits. Each record is a plain dict."""
    from datasets import load_from_disk
    ds = load_from_disk(path)
    rows = []
    for split_name in SPLITS_TO_CONVERT:
        if split_name not in ds:
            print(f"  WARN: split {split_name!r} not in dataset; available: {list(ds.keys())}")
            continue
        split = ds[split_name]
        print(f"  split {split_name!r}: {len(split):,} records")
        for rec in split:
            rows.append(rec)
    return rows


def g(rec, key):
    return rec.get(F[key]) if isinstance(rec, dict) else None


def is_vuln(rec):
    raw = g(rec, "label")
    # R2Vul uses int64 0/1; be permissive about other formats too
    if isinstance(raw, (int, bool)):
        return int(raw) == 1
    return str(raw).strip().lower() in {str(x).lower() for x in VULN_VALUES}


def clean_reasoning(text):
    """Light touch -- strip R2Vul's own <thinking>/<reasoning> wrappers so we
    don't end up with nested <think><thinking>...</thinking></think> in our
    training data."""
    if not text:
        return ""
    t = str(text).strip()
    t = re.sub(r"^\s*(reasoning|analysis|answer)\s*:\s*", "", t, flags=re.I)
    # Remove R2Vul's own outer wrapper tags so they don't nest.
    t = re.sub(r"</?\s*thinking\s*>", "", t, flags=re.I)
    t = re.sub(r"</?\s*think\s*>", "", t, flags=re.I)
    t = re.sub(r"</?\s*reasoning\s*>", "", t, flags=re.I)
    t = re.sub(r"</?\s*analysis\s*>", "", t, flags=re.I)
    return t.strip()


def normalize_cwe(raw):
    """R2Vul's cwe_id is a Sequence[str]. Pull the first entry and normalize."""
    if not raw:
        return None
    if isinstance(raw, (list, tuple)):
        if not raw:
            return None
        raw = raw[0]
    m = re.search(r"CWE-?(\d+)", str(raw), flags=re.I)
    return f"CWE-{m.group(1)}" if m else None


def normalize_lang(raw):
    s = str(raw or "").lower()
    if "javascript" in s or s == "js":
        return "javascript"
    if "python" in s or s == "py":
        return "python"
    return s


def build_user(code, lang):
    """Match the exact format used by manual_pilot.py / extra_shape1_traces.py."""
    return f"<SCAN>\n{code}\n</SCAN>"


def derive_trace_summary(reasoning: str, cwe: str | None, lang: str | None,
                          is_vulnerable: bool) -> str:
    """Extract a one-line trace summary from the R2Vul reasoning. Used as the
    `trace:` field AND propagated to shape4 finding-set titles, so it must be
    informative — never a placeholder."""
    if not reasoning:
        return f"{cwe or 'CWE-UNK'} in {lang or 'code'}" if is_vulnerable else "safe code pattern"

    # Take the first sentence-ish chunk. Reasoning often starts with numbered points
    # or markdown bullets; strip those.
    t = re.sub(r"^[\s\d\.\)\*\-•]+", "", reasoning).strip()
    # First sentence
    parts = re.split(r"[.!?]\s+", t, maxsplit=1)
    head = parts[0].strip() if parts else t
    # Cap at 120 chars to keep it title-shaped
    if len(head) > 120:
        head = head[:117].rstrip() + "..."
    # Reject pathological cases
    if len(head) < 20:
        return f"{cwe or 'CWE-UNK'} in {lang or 'code'}" if is_vulnerable else "safe code pattern"
    return head


def derive_fix_summary(reasoning: str, is_vulnerable: bool) -> str:
    """Try to extract a fix hint from the reasoning. Falls back to a generic
    pointer when the reasoning doesn't explicitly suggest one."""
    if not is_vulnerable:
        return "none"
    if not reasoning:
        return "consult security guidance for this CWE class"
    # Look for sentences mentioning fix/patch/sanitize/use/replace
    m = re.search(
        r"([A-Z][^.!?]*?\b(fix|patch|sanitize|replace|use(?:s|d)?\s+\w+|should|must)\b[^.!?]*[.!?])",
        reasoning,
    )
    if m:
        s = m.group(1).strip()
        if len(s) <= 200:
            return s
        return s[:197].rstrip() + "..."
    return "remediate at the dangerous sink (see reasoning for details)"


def build_assistant(rec):
    """Build <think> + structured verdict. Format matches what shape1.verify() expects.
    Crucially, derives REAL trace+fix summaries from the reasoning rather than
    placeholders — these get propagated to shape4 finding titles."""
    think = clean_reasoning(g(rec, "valid"))
    cwe = normalize_cwe(g(rec, "cwe"))
    lang = normalize_lang(g(rec, "language"))
    vuln = is_vuln(rec)
    trace = derive_trace_summary(think, cwe, lang, vuln)
    fix = derive_fix_summary(think, vuln)

    if vuln:
        severity = SEVERITY_FOR_CWE.get(cwe, "MEDIUM")
        return (
            f"<think>\n{think}\n</think>\n\n"
            f"status: confirmed\n"
            f"cwe: {cwe or 'CWE-UNK'}\n"
            f"severity: {severity}\n"
            f"line: none\n"
            f"trace: {trace}\n"
            f"fix: {fix}\n"
        )
    return (
        f"<think>\n{think}\n</think>\n\n"
        f"status: safe\n"
        f"cwe: none\n"
        f"severity: none\n"
        f"line: none\n"
        f"trace: {trace}\n"
        f"fix: none\n"
    )


def build_task_record(rec, idx) -> dict | None:
    """Construct the task dict and response that shape1.verify() will consume."""
    code = g(rec, "code")
    lang = normalize_lang(g(rec, "language"))
    if not code or lang not in KEEP_LANGS:
        return None
    cwe = normalize_cwe(g(rec, "cwe"))
    task = {
        "task_id":   f"shape1:r2vul:{idx}",
        "source":    "r2vul",
        "language":  lang,
        "label":     "vuln" if is_vuln(rec) else "safe",
        "cwe":       cwe,
        "code":      code,
        "fixed_code": None,
    }
    response = build_assistant(rec)
    return {"task": task, "response": response}


def build_verifier_pair(rec):
    """Bonus output: (valid, flawed) reasoning pairs for later preference training."""
    flawed = clean_reasoning(g(rec, "flawed"))
    if not flawed:
        return None
    return {
        "code":           g(rec, "code"),
        "language":       normalize_lang(g(rec, "language")),
        "label":          "vuln" if is_vuln(rec) else "safe",
        "cwe":            normalize_cwe(g(rec, "cwe")),
        "good_reasoning": clean_reasoning(g(rec, "valid")),
        "bad_reasoning":  flawed,
    }


# ---- run ----

def main():
    if not os.path.isdir(R2VUL_DIR):
        print(f"ERROR: R2VUL_DIR not found: {R2VUL_DIR}")
        print(f"\nDownload from https://zenodo.org/records/16741648,")
        print(f"unzip the r2vul_dataset folder, and put it at: {R2VUL_DIR}")
        sys.exit(1)

    print(f"Loading R2Vul (HuggingFace Arrow format) from {R2VUL_DIR}")
    print(f"Splits to convert: {SPLITS_TO_CONVERT}\n")
    rows = load_r2vul(R2VUL_DIR)
    print(f"\nLoaded {len(rows):,} raw records total\n")

    if not rows:
        print("EMPTY — check the path / file pattern")
        sys.exit(1)

    # STEP 1 — confirm schema before trusting the field map
    print("=" * 70)
    print("SCHEMA DUMP (first record)")
    print("=" * 70)
    first = rows[0]
    print(f"\nTop-level keys: {sorted(first.keys()) if isinstance(first, dict) else type(first).__name__}")
    print(f"\nSample record (truncated):")
    print(json.dumps(first, indent=2)[:1800])
    print()
    print(">>> If these keys don't match FIELD MAP `F` at the top of this script,")
    print(">>> edit F and re-run. Current map:")
    for k, v in F.items():
        present = "OK" if isinstance(first, dict) and v in first else "MISSING"
        print(f"      F[{k!r:<10s}] -> {v!r:<20s}  [{present}]")
    print()

    # STEP 2 — process records
    print("=" * 70)
    print("CONVERSION")
    print("=" * 70)
    stats = {
        "total": len(rows),
        "wrong_language": 0,
        "missing_fields": 0,
        "kept": 0,
        "discarded_by_verifier": 0,
        "verifier_pairs": 0,
    }
    langc = Counter()
    verdictc = Counter()

    os.makedirs(COT_DIR, exist_ok=True)
    verifier_records = []

    with CheckpointWriter(PILOT_OUT) as w:
        for i, rec in enumerate(rows):
            built = build_task_record(rec, i)
            if built is None:
                # missing code or wrong language
                lang = normalize_lang(g(rec, "language"))
                if lang and lang not in KEEP_LANGS:
                    stats["wrong_language"] += 1
                else:
                    stats["missing_fields"] += 1
                continue

            task = built["task"]
            record = shape1.verify(task, built["response"])
            if record is None:
                stats["discarded_by_verifier"] += 1
                continue

            w.write(task["task_id"], record)
            stats["kept"] += 1
            langc[task["language"]] += 1
            verdictc["vuln" if task["label"] == "vuln" else "safe"] += 1

            pair = build_verifier_pair(rec)
            if pair:
                verifier_records.append(pair)
                stats["verifier_pairs"] += 1

            if (i + 1) % 500 == 0:
                print(f"  {i+1}/{len(rows)} processed | kept={stats['kept']} discarded={stats['discarded_by_verifier']}")

    with open(VERIFIER_OUT, "w", encoding="utf-8") as fh:
        for p in verifier_records:
            fh.write(json.dumps(p, ensure_ascii=False) + "\n")

    print()
    print("=" * 70)
    print("RESULT")
    print("=" * 70)
    print(f"  total input records:     {stats['total']:,}")
    print(f"  wrong language:          {stats['wrong_language']:,}")
    print(f"  missing fields:          {stats['missing_fields']:,}")
    print(f"  discarded by verifier:   {stats['discarded_by_verifier']:,}")
    print(f"  KEPT:                    {stats['kept']:,}")
    print()
    print(f"  by language: {dict(langc)}")
    print(f"  by verdict:  {dict(verdictc)}")
    print()
    print(f"  Wrote:")
    print(f"    pilot (shape1):       {PILOT_OUT}")
    print(f"    verifier pairs:       {VERIFIER_OUT}  ({stats['verifier_pairs']:,} pairs)")
    print()
    print("NEXT:")
    print("  - spot-check ~20 records: head -5 data/cot/pilot/shape1.jsonl")
    print("  - re-run split_pilot_to_eval.py if you want larger eval holdout")
    print("  - the verifier-pairs file is for later DPO/preference training")


if __name__ == "__main__":
    main()
