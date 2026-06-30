# Wave — A Chain-of-Thought Source-Code Vulnerability Scanner

Fine-tuning an 8B open model (Qwen3-8B) with QLoRA to scan source code and emit a
**structured, reasoned verdict**: is this code vulnerable, which CWE, where, how the
tainted data flows from source to sink, and how to fix it — all on a single
16 GB consumer GPU (RTX 5070 Ti).

This README is the honest project log: what we built, the dead ends we hit, how we
got past them, and the things we got **wrong**. The mistakes are the most useful part.

---

## What the model does

Given a code snippet wrapped in `<SCAN>…</SCAN>`, the model produces:

```
<think>
1. `uid` enters from the route parameter /user/<uid> (untrusted).
2. It is concatenated into a SQL string via an f-string.
3. The string is passed to db.execute with no parameterization.
4. An attacker controlling `uid` can alter the query — SQL injection.
</think>
status: confirmed
cwe: CWE-89
severity: HIGH
line: 3
trace: uid -> f-string -> q -> db.execute(q)
fix: Use a parameterized query, e.g. cur.execute("...WHERE id = %s", (uid,))
```

The **headline metric is false-positive rate on safe code** (alert fatigue is what
kills a scanner in practice); vuln recall is secondary.

---

## The core architecture

- **Teacher → student distillation.** A teacher generates chain-of-thought traces;
  the 8B student is fine-tuned on them. The teacher was a *local, free* model
  (`gpt-oss-20b`) — no API costs.
- **"Shapes"** — trace formats: `shape1` (local single-file scan), `shape2`
  (needs more context), `shape3` (cross-file), `shape4` (synthesis).
- **The oracle.** For data sourced from CVE *patches*, the diff between vulnerable
  and fixed code tells us exactly where the vulnerability is — ground truth for free.
- **Verification gates** (`cot/gates.py`, `cot/oracle.py`) — a generated trace is
  kept only if its CWE matches the label, its sink lands near the patched lines,
  and it describes a concrete source→sink flow. Bad traces are dropped, not
  hand-cleaned.

---

## The journey (including the dead ends)

### Era 0 — From-scratch / plain SFT (abandoned)
The project began trying to train a small LM from scratch and then plain
instruction-tuning. It plateaued and produced weak verdicts with no reasoning.
**Lesson:** for a reasoning task, distilling chain-of-thought into a capable base
beats training a small model from zero. Pivoted to the CoT + QLoRA approach.
(The old code — `train.py`, `train_qwen_sft.py`, etc. — has been removed.)

### Era 1 — The data-quality wars
The first CoT pilot "worked" but the data was quietly broken in ways that train a
model to do the *wrong* thing:
- **Safe-branch contradictions** — `safe` records carried `cwe:` tags and
  `severity: HIGH` in their fields (the generator stored raw model output without
  normalizing). This literally teaches the model to flag safe code. Fixed with
  `normalize_safe_assistant()`.
- **Menu-echo placeholders** (`cwe: CWE-78 | none`) — 349 records cleaned.
- **Fragment hunks** — imports/types only, no traceable logic.
- **Deterministic-clone duplication** — a fixed-seed local model produced 736
  "synthetic React" records that were really **12 unique snippets cloned ~60×**.
  **Lesson:** synthetic/template data needs prompt-level diversity *and* temperature,
  and you must always count unique snippets after generation.

### Era 2 — The accuracy ceiling
Across versions v2–v8, balanced accuracy sat at **~72–74%**, and every data tweak
just slid the operating point along the same curve — lower FPR bought lower recall
and vice-versa. The ceiling turned out to be **teacher quality**: a weak local
teacher can't produce above-weak reasoning, so the student inherits the cap.

### Era 3 — Verified regeneration (Trellis-inspired)
Instead of hand-cleaning, **gate every generated trace against the oracle and drop
failures.** Built `cot/oracle.py` (diff → changed lines/identifiers, with a Bandit
fallback) and `cot/gates.py`. This made the weak teacher *usable* — we keep only the
traces it gets right. Also discovered the deepest data bug: `morefixes_pairs.jsonl`
`<SCAN>` blocks were concatenated diff-hunks, not coherent functions — so we switched
to parsing the **32,008 raw `.patch` files** directly (99% oracle-locatable).

### Era 4 — Bigger student: DeepSeek-R1-Distill-14B (FAILED)
Hypothesis: a larger, reasoning-distilled student breaks the ceiling. We QLoRA-trained
R1-Distill-Qwen-14B for ~27 hours. **It was unusable:**
- **0/42 parse success** — its distilled reasoning reflex emits free-form prose, never
  our structured format. (Exactly the "over-thinking" risk we'd flagged.)
- **52% accuracy** even when we re-scored its prose leniently — chance level.

**Verdict:** R1's reasoning is math/logic-tuned, not security-code-tuned, and a light
LoRA can't override it. Capacity was never the bottleneck — data was. We shelved it.

### Era 5 — Operating points (v6 / v7 / v8)
With the verified pipeline scaled up, three models mapped the full ROC curve:
| Model | recall | FPR | balanced acc |
|---|---|---|---|
| v7 (safe-leaning) | 44.9% | 11.5% | 66.7% |
| v6 (middle) | 61.5% | 27.6% | 67.0% |
| **v8 (vuln-leaning)** | 72.5% | 31.2% | **70.7%** |
The one slice that genuinely *lifted* the curve was `shape1_verified` (oracle-gated
data) — confirming that **only higher-quality data lifts the curve; weighting only
slides along it.**

### Era 6 — The great hardening, and a costly discovery
We audited the entire corpus for label correctness and consistency. We found —
and this is the big one — **1,147 training records whose code also appeared in the
eval set** (normalized for whitespace). Exact-match de-leaking at train time had
missed these formatting-variant near-duplicates, which means **past v6/v7/v8 eval
numbers were somewhat inflated.** Removing them made the eval trustworthy.

The corpus went through five gauntlets: structural/label consistency, contradiction
removal (same code labeled both safe *and* vuln), normalized dedup, eval-leak removal,
and over-length removal. Result: a clean, balanced, leak-free corpus.

### Era 7 — Deterministic mining (no teacher needed)
Key realization: **most conversion needs no model at all.**
- **R2Vul** ships expert reasoning + CWE per row → reformat directly (+10,483
  C/Java/C# traces, free).
- **Patches** → the oracle gives the real sink; **per-CWE "contracts"**
  (`cot/cwe_contracts.py`, authored once, above the ceiling) supply the reasoning
  skeleton → assemble traces deterministically (`cot/template_reason.py`).
- Mined JS/TS/React + PHP/C/Java/Go patches, CVEfixes, cve-fix-pairs, and FixJS.

The corpus grew **8,132 → 26,177 traces** across 7 languages, with the old crypto /
ReDoS / DoS / auth blind spots filled.

### Era 8 — v9
Retrained on the hardened, leak-free, 2.5×-larger corpus. (Validation/eval in
progress at the time of writing.)

---

## What we got wrong (the honest list)

1. **Trusted exact-match de-leaking.** Formatting-variant duplicates leaked train↔eval
   for many versions → inflated numbers. *Always normalize before dedup/leak checks.*
2. **Bet on a bigger student (R1-14B) before exhausting data.** Burned ~27h proving
   the bottleneck was data, not capacity — which we could have reasoned about first.
3. **Synthetic data didn't transfer.** Synthetic React scored 100% on synthetic eval
   and **29% on real React.** Toy data teaches toy patterns.
4. **Over-strict verification, twice.** Gates built for *generation* (policing a weak
   model on unlabeled code) were wrong for *cleaning labeled expert data* — they
   false-quarantined **1,858 good R2Vul traces** (treating prose words like "SQL" as
   missing code identifiers, and legit "if an attacker…" exploit explanations as
   "speculation"). Caught only by sampling the quarantine. *Always eyeball what a
   filter rejects before trusting it.*
5. **First template assembler grounded the sink on the wrong token** — it grabbed a
   *fix*-introduced identifier (`whitelisting`) instead of the real sink. Fixed by
   locating the sink via contract markers in the *vulnerable* code.
6. **Inherited a second model's two wrong premises** ("FP is fixed in v8" — it wasn't,
   v8's FPR is 31–50%; "the traces are already improved" — they weren't) and had to
   correct them against the actual eval.
7. **Gemini-as-teacher dead end.** GCP free-trial credits aren't eligible for the
   Generative Language API; a free-tier project couldn't be created. Abandoned;
   teacher stayed local.
8. **Underestimated eval time** (quoted 30–60 min; the full eval is ~11 h).

---

## Key lessons

- **Data quality is the ceiling, not model size.** Proven twice (R1-14B failure;
  v6/v7/v8 plateau).
- **A weak model never *authors* quality — it *applies* a contract you authored above
  its ceiling, under a verifier.** Spend strong capability once (≈15 CWE contracts +
  a verifier), not on every record.
- **Headline metric = false positives.** A scanner that cries wolf is ignored.
- **Verify labels structurally before training** — status↔label match, no
  contradictions, no leakage — *that's where failure starts.*
- **Sample what your filters reject.** Over-strict gates silently delete good data.

---

## Repository structure

```
cot/                      core library
  oracle.py               patch-diff → vulnerability location (ground truth)
  gates.py                verification gates (correspondence/localization/cwe/substance)
  cwe_contracts.py        per-CWE reasoning contracts + cross-CWE bleed detector
  template_reason.py      deterministic trace assembler (contract + oracle)
  postprocess.py          field cleanup (markdown/CVE-noise/run-on repair)
  fix_pairs.py            (vuln, fixed, cwe, language) loader from patches/CSVs
  vuln_types.py           sink → vuln-type/CWE classifier
  shapes/                 trace formats (shape1..4, verified, safe)
eval/                     evaluation harness (inference, parsers, scoring, loader)
tests/                    unit tests for oracle + gates

train_qwen_cot.py         QLoRA trainer (env-configurable)
run_eval.py               full evaluation
reformat_r2vul_to_shape1.py   R2Vul → traces (no model)
convert_patches_wave3.py  patches → traces via template assembler
convert_cvefixes.py       CVEfixes → traces
convert_fixjs.py          FixJS → security traces
clean_and_verify.py       clean + verify + quarantine
harden_corpus.py          leak / near-dup / over-length removal
validate_corpus.py        label-correctness & consistency audit
balance_analysis.py       per-language / per-CWE balance report
DATA_INVENTORY.md         full inventory of every dataset on disk
```

> Data and model checkpoints are **gitignored** (too large for git). The pipeline
> scripts regenerate the corpus from the raw sources.

---

## Pipeline (end to end)

```bash
# 1. Convert raw sources → traces (no model needed)
python reformat_r2vul_to_shape1.py            # R2Vul expert reasoning
python convert_patches_wave3.py --langs javascript,typescript,react
python convert_cvefixes.py ; python convert_fixjs.py

# 2. Clean → verify → harden → audit
python clean_and_verify.py                    # + --pilot <file> per new source
python harden_corpus.py                       # leak / dup / length
python validate_corpus.py                     # must report zero issues

# 3. Train
WAVE_PILOT_DIR=data/cot/pilot_clean python train_qwen_cot.py

# 4. Evaluate
WAVE_ADAPTER_PATH=data/qwen_cot_best python run_eval.py eval --label cot_vN --skip-judge
```

---

## Data sources

| Source | Size | Fidelity |
|---|---|---|
| R2Vul (C/Py/Java/JS/C#) | ~18.3K rows | high (expert reasoning + CWE) |
| morefixes CVE patches | 32K `.patch` files | high (diff oracle) |
| CVEfixes | ~31K rows | low (no CWE/oracle) |
| FixJS (JS bug-fixes) | 66K pairs | low (general bugs, security-filtered) |
| cve-fix-pairs | 40 rows | high |

166 distinct CWEs represented; heavily web-injection (XSS/SQLi/SSRF/path-traversal)
with crypto / DoS / auth coverage added in the mining waves.
