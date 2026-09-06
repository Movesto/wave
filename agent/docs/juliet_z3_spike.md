# Juliet Z3 Spike — Findings (2026-08-22)

## Purpose
Measure **R3**, the one crux Phase 0 never touched: the **compiled/math pipeline's
translation rate** — can a model translate a labelled arithmetic-bug slice into a Z3
formulation that *runs* and *solves for an input that genuinely triggers the bug*?
(`docs/orchestrator_design.md` flagged the compiled pipeline + R3 as unmeasured.)

## Setup
- **Data:** NIST **Juliet C/C++ v1.3**, **CWE-190 (integer overflow)**. Downloaded, extracted
  15 baseline single-file free-input slices (`_01`, sources fgets/fscanf/rand, ops add/mul/square,
  types int + short). Harness + slices persisted to `data/downloads/juliet_spike/`.
- **Independent oracle (no C compilation):** parse the *actual* sink expression + C type from each
  file; a solved input `data` is a genuine trigger iff the **exact math result falls outside the C
  type range** (int=±2³¹, short=±2¹⁵). Juliet's type/op is the label, not the model.
- **Translator (intended):** DeepSeek V4 Flash via OpenRouter — the strong-model proxy for the
  untrained pipeline (a *ceiling* measure: stronger than the target 14B). Harness: `juliet_z3_spike.py`.
- **Solver:** `z3-solver` 5.1.0 on Python 3.14.

## Result

### ✅ Tools-PROVE leg (deterministic): 15/15 = **100%**
With the reference translation (`z3_toolcheck.py`), Z3 solved **every** slice to a genuinely
overflowing input — add (`data=INT_MAX`), multiply (`data=2³⁰`), square (large `data`), and
the subtle `short` square cases where the trigger is a **negative** input (e.g., `data=-16454`,
`(-16454)²=270M` ∉ int16). **The symbolic oracle for the arithmetic-overflow class is sound and
correct on real Juliet slices.** This de-risks the "tools prove" half of the compiled pipeline.

### ◐ Model-TRANSLATE leg (R3): measured at the CEILING via Claude-as-translator — 15/15
The intended translator (DeepSeek V4 Flash) was dead-key-blocked (`{"error":"User not found",401}`),
and — as the user pushed on — a frontier proxy only measures the *ceiling*, not the deployed 14B.
So the translator was **Claude (this session)** on a deliberately **harder/varied** set
(`z3_translate_hard.py`, slices in `jhard/`): CWE-190 **control-flow-obfuscated** variants
(`_12/_17`, decoy `globalReturnsTrueOrFalse()` branches), **CWE-191 underflow** (`data-1`, `data*2`),
and **CWE-369 divide-by-zero** (`100/data`, `100%data`) — **6 distinct sink semantics, 3 CWE classes**,
none reusing the baseline reference solver. Result: **15/15** — every slice translated to runnable Z3
whose solved input the independent per-CWE oracle confirms genuinely triggers the labelled bug
(overflow→INT_MAX, underflow→INT_MIN, div-by-zero→0), including through the decoy control flow.

### ★ Real R3 (DEPLOYED model): DeepSeek-R1-Distill-Qwen-14B, 4-bit, local — **10/15 = 67%**
The number the architecture actually rests on. Ran the design's target model locally (transformers
+ bitsandbytes nf4, ~10GB VRAM, GPU capped at 250W; `juliet_z3_local.py`) on the 15 baseline
CWE-190 slices, one-shot (a single exemplar showing the z3 API idioms on a *different* op — no
answer leak), scored by the same independent overflow oracle.

- **Zero-shot first:** the 14B **reasons correctly** (e.g., derives `data==INT_MAX` for add) but
  writes **broken z3 API** — `z3.BV(...)` (nonexistent), `solver.sat`, `as_int()` — so scripts crash.
  Right logic, wrong tool syntax → ~0.
- **One-shot (API demonstrated, as the deployed pipeline would):** **10/15 = 67%.** The 5 misses:
  - **2 bit-width errors** (multiply): computed `data*2` in a *32-bit* BitVec, which wraps, making
    the overflow condition unsatisfiable → wrong UNSAT. It used the widening (`SignExt`) idiom from
    the exemplar for subtraction but dropped it for multiply — a systematic, learnable slip.
  - **3 truncations**: over-long `<think>` hit the 3500-token cap before emitting code (all ~183s).
    A budget artifact, not a logic failure; a fine-tuned model reasons more concisely.
  - **10 correct**: oracle-verified genuine overflows (INT_MAX / 2³⁰ / large square / int16 bounds).

**Read:** this directly supports the DAGVUL bet — the untrained target model already translates 2/3
one-shot, and *every* failure is exactly what QLoRA on the gold exemplars addresses (the
widen-before-op idiom + shorter reasoning). 67% untrained is a floor, not a ceiling.

### ★★ DAGVUL bet TESTED DIRECTLY: QLoRA'd 14B = **15/15 = 100% zero-shot** (2026-08-23)
Fine-tuned DeepSeek-R1-Distill-Qwen-14B (QLoRA r16/α32, ~200 gold pairs from **held-out** Juliet
CWE-190/191/369 slices — the 15 test files EXCLUDED; `dagvul_build_data.py` + `dagvul_train.py`,
~27 min on the 5070Ti at 250W) then evaluated **zero-shot** (no exemplar) on the same 15 held-out
test slices: **15/15 correct**, oracle-verified. The progression on the identical test set:

| Config | correct-Z3 rate | failure modes |
|---|---|---|
| untrained, zero-shot | ~0% | reasons right, writes broken z3 API (`z3.BV`, `solver.sat`) |
| untrained, one-shot | 10/15 = 67% | 2 bit-width (32-bit `*` wraps), 3 truncations |
| **QLoRA'd, zero-shot** | **15/15 = 100%** | none — fixed the multiply widening AND the truncation |

QLoRA taught the correct idiom (`SignExt` widen-before-op + signed conversion) and concise
code-only output, repairing exactly the two diagnosed failure modes. **The neuro-symbolic thesis's
crux (R3) holds for the integer-arithmetic class: a small local model, cheaply fine-tuned on
tool-verifiable gold, translates to correct Z3 with 100% held-out accuracy.**

**Honest scope of the 100%:** it is **in-distribution by shape** — held-out *files*, but the same 6
sink shapes (add/mul/square/sub/div/mod × int/short) as training (loss→0 fast; the shapes are
templated). The generalization test below shows this 100% was **largely shape memorization.**

### ★★★ GENERALIZATION TEST — the 100% does NOT hold out of distribution: **4/15 = 27%** (2026-08-23)
`dagvul_generalize.py`, QLoRA'd model, zero-shot, on four axes NONE of which were in training
(int/short `bad()` only):

| Axis (out-of-distribution) | rate | what happened |
|---|---|---|
| **char** (8-bit, unseen type) | **3/3** ✓ | width-idiom transferred cleanly to a new type |
| **int64_t** (64-bit) | 1/3 | correct z3 logic, but copied the int32 signed-conversion **constants** (2^62/2^63 not 2^63/2^64) → corrupted the solution |
| **unsigned_int** (unsigned wrap) | 0/3 | applied *signed* overflow logic → all UNSAT; no semantic adaptation |
| **safe / goodB2G** (guarded → UNSAT) | **0/6** | emitted the identical overflow z3 and **ignored the guard entirely** — false-positive every time |

**The decisive finding:** the safe-side **0/6** is the project's oldest defect — *"learned a form, not
discrimination"* — reappearing. QLoRA on single-class templated gold taught the model to **emit
overflow-finding z3 for a recognized shape**, NOT to **translate the actual code** (its guards, its
type width/semantics). On real safe code it would false-positive every time. So the 100% headline is
**in-distribution memorization**, not general translation ability.

**But this is a DATA problem, not a refutation:** `char` proves the model *can* generalize width when
the idiom applies; every failure traces to the gold being narrow, single-class, and **non-contrastive**
(no unsigned, no 64-bit constants, and critically **no safe/guarded/UNSAT examples**). The fix is the
project's north-star principle applied here: **contrastive gold** — safe (UNSAT) alongside vuln, and
type/semantic diversity — so the model learns to translate the code, not the shape.

**What the CEILING run does and does NOT establish (honest):**
- ✅ The translate→prove chain is **fully expressible end-to-end** on real, varied, obfuscated Juliet
  slices — task viability confirmed, and it yields gold Z3 exemplars (few-shot / QLoRA targets).
- ⚠️ It is a **frontier ceiling with domain knowledge** (I also built the oracle) — an *upper bound*,
  not the number the architecture rests on.
- ⛔ Still **open**: the **deployed-model** rate (untrained 14B/9B, and after QLoRA — the DAGVUL bet),
  and **harder bug classes** (buffer/heap overflow needing memory modeling; multi-variable/pointer
  arithmetic). This spike covers the single-free-variable integer-arithmetic class only.

## Verify-before-shipping notes (two false results caught — the project's core anxiety, live)
1. **False negative:** first tool-run showed 13/15, but the 2 "misses" were a harness bug — z3's
   `as_long()` returns the *unsigned* 2's-complement form, so a valid negative solution (−539) read
   as 1.8×10¹⁹ and my oracle rejected it. Fixed sign conversion → 15/15.
2. **False *positive* (the dangerous one):** the first hard-set run reported a clean 15/15 — but a
   **greedy** body regex swallowed the whole file, so `/ data` matched everywhere and *every* slice
   (incl. CWE-190 `add`) was mislabeled div-by-zero and "passed" at data=0. A textbook **gate-passes-
   while-wrong**. Caught only because the output table showed `CWE190 … add … divzero` — obvious
   nonsense. Fixed (non-greedy body + strip comments) → the real, per-shape 15/15 above.
3. **False "0/3" (untrained):** looked like the model couldn't translate — hand-reading the raw
   output showed it *reasoned correctly* (`data==INT_MAX`) but wrote broken z3 API. A translation
   *execution* failure, not a reasoning one — completely different implication.
4. **False "0/15" (fine-tuned):** the QLoRA'd model emitted **perfect** z3 but as raw code (only a
   trailing fence), so the ```python-only parser scored it "nocode." Re-scored the already-saved
   generations with a lenient extractor → the true 15/15. (Harness extractor now fixed.)
This is exactly the failure mode the whole project distrusts; **all four** were caught by hand-reading
output, not by the gate. Trust the table (and the raw output), not the summary line.

## Interpretation
- The **oracle leg is proven** for the math class: given a correct Z3 encoding, the tool finds the
  bug deterministically. So the compiled-pipeline risk is now **entirely** on the *translation* leg
  (can the model emit that encoding) — exactly the R3 crux, now isolated.
- This mirrors the web-side finding inverted: on web, detection is carried by instrumented-sink +
  differential oracles (Z3 barely fires — gap C); on the math class, Z3 *is* the oracle and it works.

## Net + Next
**Net (revised after the generalization test):** the *tools* leg is solid (Z3 proves the class,
15/15). The *translation* leg is real but **shallow as trained**: the untrained 14B does 67% one-shot;
QLoRA lifts in-distribution to 100% — but that is **memorization of trained shapes**, and true
generalization is **27%**, with **0/6 on the safe/guarded side** (no discrimination — the core defect).
So the DAGVUL bet is **conditionally supported**: the mechanism works, but only diverse, CONTRASTIVE
gold will teach genuine translation rather than a form. Next, in priority:
1. **Contrastive + diverse curriculum (the real fix)** — regenerate gold to include SAFE/guarded
   cases (UNSAT), unsigned + 64-bit + char types, varied guards/ops; re-QLoRA; re-run BOTH the
   in-distribution eval and this generalization test. Target: safe-side accuracy up from 0/6.
2. **Harder classes** — buffer/heap overflow (memory modeling), multi-variable / pointer arithmetic.
3. The pipeline (build → validate gold → QLoRA → tool-verified eval → generalization test) is proven
   and reusable; the generalization test is now the gate that catches memorization.
Artifacts in `data/downloads/juliet_spike/`: harnesses, gold data, `dagvul_adapter/`, generalization
harness. GPU left at 250W; models unloaded. ENV: background GPU load is UNRELIABLE (killed at load
~half the time) — run GPU jobs FOREGROUND; the fine-tuned model is concise so eval fits the 10-min cap.
