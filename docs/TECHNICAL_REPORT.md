# Wave — Technical Report

**A chain-of-thought vulnerability scanner: what was built, what worked, and what did not.**

Status: 2026-07-26 · Production model **v10** · Candidate **v12** in training · Corpus **67,492** training records / **1,317** held-out

---

## Abstract

Wave fine-tunes an 8B open model (Qwen3-8B, QLoRA, 4-bit, single 16GB consumer GPU) to
read source code and emit a structured, reasoned vulnerability verdict — CWE, location,
source→sink data-flow trace, and fix. Around the model sits a corpus-construction
pipeline that converts CVE patches, expert-annotated datasets, and static-analysis output
into chain-of-thought traces without paying for a teacher API, and a multi-stage scanner
that uses deterministic tools to *find* and the model only to *triage*.

Twelve model versions were trained. The headline result is not the accuracy number. It is
a set of **negative results that were expensive to obtain and are individually
transferable**: model capacity was never the bottleneck; data quality alone lifts the
curve while sampling weights only slide along it; synthetic security data does not
transfer; and — the finding that reframes the project — the model learned **topic
discrimination rather than guard discrimination**, which the evaluation was structurally
incapable of detecting.

This document records the system, the evidence, and the open problems. It is deliberately
weighted toward what failed, because that is where the reusable information is.

> Scope note: `README.md` is the narrative project log and covers the early eras (v1–v9)
> in more detail. This report is the technical reference and carries the later work
> (v10–v12, the scanner, contrastive training, and the evaluation critique) that the
> README predates.

---

## 1. Problem

Static analyzers find vulnerabilities by pattern and produce no explanation. LLM scanners
explain but hallucinate and over-flag. The goal was a scanner that does both: catches a
real flaw *and* justifies it with a concrete data-flow argument a reviewer can check, at a
false-positive rate low enough that people keep it switched on.

**The headline metric is false-positive rate on safe code**, not recall. A scanner that
cries wolf gets uninstalled. This choice drove every later decision and is the reason
several "better" models were not promoted.

---

## 2. System

### 2.1 Trace format ("shapes")

Records are chat pairs: a `<SCAN>`-wrapped code block in, a `<think>` reasoning block plus
structured fields out.

```
<think>
Hypothesis: `uid` is attacker-controlled and reaches `db.execute`, which
  interprets its argument as SQL — a possible CWE-89.
Trigger path: `uid` reaches `db.execute` unchanged via f-string concatenation.
Defensive check: nothing on this path validates, neutralizes, or parameterizes `uid`.
Since the trigger path is unguarded, an attacker can alter the query. Confirmed CWE-89.
</think>
status: confirmed
cwe: CWE-89
severity: HIGH
line: 3
trace: uid -> f-string -> q -> db.execute(q)
fix: Use a parameterized query, e.g. cur.execute("...WHERE id = %s", (uid,))
```

Shapes are trace *formats*, and there are now 25 in the training config. The important
distinction is single-file (`shape1*`) versus cross-file (`shape3*`) versus judgment
(`shape2` needs-context, `shape4` synthesis).

The `Hypothesis / Trigger path / Defensive check / conclusion` structure above is
deliberate (see §6.3): vulnerable and safe traces are **parallel**, differing only in the
outcome of the defensive check, so the reasoning cannot be produced without considering
whether a guard exists.

### 2.2 Corpus construction

The central insight is that **most trace conversion needs no model at all.** Three
grounded sources of truth replace a teacher:

| Mechanism | Ground truth | Used for |
|---|---|---|
| **Expert reasoning** | R2Vul ships human-written `positive`/`negative_reasoning` + CWE | ~18K traces, verbatim |
| **The patch oracle** | `diff(vuln, fixed)` marks exactly which lines were vulnerable | 32,008 CVE `.patch` files |
| **Static-analysis proof** | CodeQL SARIF `codeFlows` give a verified interprocedural taint path | 7,048 cross-file traces |

Where a model *was* used (`gpt-oss-20b`, local and free), it never decided labels — it was
given known-vulnerable code and asked to *explain* it, then every output was gated
(`cot/gates.py`) against the oracle and dropped on failure.

**Corpus today: 67,492 records across 25 shapes** — 39,035 vuln, 28,084 safe, 373
judgment-type. Languages: C, Python, JavaScript, PHP, Java, Go, TypeScript, React.

### 2.3 The quality gauntlet

Every record passes: structural/label consistency → contradiction removal (same code
labeled both ways) → normalized dedup → eval-leak removal → over-length removal.
`final_scan.py` is the single authoritative pass (18 checks) and currently reports
**18/18 PASS**.

This machinery exists because each check was added after a defect reached training. The
gauntlet is a record of past failures, not foresight.

### 2.4 The scanner ("car wash")

Model-as-scanner failed in practice: ~30s per function, and on a real, well-secured
application it produced **10 false positives and missed the one real vulnerability**.

The fix was architectural — let deterministic tools find, and the model only judge:

| Station | Component | Role |
|---|---|---|
| 1a | `flag.py` | Source→sink taint (Python AST, JS/TS regex) + 12 pattern detectors. Instant, CPU, no model. |
| 1b | `embed.py` / `retrieve.py` | Neural (MiniLM) and TF-IDF retrieval over known-CVE snippets — a recall net |
| 2 | `pipeline.py` | The 8B model triages **only flagged functions**: real or false positive? |
| 3 | `patches.py` | Deterministic per-CWE fix templates (14 CWEs) — the model never writes code |

Two-signal confidence: taint+model agreeing is HIGH, a single signal is REVIEW.

**Validated on a real application** (a FastAPI + React app, 124 functions): 1 confirmed
finding — a genuine CWE-209 error-leak that both the model alone and taint alone had
missed — and **zero confident false positives**, versus 10 false positives for the model
alone. Station 1 alone flagged 0 candidates on the clean files, instantly.

This is the part of the project that most exceeded expectations, and it is worth stating
plainly: **its success comes from constraining the model's role, not from the model's
quality.**

### 2.5 The guard-witness verifier (Station 2c)

The model's most persistent failure (§6.4) is the **completeness gap**: it declares a guard
sufficient without checking what the guard actually admits. It reads `if (!file.includes("/"))`
and calls the code safe, never testing that `..%2f..%2f` walks straight through.

Station 2c (`guard_witness.py`) is a deterministic answer that needs no model and no retrain.
For six guard classes it reimplements the guard's *actual logic* and runs it against a battery
of known bypass inputs. If the guard admits one, the code is a finding **even when the model
said safe** — and the report names the concrete bypass.

| Class | CWE | Insufficient shape it proves | Bypass witness |
|---|---|---|---|
| redirect | 601 | `startsWith("/") && !startsWith("//")` | `/\evil.com` |
| path | 22 | `'..'` substring / `!includes("/")` | `..%2f..%2f`, `/etc/passwd` |
| command | 78 | `escapeshellcmd` (argument injection) | `--output=/etc/passwd` |
| ssrf | 918 | literal-host denylist | `127.1`, `169.254.169.254` |
| proto | 1321 | key blocklist missing `constructor` | `constructor` |
| xss | 79 | `<script>`-strip / strip-`<>` in JS-string | `<img onerror>`, `";alert(1)//` |

The **contract is the load-bearing part**: the witness speaks *only when it can prove
insufficiency*. Every defensible design — a `new URL().origin` allowlist, `realpath`+prefix,
`escapeshellarg`, `shlex.quote`, a resolve-then-check SSRF guard, DOMPurify — returns UNKNOWN
and is never flagged. Building this required removing four separate false-positive shapes
(redirect-backslash, ssrf-hardcoded-URL, proto-sufficiency, path-absolute) that each accused
correct code; the discipline is that a false "this guard is broken" is worse than a miss.

**Verified end-to-end** with the GPU model stubbed to a worst-case SAFE verdict: on real test
files the ssrf/proto/xss witnesses promote a model-"safe" function to a finding, and a raw
no-guard sink is left to the taint layer. Wiring it required three integration fixes —
module-scope for guard data held in file-level constants, a proto/merge taint sink, and a JS
function-extractor that had been truncating nested sinks.

**What it is not.** The same battery was measured as a *training-data* generator and rejected:
it is a high-precision but narrow oracle (~6 modelled shapes), so harvesting witness-verified
pairs yields single digits at every real source — 8 distinct guards in the 63K-scan corpus,
3 verified completeness pairs across 18K real CVE fixes. Real insufficient guards are far more
varied than the shapes it models. Its value is the runtime layer above, not a data source.

---

## 3. Model iterations

Twelve versions, all preserved as `data/qwen_cot_vN_best`.

| Version | Change | Result | Lesson |
|---|---|---|---|
| v1–v4 | Format fixes, MLP LoRA targets | ~72% plateau | Data defects were teaching the wrong thing |
| v5 | +verified vuln only | Recall 64→80%, FPR 16→34% | Unbalanced data shifts the operating point, not skill |
| v6 | +verified vuln **and** safe | React recall 29→53% | Starved slices move; saturated ones do not |
| v7 | Doubled safe traces | FPR 30→9%, recall collapsed | Pure FPR↔FNR trade along one curve |
| v8 | Reweighted toward recall | Best balanced acc 70.7% | **Weights slide along a curve; only data quality lifts it** |
| R1-14B | Larger reasoning-distilled student | **0/42 parse; 52% on lenient re-score** | Capacity was never the bottleneck |
| v9 | Hardened, leak-free corpus | 73% / 19% FPR | Removing 1,147 leaked records made numbers real |
| v10 | +mined multi-language data (41K) | **78% / 19% / 77%** — production | Quality sources lift recall without costing FPR |
| v11 | +7,048 CodeQL cross-file (48K) | Cross-file "100%"; single-file **regressed** | See §5.2 — the 100% is unfalsifiable |
| v12 | +contrastive pairs, aux tasks (67K) | In training | Targets the guard-blindness root cause |

### 3.1 The R1-14B experiment (do not repeat)

DeepSeek-R1-Distill-Qwen-14B, QLoRA, ~27 hours. It emitted free-form prose and **never**
the required format: 0/42 parse success. Re-scored leniently by regex for a positive or
negative verdict, it reached **52% — chance**. Its distillation is math/logic-tuned, and a
light adapter cannot override that reflex. The bottleneck was data, and this cost 27 hours
to confirm something that could have been reasoned about first.

---

## 4. Evaluation — and why it was insufficient

This section is the most important in the report.

### 4.1 The instrument was underpowered

Every version decision above rests on a **42-record smoke test**. At n=42 the 95% Wilson
confidence interval on accuracy is roughly ±13 points:

| Model | Accuracy | 95% CI |
|---|---|---|
| v8 | 66% | 52–79 |
| v9 | 73% | 59–85 |
| v10 | 78% | 64–88 |
| v11 ep2 | 69% | 54–81 |

These intervals overlap almost entirely. **"v10 beat v9" and "v11 regressed" are not
statistically supported.** An FPR of 19% is 4 false positives out of 21 safe records.
Resolving a genuine 8-point gap needs ~406 records unpaired, or ~136 paired. There are
1,317 held-out records on disk; the smoke used 42 of them.

`eval_bench.py` now exists to fix this: a 369-record stratified sample, identical record
IDs across models, Wilson intervals, Matthews correlation, and an exact **McNemar paired
test** that reports how many discordant records would be needed when a gap is not
significant.

### 4.2 Some metrics could not be failed

`data/cot/eval/shape3_codeql.jsonl` contains 150 cross-file records, **all vulnerable**,
and the cross-file smoke scored "did the model say vuln." An always-say-vuln stub was
constructed as a control and scores **100% cross-file recall (40/40) — identical to
v11's headline result**, at a Matthews correlation of 0.000, i.e. no skill whatsoever.

A metric no model can fail carries no information. v11's "cross-file specialist" status
and the two-adapter routing plan rested on it.

### 4.3 External benchmark: PrimeVul

Home-grown evaluations can only be compared against themselves. **PrimeVul**
(arXiv:2403.18624) exists because the field's benchmarks were broken — Devign and BigVul
carry heavy label noise and duplication, inflating reported accuracy — and it ships a
**paired** split: the same function before and after its security fix. That is the v2p test
this project invented independently, curated by the authors.

Its paired metrics partition every pair: **P-C** (both sides correct — the real score),
**P-V** (both called vulnerable — flags everything), **P-B** (both called benign), **P-R**
(reversed). The paper's central result is that P-C is low and P-V high across the models
tested: they detect the *topic* of vulnerable code rather than reading the fix.

That is the same conclusion reached in §5 from entirely separate data — which makes this
project's central finding a **confirmation of published work**, not an isolated claim.

`bench_primevul.py` scores against 287 clean pairs (7× the 40-pair v2p smoke).

> **Contamination found and fixed.** `build_contrastive.py` globbed `*_paired.jsonl`, which
> also matched `primevul_test_paired.jsonl` — the benchmark's test split was being fed into
> training. The glob is now an explicit train+valid list, and because models up to v12 were
> trained before the fix, `bench_primevul.py` excludes contaminated pairs by content hash,
> recomputed against the live corpus on every run and always printed. This is exactly the
> class of defect §4.1 warns about: a leak that silently inflates a number nobody checks.

Not yet implemented: **VD-S** (false-negative rate at a fixed low false-positive rate), the
paper's other headline metric. It needs a confidence score rather than a binary verdict, so
it requires reading the vuln/safe token log-probability at inference. It is also the metric
a CI gate would actually be configured against.

### 4.4 Validation loss is not the metric

v11 achieved a *better* validation loss than v10 and lost on every single-file smoke
metric. Loss measures token likelihood over the training distribution; it does not measure
whether the model reaches the right verdict. **Behavioral smokes decide promotion.**

---

## 5. The central finding: topic discrimination, not guard discrimination

### 5.1 The evidence

A "vuln→patched" test (v2p) presents both sides of a real security fix — the vulnerable
code and the patched code — and asks for a verdict on each.

| Model | Recall | FPR on patched | **Pair accuracy** |
|---|---|---|---|
| v10 | 50% | 50% | 5% |
| v11 ep2 | 85% | 80% | 5% |
| v11 ep3 | 37% | 30% | 7% |

**No model reads the patch.** Pair accuracy is at chance for all three; they differ only
in how aggressively they flag. On a clean CWE-tagged subset, pair accuracy was **0/13 for
both v10 and v11.** The traces never evaluate the added guard — `canChangeRole()`,
ACL checks, `is_safe_url` — they re-narrate a generic source→sink and flag.

### 5.2 The root cause is in the data

Scanning the 48K corpus: of **48,405 distinct code snippets, exactly 1** appeared as both
vulnerable and safe. Vulnerable and safe records were drawn from **different code
populations**, so the model could minimize loss by learning *topic* — raw SQL, `exec`,
`innerHTML` mean vulnerable; config constructors mean safe — without ever learning to look
for a guard. Patched code retains every surface feature of vulnerable code and merely adds
a control, so it still "looks vulnerable."

Worse: an earlier dedup step **deleted** the 8 same-code-both-label records as
"contradictions." The exact signal needed was being removed as noise.

The same disease exists one level up: cross-file training data is **7,048 records, 100%
vulnerable**. The model was never given a reason to say "safe" about a cross-file flow.

### 5.3 Prompting cannot fix it

A three-way test (bare, checklist-guided v1, guided v2) on identical pairs:

| Mode | Recall | Patched FPR | Pair acc |
|---|---|---|---|
| Bare | 87% | 85% | 2% |
| Guided v1 | 20% | 10% | 12% |
| Guided v2 | 20% | 20% | 12% |

Pair accuracy plateaus at 12% regardless of framing, and the correct pairs under v1 and v2
overlap only 2 of 5 — i.e. mostly noise. Critically, of 32 missed vulnerabilities under
guidance, **32 confabulated a guard** ("it's parameterized", "validation present") on code
that had none. Asked to check for a control, the model invents whichever answer its topic
prior already preferred. It has no reliable internal representation of "is this flow
guarded?"

This is behavioral proof that the cause is the data, not the prompt.

### 5.4 The intervention (v12)

Train on **both sides of the same fix**: the vulnerable code with a vulnerable trace, and
the patched code with a safe trace that **quotes the specific guard line** the patch added.
Same code, opposite labels, difference isolated to the control.

Built: **7,100 contrastive pairs** (6,100 real + 1,000 capped synthetic), plus VulLLM-style
auxiliary tasks (3,500 localization, 3,500 fix-generation) forcing the model to locate and
repair rather than only classify.

**v12 is the test of this hypothesis. Tagged v2p pair accuracy against its 2% baseline is
the success metric.** As of writing, v12 is 79% through training.

---

## 6. Secondary findings

### 6.1 Synthetic data does not transfer
Synthetic React scored **100% on synthetic eval and 29% on real React**. Toy data teaches
toy patterns. All synthetic sources are now capped and down-weighted.

### 6.2 Reasoning theater is memorizable
21% of one corpus generation — 10,188 records — shared the identical templated sentence
"the fix adds a control the vulnerable code lacks." The model emitted it verbatim on
comment-only diffs that were not vulnerabilities at all. Boilerplate lets a model produce
reasoning-shaped text without reasoning; it is now diversified and scanned for.

### 6.3 Depth had to be authored, not generated
Machine-generated traces taught recognition, not understanding: generic "untrusted input"
sources, no mechanism, no attacker model, no impact. The fix was `cot/deep_trace.py` —
per-family security knowledge (role, mechanism, attacker, impact, why-the-guard-works)
authored once, above the generator's ceiling, then applied deterministically. Mechanism
coverage went from ~2% to 74–100% depending on source.

### 6.4 The guard-picker is the recurring weak point
Five distinct classes of defect have now been found in guard extraction across two
builders: imports quoted as controls; docstrings quoted as controls; string literals and
error messages quoted as controls; minified bundle lines quoted as controls; and guards
that were already present in the vulnerable code (making the contrast false). Every one was
found by **reading sample output**, never by the funnel counts, which looked healthy
throughout.

**Operational rule: after any change to a trace builder, read ten of its outputs.**

The runtime counterpart of this weakness — the model calling a *bypassable* guard sufficient —
is now addressed deterministically by the guard-witness verifier (§2.5), which the same rule
built: four false-positive shapes in the witness itself were caught only by reading its output
against real snippets, never by its own passing unit tests.

---

## 7. Current limitations

1. **The model is a strong classifier and a weak reasoner.** It has learned what
   vulnerable code looks like, not how to verify whether a flow is guarded. §5 is the
   evidence. Whether v12 changes this is an open question, not a settled one. For six guard
   classes this is now *side-stepped* rather than solved: the witness verifier (§2.5) checks
   completeness deterministically at runtime, so the model's misjudgement is overridden — but
   only for those classes, and the underlying reasoning weakness is unchanged.
2. **Real-world false positives remain the practical failure mode.** On real application
   code the model alone produced 10 false positives; only the surrounding deterministic
   pipeline made the system usable.
3. **Cross-file false-positive rate has never been measured.** 36 contrastive cross-file
   pairs now exist (21 held out) — the first eval capable of measuring it. Sample size is
   small and the confidence interval will be wide.
4. **Complex-judgment shapes are starved**: needs-context (80), cross-file confirm/dismiss
   (142), synthesis (225) — together under 1% of the corpus. These teach dismissal and
   uncertainty, the capabilities most needed for unfamiliar vulnerabilities.
5. **Language coverage is uneven.** TypeScript, React and Go are genuinely thin, limited by
   source availability rather than pipeline capability.
6. **Hardware wall.** Sustained training on the 16GB consumer GPU is ~2 days; runs must be
   planned to fit or to salvage at a checkpoint.

---

## 8. Reproduction

```bash
# 1 — corpus (deterministic, CPU, no API)
python reformat_r2vul_to_shape1.py          # expert reasoning
python convert_patches_wave3.py --langs ... # patch oracle + contracts
python build_contrastive.py                 # contrastive pairs
python build_auxiliary.py                   # localization + fix-generation
python final_scan.py                        # 18 integrity checks — must pass

# 2 — train (QLoRA, ~1 day for 2 epochs on 67K)
WAVE_PILOT_DIR=data/cot/pilot_clean WAVE_OUTPUT_DIR=data/qwen_cot_vN \
WAVE_BEST_DIR=data/qwen_cot_vN_best WAVE_EPOCHS=2 python -u train_qwen_cot.py

# 3 — evaluate (behavioral, not loss)
python eval_bench.py plan --n 400
python eval_bench.py run --label vN --adapter data/qwen_cot_vN_best
python eval_bench.py compare --a v10 --b vN     # paired McNemar
python smoke_v2p.py --tagged-only               # guard discrimination
python smoke_crossfile_pairs.py                 # cross-file recall AND FPR

# 4 — scan real code (Station 1 needs no model, no GPU)
python scanner/flag.py path/to/project
python scanner/pipeline.py path/to/project      # full car wash
```

**Checkpoint discipline:** never overwrite `data/qwen_cot_best`; preserve each version as
`data/qwen_cot_vN_best` and repoint production only after a behavioral win.

---

## 9. What this project actually demonstrates

Stated honestly, because the numbers alone would mislead:

- **A grounded corpus pipeline that needs no paid teacher.** Patch oracles, expert
  datasets, and static-analysis proofs replace API spend. This is the most reusable asset
  produced.
- **An architecture that makes an imperfect model useful.** Constraining the model to
  triage flagged candidates converted a 10-false-positive liability into a scanner with
  zero confident false positives on real code.
- **A catalog of negative results with evidence.** Capacity is not the bottleneck; weights
  slide along a fixed curve; synthetic data does not transfer; unfalsifiable metrics
  manufacture false confidence; and a model trained on disjoint vulnerable/safe
  populations learns topic rather than mechanism.

The last of these is the finding worth publishing. It is not specific to this model or
corpus: **any vulnerability dataset whose safe and vulnerable examples come from different
code populations will train a topic classifier and score well on an evaluation drawn from
the same populations.** The failure only becomes visible when the same code is presented
both before and after its fix.

---

*Companion documents: `README.md` (narrative log, v1–v9) · `DATA_INVENTORY.md` (datasets on
disk) · `scanner/README.md` (scanner usage) · `verified_regen_design.md` (oracle/gates
design).*
