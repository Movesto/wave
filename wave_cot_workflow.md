# Wave Scanner — CoT Data & Eval Workflow

This file holds the two Claude Code prompts that drive the data and evaluation
side of the reasoning scanner, plus the workflow that ties them together.

The model plan: a LoRA-fine-tuned **Qwen3-8B (thinking mode)** acts as the
reasoning core. A dumb agent does file I/O (walk, chunk, fetch); the model does
all detection, cross-file trace reasoning, and whole-project synthesis. To make
the model *reason* instead of pattern-match, the terse `code -> verdict` pairs
must be converted into chain-of-thought (CoT) data in four shapes.

---

## The iteration loop

```
convert data  ->  train LoRA  ->  run eval harness  ->  read per-CWE/language slices
     ^                                                            |
     |________  add a few hundred targeted examples  <____________|
                 at the weakest slice, then retrain & COMPARE runs
```

The eval harness is what makes this a loop instead of a guess. You never decide
"it got better" by vibe — you compare run files.

---

## Prerequisites

- `data\sft\` populated with the existing terse pairs (the 137k vuln->fix pile).
- `ANTHROPIC_API_KEY` set — both the trace generator and the eval judge use the API.
- Qwen3-8B base downloadable, plus your LoRA training script (QLoRA 4-bit on 16 GB).
- A Python env in the repo.

---

## The four data shapes (quick reference)

1. **Local scan with trace** — single file in, `<think>` source->sink (or why safe), then verdict. Includes safe cases. Trains the per-file scan.
2. **Request missing context** — the verdict depends on unseen imported code; correct behavior is to emit `needs_context` + `open_refs` instead of guessing. Trains the anti-hallucination "ask" behavior.
3. **Cross-file completion** — caller + fetched definition; complete the trace across files. ~50/50 confirm/dismiss, ~15% multi-hop. Trains cross-file taint.
4. **Whole-project synthesis** — a set of findings + project map in; dedupe, rank, surface systemic issues. Trains the holistic report.

**Targets for a solid v1 (verified examples):** shape1 ~3000 (>=30% safe),
shape2 ~500, shape3 ~1500, shape4 ~500. Plus 150–300 per shape held out into
`data\cot\eval\`, never trained on. Quality and CWE/language coverage matter far
more than raw count — past ~10k, more does not help and can wash out the base.

---

## Step 1 — Convert (paste into Claude Code at repo root)

```text
You're working at my security-scanner repo root (Windows: C:\Users\pscad\Documents\wave\).
I'm fine-tuning a reasoning model (Qwen3-8B) to scan code for vulnerabilities, and I need to
convert my terse training pairs into chain-of-thought (CoT) data in FOUR specific shapes.
Build a generation + verification pipeline, run a small pilot, and STOP for my review before
scaling. Plan the work, then execute step by step.

## Context
My SFT pairs are in data\sft\ as JSONL like:
{"messages":[{"role":"user","content":"<SCAN>\n<code>\n</SCAN>"},
             {"role":"assistant","content":"CWE-XX: ...\nFixed code:\n...\nExplanation: ..."}]}
Some sources carry a ground-truth label (e.g. cvefixes has a safe/vulnerable field). The pairs
are terse — they jump code -> verdict with no reasoning. I'm training a REASONING model, so I
need traces that reason their way to the verdict; terse targets destroy reasoning.

## Step 0 — INVENTORY FIRST (before writing any generation code)
List every file in data\sft\, read real samples, detect each schema (fields, whether it has a
ground-truth label, language, vuln vs safe), and print a summary: source | count | has_label |
languages | vuln/safe mix. Don't assume formats. Report back, then continue.

## Pipeline requirements
Write a RESUMABLE Python pipeline (checkpoint to disk; a crash must not lose progress) that uses
the Anthropic API as the trace GENERATOR.
- Put GENERATOR_MODEL at the top, configurable. Pick a current strong Claude model (check
  docs.claude.com for the current model string — don't hardcode a guess).
- Low temperature for consistency. Batch with rate-limit + retry handling.
- Estimate and print token/cost BEFORE any full run.
- For each example: the generator is GIVEN the ground truth (known CWE+fix, or the safe label)
  and must write a trace that reasons TOWARD it as if discovering it — never just restating the
  label. Then a VERIFICATION step parses the trace's emitted final verdict and checks it against
  the ground truth. If they don't match, DISCARD and log. Report discard rate per shape.
- Output JSONL in my training format: messages = [user with the task tag, assistant with a
  <think>...</think> reasoning block FOLLOWED BY the structured verdict]. One file per shape in
  data\cot\.

## The four shapes
SHAPE 1 — local scan with trace (convert directly from single-file pairs; INCLUDE safe cases that
reason to "no vuln"). Assistant = <think> trace from source->sink (or why it's safe) </think>
then: status (confirmed|safe) | CWE | severity | line | trace | fix.

SHAPE 2 — request missing context (CONSTRUCT: take a vuln pair whose sink is a function call,
rewrite so that function is imported from another file and NOT shown; correct behavior is to ask,
not guess). Assistant = <think> input is tainted, flows into <fn> imported from <file>, verdict
depends on code I can't see, guessing would be wrong </think> then: status: needs_context |
open_refs: ["<fn> (<file>)"] | partial_trace. Verify status==needs_context and the right symbol.

SHAPE 3 — cross-file completion (CONSTRUCT: pair the shape-2 caller with the actual definition).
Make ~50% confirm (definition is unsafe) and ~50% dismiss (definition sanitizes). Include ~15%
multi-hop (the definition calls something new -> emit a NEW open_ref). Assistant = <think>
continue the trace given the now-visible code </think> then final verdict spanning both files.

SHAPE 4 — whole-project synthesis (CONSTRUCT: sample N=4-8 findings from generated shape-1/3
outputs into a finding-set + a short project map). Assistant = <think> cluster duplicates by root
cause, rank by exploitability, infer systemic issues </think> then: executive summary -> ranked
findings -> systemic observations.

## Targets, coverage, split
- shape1 ~3000 (>=30% safe), shape2 ~500, shape3 ~1500, shape4 ~500.
- Spread shape1/3 across CWE classes AND languages (Python/JS/TS/React). Cap any single CWE at
  ~20% of the set so SQLi doesn't dominate. Report the CWE/language distribution.
- Dedup near-identical code.
- Hold out a random 150-300 per shape into data\cot\eval\ that NEVER enters training.

## Pilot, then stop
Generate ~40 per shape into data\cot\pilot\, print: discard rate per shape, CWE/language spread,
and a projected cost+time for the full targets. Then STOP and wait for me to review quality before
scaling to the full counts.
```

**When you review the pilot:** check (a) the discard rate is sane, and (b) the
kept traces are real reasoning, not reasoning-theater that just restates the label.

---

## Step 2 — Train

Train the Qwen3-8B LoRA on `data\cot\` with your existing script, with three
guardrails so you don't wash out the base's reasoning:

- Verify `target_modules` actually attach (Qwen3-8B is a vanilla transformer, so
  standard `q/k/v/o_proj` + `gate/up/down_proj` is correct — run `print(model)`
  once to confirm, unlike the Qwen3.5 DeltaNet line).
- Conservative learning rate, few epochs — you're nudging a strong model, not
  retraining a blank one.
- QLoRA 4-bit to fit 8B on 16 GB.

---

## Step 3 — Evaluate (paste into Claude Code at repo root)

```text
You're working at my security-scanner repo root (Windows: C:\Users\pscad\Documents\wave\).
I have a LoRA-fine-tuned Qwen3-8B (thinking mode) vulnerability scanner and a held-out eval set
in data\cot\eval\ (four shapes, each example carries ground truth). Build a REPEATABLE eval
harness that scores a checkpoint and lets me compare runs across retrains, so I can tell whether
iteration N+1 actually beat N — and where it's weak. Plan, then execute.

## Why this exists
My #1 pain is false positives on safe code. My bet is on reasoning. So the harness must measure
false-positive rate, recall, the "ask-don't-guess" behavior, cross-file correctness, and whether
the reasoning actually supports the verdict. And it must be COMPARABLE across runs: fixed eval
set, fixed seed, pinned judge model+prompt — so a metric delta is a real change, not noise.

## Inference config (match production)
- Load base Qwen3-8B + LoRA adapter; make BASE and ADAPTER_PATH configurable at the top.
- Thinking mode ON; use the same generation settings (thinking budget, temperature, stop tokens)
  I'll use in deployment. Low/zero temperature + fixed seed for reproducibility.
- Serve efficiently (vLLM if available, else transformers). Resumable; checkpoint predictions.
- Save every prediction (input, full <think>, parsed verdict, ground truth, pass/fail) to disk so
  I can eyeball failures.

## Scoring — two layers
LAYER 1, deterministic (the primary signal — objective, fast, no judge):
Parse each shape's structured output (formats must match the conversion pipeline's schemas) and
compare to ground truth.
- SHAPE 1 (local scan): treat as classification vuln-vs-safe.
    * FALSE-POSITIVE RATE on the safe subset  <- headline metric, print first
    * recall on the vuln subset (false-negative rate)
    * precision, F1
    * CWE accuracy: when it flags, is the CWE class correct?
- SHAPE 2 (needs-context): % that correctly emit needs_context AND name the right symbol vs
    % that HALLUCINATED a verdict instead (the failure mode). Call this the ask-don't-guess rate.
- SHAPE 3 (cross-file): confirm/dismiss accuracy (precision/recall on each), and on multi-hop
    cases, did it correctly emit a new open_ref instead of closing early?
LAYER 2, LLM-judge (Claude API, for the fuzzy parts — pin JUDGE_MODEL + prompt, temp 0):
- fix quality (1-5): does the fix actually remediate, in the right language?
- reasoning faithfulness (1-5): does the <think> logically lead to the stated verdict, or is it
    reasoning-theater that just restates the label?
- SHAPE 4 synthesis rubric (1-5 each): correct dedup/clustering, sensible severity ranking,
    real systemic insight, NO hallucinated findings.
Treat judge scores as trend indicators; deterministic metrics are the source of truth.

## Slicing (this is how I decide what data to add next)
Break every Layer-1 metric down by CWE class and by language (Python/JS/TS/React). Print a table
so I can see e.g. "SQLi recall 0.95 but SSRF 0.40" or "JS FPR double Python's." That tells me
exactly where the next few hundred training examples should go.

## Reporting + comparison (the point of the harness)
- Write each run to data\eval_runs\<timestamp>_<label>.json with: model, adapter path, date, git
  commit if available, all metrics, all slices, and run config.
- Print a top-line dashboard: FPR(safe), recall, ask-don't-guess rate, cross-file accuracy,
  mean faithfulness.
- Add a COMPARE mode: given two run files, print metric deltas side by side and FLAG REGRESSIONS
  loudly (FPR up, recall down, faithfulness down, ask-don't-guess down). Improving one metric while
  silently regressing another is the trap — surface it.

## Sanity run first
Run on a small slice (~20 per shape) end to end, confirm the parsers, judge calls, slicing, and
report all work and the numbers look plausible. Then STOP and show me before running the full set.
```

---

## Notes & gotchas

- **Verification gate is non-negotiable.** An unverified trace that's confident
  and wrong is worse than no data — it teaches reasoning-theater.
- **FPR on safe code is the headline.** It's the original pain; watch it every run.
- **Pin the judge model + prompt + seed.** Otherwise run-to-run "improvements"
  are just judge noise.
- **Pilot / sanity run first, always.** Both pipelines hit the API thousands of
  times at full scale — that costs money. Eyeball the small batch first.
- **Per-CWE / per-language slices drive the next batch.** Don't add data blindly;
  add it where the slice table says you're weak.
- **Coverage beats count.** A well-spread 5–7k verified set beats 50k of one CWE.
