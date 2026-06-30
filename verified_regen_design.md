# Verified Regeneration — Design

## Why
The model ceilings at ~72% / 22% FPR / 33% FNR. Root cause (confirmed by reading ~25 records and the FP failure cases): the **vuln** CoT traces are only ~55% solid because the local teacher (gpt-oss-20b) *fakes* reasoning — it hedges ("this *could* be vulnerable *if* the value were user input"), hallucinates sinks on incomplete code, and is never checked against an oracle. We've been hand-cleaning the fakes one defect at a time (menu-echo, speculative, fragments). That treadmill is the real problem.

**Trellis insight:** a proof is rigorous only when every step is checkable; agents drive *progress*, never *soundness*. Apply that here — **verify each regenerated vuln trace against an oracle at generation time, and DROP what can't be verified**, instead of keeping every trace and cleaning later.

The key disanalogy: security has no Lean kernel ("is this vulnerable?" is undecidable). But for **fix-pair data we have a strong partial oracle: the patch itself.** The diff between the vulnerable and fixed code tells us *exactly which lines were changed to remove the vuln* — i.e., where the vulnerability is. A correct trace must point there.

## The oracle
For each fix-pair record `(vuln_code, fixed_code, cwe?)`:
- `diff(vuln_code, fixed_code)` → **changed line indices** + **changed identifiers** = the vulnerability's location (`sink_region`).
- Sources available: `data/downloads/{CVEfixes, morefixes-patches, cve-fix-pairs, vulnerability-fix-dataset}`, R2Vul (`commit_URL` + positive/negative reasoning), and morefixes "Fixed code:" blocks already parsed in `shape1._from_morefixes`.
- **Fallback** when no usable diff (e.g., some R2Vul): run a static analyzer (Bandit for Python, Semgrep for JS/TS) on `vuln_code` → it returns `(line, cwe)` for findings → use that as `sink_region`. Weaker but catches gross hallucinations.

## The gates (independent, all must pass — Trellis: substantiveness / correspondence / soundness)
Run on the teacher's generated trace for a vuln record:

1. **Correspondence** — every identifier/expression the trace names as source or sink must literally appear in `vuln_code`. (Kills fragment hallucinations like the invented `axios.get`.)
2. **Localization (the core gate)** — the trace's claimed sink (and its `line:` field) must fall within or adjacent (±2 lines) to `sink_region`. If the teacher points somewhere the patch didn't touch, it found a phantom → reject.
3. **CWE consistency** — when ground-truth `cwe_id` is known (R2Vul/CVEfixes), the trace's CWE must match (family-level). Mismatch → reject or flag.
4. **Substantiveness** — reject hedged/speculative traces: must name a concrete source AND concrete sink AND a connecting flow; reject if it leans on `could be / if it were / presumably / if rendered / not shown`. No hypothetical vulns.

## Generation loop (blind-then-guided, with hard drop)
```
for record in vuln_fixpairs:
    region = oracle(vuln_code, fixed_code, cwe)        # patch diff or analyzer
    # 1) BLIND attempt — honest signal of trace quality
    trace = teacher(vuln_code)                          # no location hint
    if all_gates_pass(trace, region): keep; continue
    # 2) GUIDED retry — anchor to the real location, up to K tries
    for _ in range(K):
        trace = teacher(vuln_code, hint=region)         # "the vuln is at/near lines ..."
        if all_gates_pass(trace, region): keep; break
    else:
        DROP(record, reason=failed_gate)                # <-- the thing we never did before
```
- **Blind-pass** records are highest confidence (teacher found it unaided + it matches the patch).
- **Guided-pass** records are still verified (gates run on the final trace regardless of hint).
- **Dropped** records are logged with the failing gate — yield + rejection-reason breakdown is a first-class output.

## Teacher
Pair the gates with a **stronger teacher** (Claude / GPT-4-class via API — `cot/client.py` already supports `WAVE_GENERATOR_BACKEND=anthropic`). Gates + strong teacher together are the ceiling-breaker; gates also make the API spend efficient (only regenerate failing slices, only keep passing traces). Estimated cost is bounded — only the weak vuln slices, ~a few thousand calls.

## Scope (LOCKED — from full eval `cot_v4`, 2026-06-16, ~825 records)
Measured weak slices, in priority order:
| target | metric | why |
|--------|--------|-----|
| **real React vuln** (shape1_react) | recall **29%** | worst slice; least real data |
| **TS vuln** (shape1_ts) | recall **40%** | misses 60% |
| **safe TS/React** (shape1_ts_safe / react_safe) | FPR **25–28%** | over-flags ~1 in 4 |
| **Python/JS vuln** (shape1, R2Vul) | recall **64%** | biggest volume → biggest absolute lift |
| **crypto/auth/missing-control CWEs** | ~0% recall (327, 338, 347, 287, 306, 601) | model only catches injection well |

**KEY EVAL FINDING:** synthetic React = **100% recall** but real React = **29%** → synthetic does NOT transfer to real-world vulns. So:
- **Regenerate (verified):** real fix-pair vuln data for React, TS, and the R2Vul py/js set; deliberately over-sample crypto/auth/missing-control CWEs.
- **Do NOT add more synthetic** — it inflates eval without buying real skill. Consider down-weighting `shape_react_syn` in the next train.
- **Leave untouched:** the `*_safe` generators (~90% good) and shape2/shape3/shape4.
- The patch-localization oracle is strongest exactly here (real fix-pairs from morefixes/CVEfixes/R2Vul have diffs).

## Implementation (fits the existing `cot/` package)
- `cot/oracle.py` — `locate_vuln(vuln_code, fixed_code=None, cwe=None) -> region` (diff first, analyzer fallback).
- `cot/gates.py` — `correspondence()`, `localization()`, `cwe_consistency()`, `substantiveness()`; `all_gates_pass()`.
- `cot/shapes/shape1_verified.py` — the blind-then-guided loop above; emits shape1-format records + a `rejections.jsonl` log.
- Reuse `cot/runner.py`, `cot/client.py` (anthropic), checkpointing.

## Success criteria
1. Yield + rejection-reason report (expect ~40-55% rejection on the weak slices — that's the point).
2. Retrain on the verified vuln set → re-run the full eval → **FNR drops** without FPR regressing. That is the proof the approach worked.

## Honest risks
- Patch-localization isn't perfect — multi-purpose patches, or fixes that aren't at the sink. Mitigated by the ±2-line tolerance and the analyzer fallback; gross hallucinations still get caught.
- Lower yield = fewer vuln records. Acceptable: fewer verified-correct traces beat many speculative ones (the whole thesis).
- It's real engineering. But it *ends the manual-cleanup treadmill* — generate once, gate hard, train. That is the actual fix for "weeks of fixing nonsense."
