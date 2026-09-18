# Stage 5 — Review & Reconcile  *(PLAN — not built; review before implementing)*

*Author: session 2026-09-17. Supersedes nothing; extends `wave_architecture_plan.md` (four stages → five).
Fold into that doc's §6/§7 after review.*

## 1. The problem this solves

Today every finding is judged **in isolation**. Stage 3 (`prove.py`) investigates one candidate at a time
with **no memory of the others**, and `report.py` merely **collates** the per-finding verdicts. There is no
final pass that reads the whole set the way a pentester re-reads a report before submitting it. Three concrete
failures follow from that:

1. **Contradictions survive.** On netdata, line `netdata-updater.sh:1508` appeared **twice** — once as
   `anomalous_state` (a witnessed effect) and once as `not_exploitable` (reasoned safe) — because the detector
   emitted two candidates for the same line under different class labels (`cmd` vs `other`), each was proved
   independently, and the model's per-finding non-determinism reached opposite conclusions. Nothing noticed
   they were the same line.
2. **No cross-file reasoning.** If the *same* code pattern is confirmed a vuln in file A but dismissed in
   file B, nothing asks *why the two differ*. That difference is almost always **reachability/context** — and
   surfacing it catches **both** a false positive in A **and** a missed vuln in B.
3. **Duplicate noise.** The same sink surfaced under two class labels or two slightly different sink strings
   is counted as two findings.

This is a **harness gap, not a model gap** — the model reasons fine per finding; nothing gives it (or a
deterministic pass) the whole-report view.

## 2. Goals / non-goals

**Goals**
- Deduplicate findings by code location.
- Detect and reconcile **contradictions** (same/adjacent code, different verdicts).
- Add **cross-file look-alike** reasoning: cluster structurally-similar sinks, explain divergent verdicts,
  and flag likely **missed vulns** (recall) as well as likely **false positives** (precision).
- Produce one **consistent, deduped** finding set + a transparent reconciliation log.

**Non-goals**
- Not a re-detection stage: it works on the findings already produced (plus a bounded look-alike scan).
- Not cross-*run* memory (the review rejected that as folklore); this is **within-run** consistency only.
- Not a place to re-tune the class taxonomy or reachability gates — it consumes their output.

## 3. The one rule that keeps it honest (the guardrail)

Reconciliation is where bias could sneak back in. The whole verification design is **decorrelated on
purpose** — the clean-room falsifier (Stage 2) and the fresh-auditor (`audit.py`) share no context so one
confident narrative can't bias everything. A "read it all and tidy up" pass reintroduces exactly that risk:
a confident model rationalizing away a real, tool-witnessed finding to make the report internally neat.

So the invariant is absolute:

> **Reconciliation may merge, flag, re-prioritize, annotate, and trigger re-investigation — but it may NEVER
> overturn a TOOL-WITNESSED verdict with reasoning. A witnessed result can only be changed by another TOOL
> observation (a re-investigation that fails to reproduce). Nothing is ever deleted; a merge preserves the
> union of evidence, and a downgrade stays visible in the report.**

Concretely:
- **Witnessed verdicts** — `confirmed` backed by an observed effect, or a rung1 canary `proven` — are
  *immutable to prose*. Reconcile can only (a) leave them, or (b) enqueue a **re-investigation** if a
  look-alike casts doubt; the verdict changes only if the tool re-run changes it.
- **Reasoned verdicts** — `believed`, `not_exploitable` — are the model's to reconcile, **with the safe
  direction preserved**: on any doubt a finding stays a visible `believed` lead; it is never silently upgraded
  to `not_exploitable`, and never dropped.
- **Merges never hide a witness.** If any member of a merged group was witnessed (even a forced-input
  `anomalous_state`), the merged finding keeps at least `anomalous_state` — carrying the reasoning as context.

This makes the pass safe *by construction*: its worst case is over-conservative noise (a real non-issue kept
as needs-review), never a buried vuln.

## 4. Architecture — deterministic first, model second

Two phases. The deterministic phase is free and safe and does most of the work; the model phase is bounded,
per-cluster, and evidence-anchored (so it can't drift into whole-report rationalization).

### 4a. Deterministic reconciliation (no model)

1. **Location resolution + dedup.** Resolve every finding to its enclosing unit via `codemap`
   (`_enclosing` → file + function span). Group by `(file, enclosing-unit)` — and, when there's no unit
   (shell scripts), by `(file, line ± small window)`. Findings in the same group that share a class collapse
   to one (union their evidence, keep the most-attention verdict per §5).
2. **Contradiction detection.** Any location-group holding **more than one distinct verdict** is a
   contradiction → queued for the model phase (or resolved deterministically per §5 when the rule is
   unambiguous, e.g. witnessed vs reasoned → keep witnessed).
3. **Look-alike clustering (cross-file).** Compute a structural **signature** per finding — normalized sink
   pattern + class + (optionally) a normalized slice shape — and cluster across files. A cluster whose members
   hold **divergent verdicts** is queued for the model phase. (Signature = sink text with identifiers/literals
   masked; cheap and deterministic.)

### 4b. Model reconciliation (bounded, per-cluster, evidence-anchored)

For each queued contradiction / divergent cluster (capped at top-N by severity), one focused reconcile call:
- **Input:** only the conflicting findings in that cluster + each one's **evidence** (what was actually
  observed / tool-witnessed) + the relevant slices. *Not* the whole report — this keeps it from anchoring on a
  global narrative.
- **Task:** explain the difference (name the reachability/context reason one is exploitable and the other
  isn't), OR declare one wrong.
- **Allowed outputs (only these):**
  1. `reconcile-reasoned` — pick/merge among **reasoned** verdicts with a cited reason (safe direction holds).
  2. `reinvestigate` — enqueue a finding for one more Stage-3 pass (the *only* way to change a witnessed
     verdict, or to chase a suspected missed vuln).
  3. `annotate` — attach a "why these differ" note to the cluster; verdicts unchanged.
  It **cannot** emit "downgrade this confirmed" as a prose action.

### 4c. Re-investigation worklist

Findings marked `reinvestigate` are run once more through `prove` (same oracle, fresh marker). Two sources:
- **Settle a contradiction** a slice can't decide (needs a tool run).
- **Recall:** a look-alike of a `confirmed`/`anomalous_state` finding that was dismissed → re-check it as a
  possible missed vuln. Bounded to top-N to cap cost.

## 5. Verdict-change rules (the precedence table)

Attention precedence (highest first): `confirmed` > `anomalous_state` > `blocked` > `believed` >
`not_exploitable` > `refuted`.

| Group contains… | Deterministic merge result | Model may… |
|---|---|---|
| a witnessed `confirmed` + anything | stays `confirmed` | only `reinvestigate` a conflicting look-alike; never downgrade by prose |
| `anomalous_state` (incl. forced-input) + `not_exploitable`/`believed` | stays `anomalous_state`, annotated with the reasoning (the 1508 case) | annotate; or `reinvestigate` to settle |
| only reasoned (`believed` / `not_exploitable`) that disagree | keep the **more conservative** (`believed`) pending model | `reconcile-reasoned` with a cited reason; safe-direction default = `believed` |
| exact duplicates (same verdict) | collapse to one, union evidence | — |
| look-alike cluster, mixed verdicts across files | no auto-change | `annotate` the difference; `reinvestigate` the dismissed twin (recall) |

Nothing is deleted; every merge/flag is logged with its reason.

## 6. Pipeline placement, artifacts, CLI

- **Placement:** runs **after Stage 3 (prove), before Stage 4 (patch)** so patch acts on the reconciled set
  (a finding reconcile downgrades won't be needlessly patched, and a `reinvestigate` result is settled first).
  It is the final *analysis* step before the report. (Named "Stage 5" per the ask; it sits between prove and
  patch in execution order — patch stays the last mutating stage.)
- **Inputs:** `wave_findings.jsonl` (+ `casefile.json`), `codemap`/`repomap` (enclosing units, signatures).
- **Outputs:**
  - reconciled `wave_findings.jsonl` (deduped, merged, verdicts changed only within §3/§5),
  - `wave_reconcile.jsonl` — every action (merge/flag/annotate/reinvestigate) + reason (audit trail),
  - casefile `reconciliation` records,
  - a **Reconciliation** section in the report (what was merged, which contradictions were resolved and how,
    which look-alikes were re-checked).
- **CLI:** `wave reconcile <target>` standalone; folded into `wave all` between prove and patch. Resumable and
  keyed like the other stages.

## 7. Cost & safety bounds

- Deterministic phase: free (no model).
- Model phase: runs **only** on detected contradictions + top-N divergent look-alike clusters — cost scales
  with *conflicts*, not total findings. Re-investigations capped at top-N.
- Bias bound: per-cluster focused calls with evidence, never a whole-report tidy-up; witnessed verdicts are
  prose-immutable.

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Model rationalizes away a real finding | §3 invariant: witnessed verdicts prose-immutable; only a tool re-run changes them |
| Over-merging distinct bugs at one location | Merge only within the same class + same enclosing unit; different classes stay separate findings |
| Look-alike signature too loose → wrong merges | Signatures cluster for *review*, never auto-merge across files; only annotate / reinvestigate |
| Cost blowup on big repos | Model + re-investigation both top-N capped; deterministic phase does the bulk |
| Safe non-issue kept as needs-review (false attention) | Accepted — the safe failure direction; annotated so a human dismisses it in seconds |

## 9. Build order (phased, each independently shippable + tested)

- **Phase 1 — deterministic (no model):** location dedup + contradiction detection + the precedence-merge
  rules + the reconciliation log + report section. This alone fixes the netdata 1508 contradiction and the
  duplicate noise. Fully unit-testable, no GPU/model.
- **Phase 2 — model reconciliation:** the bounded per-cluster reconcile call (reconcile-reasoned / annotate),
  under the §3 invariant.
- **Phase 3 — look-alike recall:** cross-file signature clustering + `reinvestigate` of dismissed twins.
  (Optional deeper phase: scan the repomap for structural twins that were never even pinned — bigger, later.)

## 10. Testing

- Phase 1: deterministic tests — same-line-two-verdicts → merged to the higher-attention verdict with note;
  witnessed + reasoned → witnessed kept; exact dup → collapsed; no false merges across different classes.
- Phase 2/3: scripted fake reconcile-model — verify it cannot downgrade a `confirmed` (only `reinvestigate`),
  the safe-direction default on reasoned disagreements, and that nothing is deleted.
- Integration: re-run netdata → the two 1508 entries become one; re-run a repo with a known cross-file twin.

## 11. Open questions (for review)

1. **1508-style resolution:** keep the merged finding at `anomalous_state` (conservative, annotated) or let
   the model argue it to `not_exploitable`? Plan's default = keep `anomalous_state` (never hide a witness).
2. **Look-alike depth:** only cluster findings already surfaced (cheap), or also scan the repomap for
   never-pinned twins (deeper recall, more cost)? Plan defers the deeper scan to Phase 3+.
3. **Auditor overlap:** should Stage 5 reuse `audit.py`'s fresh-auditor for the reconcile call, or a distinct
   prompt? (They serve different jobs: audit = per-confirmed corroboration; reconcile = cross-finding.)
