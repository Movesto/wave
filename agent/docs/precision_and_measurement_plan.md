# Precision & Measurement Plan

Status: **Shift 1 (grounded-confirm bar) — BUILDING.** Shifts 2–3 designed, not built.
Date: 2026-09-20. Branch: `corpus-rebuild-and-dpo`.

## Why this doc exists

After ~10 real-repo scans this session, every correctness fix landed in **one seam**: the
trust/reachability classifier (fastapi `@app.command()`→false-remote; §10.1 name-collision false
chains; CLI-script and desktop blind spots). Each fix was another string-matching heuristic. That
pattern is the signal — not a broken engine, but a design tension worth naming.

### The engine is sound

The prove stage does its job: when it says an effect happened (rmtree ran with `../`, a path escaped
root) it **witnessed** that with a tool. We have ~zero "wave hallucinated a vuln that isn't in the
code." Do not rebuild the loop.

### The actual flaw — one sentence

> We **ground the effect dynamically** (run it, watch the sink fire) but **infer reachability
> statically/heuristically** — yet a `confirmed` verdict claims *both*.

A `confirmed` today = "effect witnessed AND reachability heuristic passed." Only the first half is
grounded. Every false confirm this session was a **reachability guess wearing a `confirmed` badge**.
The grounding rule ("confirmed must cite a tool-witnessed effect") is honored for the effect and
silently violated for reachability.

### The second flaw — we can't measure ourselves

~10 repos judged by eye, on code we don't own, with no ground truth. The only reason the fastapi
false-confirm was caught is a hand-read. We cannot tell whether a gate change *regressed* something —
the 223 unit tests are synthetic fixtures, not real repos. "We keep seeing issues" is partly *"we have
no baseline to know if we're improving."*

## The three shifts (priority order)

### Shift 1 — grounded-confirm bar (this change, cheap, high-impact)

**Reserve `confirmed` for witnessed-effect AND a *high-confidence* path to a *remote* entry.** Anything
softer → `anomalous_state` (needs-review). The finding is never dropped — only the *label* changes to
match what we actually proved.

Operational definition of "grounded enough" for a `confirmed`:
- effect witnessed (already required), AND
- reachable to an entry whose trust tier is `remote` (not `local`/CLI — already gated), AND
- the reach path is **high-confidence** (does not lean on an ambiguous name-based edge).

The gate already computes this `confidence` and already enforces `conf == "high"` — **but only for
intrinsic sinks** (deser/eval/ssti). Shift 1 generalizes that bar to **all** classes. A witnessed cmd
/sqli/path confirm reachable only through an ambiguous chain is now review, not confirmed — exactly the
false-confirm class.

Also: **stamp the grounding on the record** (`reach_conf`, `reach_trust`) so a reader sees *"confirmed
(effect witnessed; reachability: high-confidence remote path)"* vs a review item, instead of a bare
badge. Honesty about which half is grounded.

What Shift 1 does **not** fix: an entry *mis*classification (recognized as the wrong tier, e.g. the
fastapi decorator bug) on an otherwise-clean path. That needs better entry heuristics (done per-case)
or value taint (Shift 3). Shift 1 is complementary — it removes the *shaky-chain* confirms.

Refinement deferred: the confidence signal (`_ambiguous_names`) counts a name as ambiguous by raw
multi-definition, ignoring that the binding-aware walk may have resolved it same-file/self. Making
confidence binding-aware (only genuinely weak — co-located member — edges count) would protect recall
further. Deferred to avoid churning the suite in the same change; tracked here.

### Shift 2 — a ground-truth regression harness (highest long-term leverage)

A small fixture set of **real repos** with *known* vulns AND known safe-context sinks (docs/examples/
CLI tooling), run end-to-end, emitting a precision/recall number. Then every gate change is *measured*,
not eyeballed. Turns "we keep seeing issues" into "precision 0.71 → 0.83." Design:
- `bench/` manifest: `{repo, ref, expected: [{file, line, class, verdict}], known_safe: [...]}`.
- runner scans each at pinned ref, diffs verdicts vs expected → P/R + a confusion table.
- run on every gate/reachability change before merge.

### Shift 3 — value-level interprocedural taint (§10.4, the deep fix, expensive)

Track whether the sink's argument actually derives from an untrusted entry's input, replacing
"does the enclosing function *look* untrusted-facing." The principled replacement for the heuristic
gate. Real build, own imprecision risk → **do not start blind**; start only after Shift 2 can measure
it.

## Order

Shift 1 now (stops the bleeding) → Shift 2 (lets us see) → Shift 3 (endgame, measured).
