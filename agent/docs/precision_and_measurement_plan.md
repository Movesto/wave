# Precision & Measurement Plan — closing the SAST reachability gap

Status: **Shift 1 (grounded-confirm bar) BUILT. Shift A (prove Half B) BUILDING.**
Date: 2026-09-21. Branch: `corpus-rebuild-and-dpo`.

## The real problem, stated plainly

A vulnerability is a hypothesis in **two halves**:
- **Half A** — *if bad input reaches this function, the sink does damage.*
- **Half B** — *an attacker can actually get bad input to that function.*

Today the harness **proves Half A** (the scaffold imports the sink's enclosing function and runs it
with a marked payload; the registry sink-oracle witnesses the effect) but **only infers Half B**
(`prove._apply_gate` reads the static call graph — `reachability.py` — and *guesses* whether an
untrusted entry reaches the sink). When that static guess is wrong, it **overrides the model's confirm**
and mislabels the finding. **Every false confirm this session was a wrong Half-B guess** (fastapi
`@app.command()`, the §10.1 name-collision).

The model is not struggling to confirm — it confirms Half A fine. The scaffold simply never pointed it
at the front door, so Half B is never *run*, only read off the graph. Stage 5 didn't fix this because it
re-runs the same two-part machinery (prove A, guess B).

## Why "SAST to 100%" is the wrong target

Deciding Half B precisely for arbitrary code is undecidable (Rice's theorem). Every static taint engine
is an approximation and must choose: **sound** (never miss → floods false positives) or **precise**
(few alarms → silently misses). There is no static setting that is both. So more static heuristics
(cross-function taint, type resolution) only **move** the frontier and **relocate** the whack-a-mole
(into framework/library/dynamic-dispatch models — worst exactly in Python/JS, our main targets) while
adding a permanent maintenance treadmill. They are worth doing — but as *hypothesis/slice quality*,
never as the thing that grants `confirmed`.

## The fix that closes the CLASS permanently

Apply wave's own grounding rule — *translate, then prove with a tool* — to **Half B as well as Half A**:

> **A top-tier `confirmed` may never rest on an inferred path. Either the path is WITNESSED, or the
> finding is a review lead with its best static trace attached.**

This bounds the failure mode: when we can't witness the path, we degrade to "here's the traced lead,"
never a silent false confirm. Uncertainty stays (unavoidable); **confident lies stop** (the actual pain).

### How we witness Half B without booting the whole app

`reachability.reaches_untrusted_entry_bound` already computes the **untrusted entry + the call path** to
the sink. Instead of scaffolding the *sink's* function, drive from the **entry** through that path:

1. **Scaffold the entry, not the sink.** Import the untrusted-entry function; call IT with the attacker
   payload (marked tracer). Execution flows naturally down the real chain to the sink.
2. **The existing sink-oracle (registry hooks) witnesses the landing.** If the marker reaches the sink
   in an unsafe position, **both halves are proven in one in-process run** — no app boot, no routing/DB.
3. **`reach_proof` on the record:** `witnessed` (drove from an entry and the marked value hit the sink)
   → true `confirmed`; `inferred` (only the static gate) → `anomalous_state` / review; `none` → review.
4. **Widen the mirror on failure (build-don't-abstain).** If the chain won't run standalone (a caller
   needs a value from elsewhere, a missing import), the model reflects more real source into the sandbox
   until the chain runs — the same instinct already used for Half A. Still can't run → stays a review
   lead with the static trace, never a false confirm.

Static analysis (Shift 1 gate, and any future cross-function taint / type resolution) becomes the
**hypothesis + slice generator** feeding step 1 — never the confirm authority. Its unsoundness can no
longer manufacture a false confirm, because a tool now proves the path.

## Build order

- **Shift 1 — grounded-confirm bar** *(BUILT, commit 2100433).* A confirm on a low-confidence static
  reach → review. Down payment on "don't confirm on weak inference."
- **Shift A — prove Half B** *(BUILDING).* Increment A1: thread the reachability **entry + path** into
  the prove record and the model brief, and instruct the prover to **reconstruct and drive the attacker
  value from the entry through the path to the sink**; stamp `reach_proof`. Increment A2: scaffold the
  entry directly (`repro.build` entry mode) so the drive is set up, not just requested. Increment A3:
  gate `confirmed` on `reach_proof == "witnessed"` (subsumes/retires the brittle static Half-B gate for
  cases where the path was witnessed).
- **Shift 2 — measurement.** A ground-truth harness already exists: `agent/bench/ghsa_bench.py` scores
  the current pipeline on 500 real CVEs vs ground-truth files; `bench.py` scores controlled targets.
  It is an instrument, not a decision-maker. Discipline gap: run it as a regression check after Shift A,
  not eyeball real repos.
- **Static taint upgrades (cross-function, type-resolved)** — *optional, later, as slice quality only.*
  Diminishing returns on Python/JS; never the confirm authority.

## Second-order effects (checked, per the "does the fix create new problems?" test)

- *Driving from the entry can need setup the sink-only scaffold didn't* (entry args, app context). →
  Mitigated by build-don't-abstain (widen the mirror) and by falling back to Half-A-only + inferred
  reach (review), never a false confirm.
- *Some entries genuinely can't be reconstructed standalone* (deep framework coupling). → Those stay
  review leads with the static trace — honest, and the same as today's ceiling, minus the false confirms.
- *Does the class recur?* No: because `confirmed` now requires a witnessed path, a wrong static guess
  can only ever *under*-claim (leave a real vuln as a review lead), never *over*-claim (false confirm).
  Under-claims are safe and visible; over-claims were the bug.
