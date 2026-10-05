# Proof-system integrity — threat model & mitigations

wave's core claim: **a `confirmed` finding means a tool witnessed a real effect**, not that the model said so.
This doc examines how a *non-cooperative* model (a different/fine-tuned model, or one under prompt injection
from the scanned code) could try to fake a witness, and what wave does about it.

## The witness sources, by trust

| Witness | Origin | Forgeable by the model? |
|---|---|---|
| AddressSanitizer report | the compiled binary | **No** — comes from the sanitizer, not the model |
| `WAVE-SINK-*` markers | the instrumented sink (registry.py) | **No** — printed by the driver when the sink fires |
| Browser canary (`WAVE_RENDER_CANARY: 1`) | headless chromium evaluating the DOM | **No** — the payload executed in the browser |
| `wave_HIT` side-effect file | the exploit does `touch <marker>` | **Partially** — model-planted (see below) |

The first three are **sink-origin**: the marker exists only because the vulnerable code path ran. The last is
**model-planted** — the model writes the `touch`, so in principle it could create the file without a real
exploit (`touch wave_HIT` as a standalone command), and the marker would still appear.

## The marker-planting risk

Not a current practical problem (the production model is cooperative and gains nothing from faking). But if
wave runs a less predictable model, the distinction between *"the marker came from the sink"* and *"the model
echoed the marker"* matters.

## Mitigations

**Implemented:**
1. **The harness reads its own markers** (`oracle.py`), never the model's narration of what happened. A
   confirm is graded on tokens found in the sandbox *output*, not on the model's prose.
2. **Per-run random marker.** The `wave_HIT` witness is now a per-proof random token `wave_HIT_<rand>` that the
   harness substitutes into the brief (`briefs._brief_for(hit_marker=)`) and then matches EXACTLY in the
   output (`investigate` records only the exact token; `oracle.scan` no longer matches a bare `wave_HIT`).
   This defeats a **memorized** marker (a fine-tuned model that learned `touch wave_HIT`) and a
   **prompt-injected** one (scanned code that plants `wave_HIT` cannot guess the run's token).
3. **Independent-marker corroboration** (rung1): the deterministic canary uses a fresh random marker each call,
   so its audit re-run is an independent second proof.
4. **Decorrelated second-model audit** (`WAVE_AUDIT_MODEL`) on the no-marker (judgment) confirms.

**Residual gap (accepted / deferred):**
- A model that reads its *own* brief still knows the run's token, so it could `touch <token>` standalone. The
  per-run marker does not stop a model actively gaming the brief it was given — only memorized/injected markers.
  Closing this fully needs **sink-origin verification for injection classes** (e.g. confirm the marker appeared
  in the DB query log / the instrumented sink, not in stdout), which requires loading the `WAVE-SINK-*`
  instrumentation into the investigate sandbox (today those markers appear only on the instrumented-boot path).
  That is the natural next step and overlaps with the DAST work.

## Principle

Prefer sink-origin markers where they exist (ASan, `WAVE-SINK-*`, browser canary); treat the model-planted
`wave_HIT` as the weakest witness and keep it per-run and exactly-matched; and keep the second-model audit for
everything a marker cannot decide.
