# wave SAST — Remaining Work: implementation status

Implements the recommended 1→5 sequence from "wave SAST — Remaining Work + Lessons Ledger" (Oct 14 2026).
The **Lessons Ledger** is deliberately deferred to later work (per the build order: seal the verdicts
first — a ledger that learns from fakeable confirms learns garbage).

Each item landed as its own tested, committed increment. 548 tests.

| # | Item | What shipped | Commit |
|---|------|--------------|--------|
| 1a | Proof seal | Per-run secret on the harness `WAVE-SINK-*` markers | `oracle`/`registry`/`investigate`/`prove` |
| 1b | Half-B from the tape | Reach witnessed only when a per-run tracer reaches a sealed sink | `oracle`/`briefs`/`investigate`/`prove` |
| 3 | Answer-key leak | Scan a MANIFEST-free staged copy of the app code | `bench/stage.py`, `bench/bench.py` |
| 4 | More safe twins | nodesafe / pgsafe / crossfsafe (incl. first non-python control) | `bench/targets/*safe` |
| 5 | Cheap wins | Flag+retry truncated replies; skip the coin-flip judge on TIER-3 classes | `model.py`, `prove.py` |

## 1a — the proof seal
`oracle.scan()` grepped the sink markers as FIXED strings, so a `cat` of a hook, a marker literal in
scanned source, or memorization forged a tape-grade `harness_witnessed` confirm with no audit. Now each
instrumented hook reads a per-run secret from `$WAVE_WITNESS` and emits `WAVE-SINK-<KIND>#<secret>`;
`oracle.scan(text, secret)` counts a sink marker only when it carries that run's secret. `prove` mints the
secret per candidate and threads it `prove → investigate → execute(env) → hooks`; the model is never told
it. Back-compat: no secret → legacy bare match (boot-path oracle, rung1, tests unchanged).
**Remaining 1a sub-item (needs live Docker):** hook-side UNSAFE-vs-SAFE gating via a coordinated tracer,
so a bound/parameterized query stops emitting the marker at all.

## 1b — Half-B reach from the tape
`reach_witnessed` was the model grading itself. Now `prove` mints a per-run reach tracer (`WAVEREACH<rand>`);
the reach/route brief tells the model to carry it in the attacker payload at the entry; `oracle.reach_in_sink`
is true only when the tracer arrives at a SEALED sink line. `_reach_proof` returns `witnessed` only on that
tape signal; the model's flag alone → `claimed` (visible, the gate does NOT promote it). rung1 confirms are
unaffected. **Validate the confirmed-row impact on the bench (Docker);** the tape fires when a sink hook is
loaded in the sandbox, so loading hooks in the investigate box is a provisioning follow-on.

## 3 — answer-key leak
`bench.stage.staged(target)` copies only the app code into a throwaway dir (MANIFEST.json + wave artifacts
excluded), auto-cleaned; `bench.run_target` reads the truth from the original folder and scans the staged
copy, so the answer key is never mounted into the sandbox. Reusable by any scan harness.

## 4 — more safe twins
The scoreboard's only FP alarm (confirmed-on-safe-twin must be 0) had just two controls, both python/flask.
Added nodesafe (Express/JS — first non-python control), pgsafe (parameterized Postgres), crossfsafe
(cross-function bound query). Each is flagged-but-defended; picked up automatically via `MANIFEST safe:true`.

## 5 — cheap recall/noise wins
(a) `model.py` now flags a truncated (`finish_reason`/`done_reason` == length) or empty reply and retries
with a doubled token budget instead of silently returning nothing (the notebook whiff / silent refute);
salvageable partial replies are untouched. (b) `_audit_confirm` skips the near-coin-flip 2nd-model judge on
TIER-3 judgment classes (authz/idor/access/business-logic) and routes them straight to human review.

## Not done here
- **Lessons ledger** (the doc's new proposal) — deferred to later work, gated behind sealed verdicts.
- **Hook-side safe/unsafe gating (1a)** and **loading sink hooks in the investigate sandbox (1b)** — both
  need live-Docker validation; noted above as follow-ons.
- The remaining Open items from the doc's status table (full-path-to-detector slice, Semgrep/CodeQL leads,
  diff mode on `all`) — not in the 1→5 recommended sequence.
