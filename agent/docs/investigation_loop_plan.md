# Investigation Loop — giving the brain a body

**Status:** design plan (2026-08-26). Supersedes nothing; it *wraps and generalizes* the current loop.

## 0. This is an extension of master_plan, not a replacement
Every organ here is a master_plan gap, now named and made concrete:
- **Recorder** = the *dynamic ledger / State-Space-Hash* the external reviews asked for.
- **Architect** = the *"deterministic stations own cross-file"* principle (the model's weak spot).
- **Confirmation Ladder** = how master_plan's *two-tier model* is actually earned: a finding's tier is
  the strongest rung it reached (Tier-1 = a witness at Rung 1/2/3; Tier-2 = a reasoned hypothesis).
- **Reader** = the *model-driven discovery* master_plan wanted but never had (deterministic discovery
  returned 0 on VAmPI); it also lets the model find shapes patterns miss, so it reads high-value files
  **regardless of** whether the seed pass flagged them.
- The **provisioning-first** ambition (§17) stops being *fatal*: Rungs 0/1 confirm without a full boot.
- **Request-artifact** (the cure53/xbow idea): when the body cannot confirm, it says *what it needs*.
**Motivation:** two limits surfaced testing on a real app (Manga_ryu, a FastAPI project):
1. **Provisioning is a hard gate.** The oracle is a live sink tripwire, so proving requires the whole
   app to boot. Manga_ryu couldn't boot standalone → the loop produced *nothing*. Running should be a
   *confirmation channel*, not a prerequisite.
2. **Understanding is deterministic + sink-centric.** Discovery is pattern/taint matching; the model
   never reads the code to form its own hypotheses, and proof watches sinks — but **not all vulns are
   at sinks** (logic, auth, access, pricing are about *state and relationships*).

## 1. The thesis: brain + body

The model is a **brain** — it reasons, reads, hypothesizes, decides. It has no senses, no hands, no
memory. The loop is the **body** that gives it:

- **Eyes** — read source; observe responses.
- **Memory** — the Recorder (a persistent Case File) so the same file is understood *once*, not re-derived.
- **Hands** — send requests; run targeted code.
- **Grounded senses** — the deterministic confirmers: sink tripwire, differential, data-flow prover.

The brain decides *what to investigate and what it means*; the body *perceives, remembers, and proves*.
This is the neuro-symbolic split restated: **the model translates and speculates; deterministic tools
perceive and confirm.**

## 2. The one invariant that must never break

**A hypothesis is not a finding.** The brain may speculate, correlate, and believe freely — that is its
job. A belief becomes a *reported finding* only when the body has **demonstrated** it (a sink fired, a
differential flipped, a data path shown unsanitized). In the Recorder, "believed" and "confirmed" are
different colors of ink, and **only confirmed ink is published.** Lose this and the body stops being a
body and becomes a second brain nodding along — the confidently-wrong LLM this project exists to avoid.

## 3. Components

### 3.1 The Recorder (Case File) — the body's memory
A persistent, structured, queryable investigation state. The single source of truth the brain consults
instead of re-reading. Typed, provenanced entries:

| entry type | holds | typical source |
|---|---|---|
| `file_summary` | what a file does, its role | model (Reader) |
| `route` | method, path, handler, auth-gated? | tool (Architect) |
| `dataflow_edge` | source → … → sink, sanitized? | tool (Architect) |
| `entity` | a user/resource + ownership | model + tool |
| `control` | a control that should exist (rate-limit, authz, idempotency) and whether it's present | model + tool |
| `hypothesis` | "X may be exploitable because …" | model |
| `evidence` | a fact bearing on a hypothesis | model or tool |
| `confirmation` | a demonstration at a ladder rung | oracle |

Every entry carries: **source** (`model` \| `tool` \| `oracle`), **status** (`believed` \| `confirmed`
\| `refuted`), **provenance** (`file:line` / request), **version** (entries are superseded, never
silently overwritten). The Case File is **revisable**: new evidence touching an entry's subject queues a
**revisit** of that subject only — the body doesn't re-read the world, just what changed.

> **Guardrail:** a recorded model belief can be *wrong or partial*. It is marked `believed` and is
> re-checked against the code before any hypothesis that *depends on it* is confirmed. Understand once,
> but never trust blindly forever.

### 3.2 The Reader — the brain reads code and records understanding
Replaces deterministic discovery as the *primary* understanding channel (deterministic discovery stays
as a fast **seed** pass — a hint, not the truth). The model reads **prioritized** files (routes, auth,
data access, anything the seed pass flagged — *not* exhaustively), and records `file_summary`,
`entity`, `control`, and `hypothesis` entries as `believed`. Triage + budget are explicit: chase the
highest-value files first; a real detective does not read every document.

### 3.3 The Architect — deterministic tools write facts
Call graph, import graph, route extraction, and **data-flow** (source→sink reachability + sanitization).
Writes `confirmed` structural facts — especially the **cross-file paths the model is bad at**. When the
brain proposes a connection between files, the Architect verifies the path actually exists before it is
treated as fact. *Model imagines the link; the graph proves the link.*

### 3.4 The Confirmation Ladder — the fix for the provisioning gate
A hypothesis is confirmed by the **cheapest sufficient rung**. Each finding is labeled by the strongest
rung it reached.

- **Rung 0 — static reachability + sanitization.** Does tainted input reach the sink, and is it
  neutralized on the way? Confirms *safe* (parameterized → DEFER) or *reachable-and-unsanitized* (a
  strong lead). **No execution.** (This alone correctly clears Manga_ryu's `get_browse` as safe — the
  user values go to psycopg2 params, never the SQL string — without booting anything.)
- **Rung 1 — targeted micro-execution.** *Import, mock, call* — not "extract code." The target image
  already builds (all deps present); only *full boot* fails. So: inside the built sandbox, **import the
  handler's module, stub the unavailable services** (patch `database.get_conn`, the outbound client),
  attach the sink tripwire, and **call the function directly** with a crafted input. Confirms behavior
  **without booting the whole app** — exactly what would prove Manga_ryu's `install_extension` without
  Postgres or Suwayomi. This is the rung that *decouples proof from full provisioning.* Rung-1
  confirmations record the stubs used and rank **weaker than Rung 2** (a function out of context can
  differ from the function in the running app).
- **Rung 2 — full runtime oracle.** Boot the app, fire real requests (today's loop). Strongest, but only
  when it boots.
- **Rung 3 — differential / behavioral (non-sink).** For logic/auth/pricing vulns (IDOR, tampering,
  workflow, replay) that have *no sink*. Runs against a live endpoint (Rung 2) or a micro-executed
  handler (Rung 1). These already exist as `bizlogic.py` / `idor.py` / `missing_controls.py`.

> Non-sink vulns are **first-class**: the Recorder holds the code's *behavior model* (entities,
> ownership, controls, flows), and Rung 3 confirms violations of it. A sink hit is *one kind* of
> evidence, not the definition of a finding.

### 3.5 The Editor — the coordinator
Drives the case: seeds from the deterministic pre-pass + the Reader; for each hypothesis picks the
**cheapest sufficient rung**; connects findings via the Architect's verified paths; triggers revisits;
and gates output on `believed` vs `confirmed`. Runs **one test at a time** — the smallest thing that
settles the current hypothesis.

- **Prioritization.** Hypotheses are worked in order of `severity × confidence × reachability ÷
  cost-to-confirm`. Cheap, high-severity, clearly-reachable hypotheses go first; expensive, speculative
  ones wait (and may never run if the budget ends).
- **Termination (a detective can investigate forever — the Editor must not).** Stop when: the budget is
  spent, every hypothesis above a value threshold is adjudicated (confirmed / refuted / blocked), or
  returns diminish (N steps with no new confirmed/refuted entry). The master_plan **request-hash
  backtrack** guards against re-trying the same test in a spin.
- **Refutation is a goal, not a byproduct.** Clearing a candidate as *proven-safe* (e.g. a parameterized
  query) is first-class value — it is what makes the tool trustworthy on real code, where most
  candidates are noise. Refuted entries are **remembered** so nothing re-investigates them.
- **Honest "I'm blocked."** When *no* rung can confirm a live hypothesis because the body lacks
  something real — a DB seed, a config secret, a hardware device, a service — the Editor emits a
  `blocked` entry naming **exactly what would unblock it** (the cure53/xbow request-artifact idea),
  rather than silently deferring or, worse, guessing.

## 4. How this solves Manga_ryu (and any un-bootable app)
The app never boots (missing Postgres/Suwayomi, and a Flask-vs-FastAPI entrypoint bug). Today → nothing.
With the ladder:
- **Rung 0** adjudicates the 21 candidates statically: `get_browse` SQLi → parameterized → **SAFE/DEFER**;
  the `home.py` "SQL" → GraphQL strings → **DEFER**; `install_extension` → user-controlled path segment
  reaches an outbound request unsanitized → **reachable lead**.
- **Rung 1** micro-executes `install_extension(pkg_name="../../…")` against a stubbed `BASE_URL` with the
  SSRF tripwire → **confirms** the path-injection *without* Postgres or Suwayomi.

Real, grounded, tiered output on code that never ran as a whole — which is the entire point.

## 5. Build order (each phase ships + is verified on the bench)

**Phase 1 — The Recorder.** Data model + store + query API. Retrofit the *existing* loop to write to it
(routes, candidates, sink-proofs → `confirmation`). No behavior change; the body just gains a memory.
*Verify:* run the current bench; the Case File faithfully mirrors what the loop did.

**Phase 2 — Rung 0 (static reachability + sanitization).** A deterministic source→sink data-flow check,
wired as a **pre-oracle**: provably-safe candidates (parameterized/escaped) DEFER *without booting*;
provably-reachable-unsanitized are elevated. *Verify:* pyvuln still 100%; Manga_ryu `get_browse` → SAFE
with no boot. (Fold the FastAPI **entrypoint detection** fix in here — read the Dockerfile CMD / detect
`main:app` instead of assuming `app.py`.)

**Phase 3 — Rung 1 (targeted micro-execution).** Harness to extract a function + deps and run it in the
sandbox with a crafted input + tripwire. *Verify:* prove a candidate on an app that won't fully boot
(Manga_ryu `install_extension`), decoupled from provisioning.

**Phase 4 — The Reader.** Model reads prioritized files and records understanding + hypotheses. The
brain now forms *its own* hypotheses, not just deterministic candidates. *Verify:* on a controlled
target the Reader independently surfaces the planted vulns as hypotheses; on Manga_ryu it produces a
behavior model + a ranked hypothesis list.

**Phase 5 — The Editor + revisit loop.** Coordinator that picks the cheapest sufficient rung, connects
via the Architect, triggers revisits, budgets. *Verify:* end-to-end on Manga_ryu — tiered findings with
confirmation labels, **zero false positives**, without full boot.

**Phase 6 (later) — specialized reporters.** External intel (dependency CVEs, framework-specific
patterns, git history) and a dynamic "interview" pass, as additional evidence sources feeding the board.

## 6. Integration with what exists (nothing is thrown away)
- The **sink hooks** become Rung 2's tripwire (reused as-is).
- The **business-logic / IDOR / missing-controls differentials** become Rung 3 (reused as-is).
- **Deterministic discovery** is demoted to the fast *seed* pass (a hint that primes the Reader).
- The **current provision→craft→prove loop** becomes *the Rung-2 path* — one route to confirmation, no
  longer the only one.
- **master_plan two-tier** gets concrete: **Tier-1 = confirmed at a witness rung; Tier-2 = a reasoned
  hypothesis for review.** The ladder is how a finding earns its tier.

## 7. The Case File *is* the report — and the fix hook
The Recorder isn't just internal state; it **renders to the human-readable investigation report** — the
"did it do its job" artifact: what was read, what's `believed` vs `confirmed` vs `refuted` vs `blocked`,
with evidence and provenance per entry. Tier-2 hypotheses land here for human review; Tier-1 confirmed
findings land here with their demonstration.

Remediation reconnects to the north-star ("finds **and** fixes"): a `confirmed` finding feeds the patch
phase, and the fix is **re-confirmed at the same rung** that proved it (a Rung-1 micro-exec proof →
re-run the micro-exec after patching; a Rung-2 runtime proof → re-fire the request). The ladder is thus
also the *re-verification* mechanism, extending auto-fix beyond today's sink-only classes.

## 8. How we know it's better (the eval)
The controlled bench (recall/precision on planted vulns) stays as the regression floor. The
investigation loop adds three real-code dimensions, measured on apps like Manga_ryu:
- **No-boot adjudication rate** — fraction of candidates given a grounded verdict (confirmed / refuted /
  blocked) *without* a full Rung-2 boot. (Today: 0. Target: most.)
- **Real-code false-positive rate** — of the raw deterministic candidates (Manga_ryu: 21), how many are
  correctly *cleared* by Rung 0/1 (`get_browse`, the GraphQL "SQL", the numeric filename) vs. wrongly
  reported. This is the number that proves we beat plain SAST.
- **Coverage** — fraction of high-value files the Reader actually understood, and of routes/entities the
  Case File models.

## 9. Risks / honest cautions
- **Cost.** Reading + revisiting on a 14B/16 GB setup is many model calls. Triage and budget are not
  optional; the Editor must prioritize and stop.
- **Recorded-belief drift.** Mitigated by `believed` vs `confirmed` + re-check-before-depend (§3.1).
- **Rung-0 soundness (the riskiest piece).** A *sound* inter-procedural taint engine is a research
  problem; do not promise one. Scope it: **start intra-procedural + known-sanitizer recognition**
  (parameterized-query APIs, escape/quote calls, allow-list checks) — enough to clear `get_browse` —
  and defer full inter-procedural analysis. A prover that says "safe" when it isn't is worse than none,
  so Rung 0 may only ever emit **DEFER (proven-safe)** or **ELEVATE (reachable)**, never a *finding* on
  its own; when unsure it does **not** clear (unsure → hand to a higher rung, not to "safe").
- **Micro-execution fidelity.** A function run out of context can behave differently than in the app.
  Rung-1 confirmations are labeled as such (weaker than Rung 2) and note the stubs used.
