# wave SAST — Improvements v2

**Status: all 5 implemented (Oct 13 2026).** Commits on `corpus-rebuild-and-dpo`:
571fede (#1 scoreboard) · 3421d52 (#2 guardmap) · 2e7e2e6 (#3 safe-patterns) ·
25e1ad5 (#4 deterministic notebook) · e07b679 (#5 runrecipe + patch test gate). 525 tests.

Oct 13 2026 · derived from live runs on **OpenWA** (NestJS/TS) and **gods-eye-view** (Node/JS),
following the Oct 12 Improvement Plan. Those runs validated the file-pinning + report-noise work
(PR #6, merged) but exposed a deeper pattern:

> On both real apps wave **confirmed 0** and degraded every finding to "unproven lead / reasoned
> non-issue" — i.e. **model judgment, not tool proof.** Some is correct (both codebases are
> security-literate), but it means the core thesis ("model translates, tools prove") was never
> exercised. These five items attack that, in priority order.

Work order is 1→5. Each lands as its own tested, committed increment.

---

## 1. Scoreboard (was plan §2) — *measure before tuning*
**Why:** every change since (pinning, noise fixes) is unvalidated — we eyeballed OpenWA, no number.
**What:** `agent/bench/scoreboard.py` — a deterministic funnel scorer that reads a target's
`wave_*.jsonl` against a ground-truth file and prints the stage funnel:

| Stage | Count |
|---|---|
| Real bugs pinned | |
| In notebook notes | |
| Survived detector | |
| Reached prove (in budget) | |
| Confirmed | |
| **Confirmed on safe twins (must be 0)** | |

Ground truth = a small JSON per fixture (`{file, line±, class, exploitable: true|false}`). Wire to the
existing bench fixtures + safe twins (safeapp/htmlsafe). Records model + date. No CVE download needed
now — the harness is the deliverable; the corpus is populated later.

## 2. Framework-aware guard / auth map (was plan §4) — *the recurring false-lead*
**Why:** the single most repeated failure in both runs — the model had to *guess* whether an upstream
framework guard covers a handler, and sometimes got it wrong (the `automation-rule` IDOR false-lead:
NestJS `ApiKeyGuard` scopes `:sessionId`, model couldn't trace it).
**What:** `agent/orchestrator/guardmap.py` — per-route, which guards/middleware apply: NestJS
`@UseGuards`/`@RequireRole` (class + handler), Express `app.use(mw)` / router middleware chains,
FastAPI `Depends()`, Spring security. Consumed by the authz/IDOR controls so a guard-covered route is
not flagged, and the prover is told a route is genuinely unguarded.

## 3. Known-safe deterministic pre-filter (was plan §4)
**Why:** OpenWA spent 8–16 "investigate" model runs per item re-deriving what a recognizer settles:
"TypeORM binds params → safe", "ssrf-guard wraps the fetch → safe", "argv-array spawn → safe".
**What:** `agent/orchestrator/safe_patterns.py` — deterministic clears for parameterized/bound queries
(TypeORM/Prisma/`:param`/`%s`), argv-list exec (no `shell:true`), guard-wrapped fetch, `shlex.quote`,
`path.resolve`+prefix. Runs in the detector before the model/prove budget is spent (clears only; never
a confirm authority).

## 4. Notebook coverage + determinism
**Why:** 40 of 202 pinned files deep-read, a *different* 40 each run (model-chosen) → 80% skipped and
not reproducible. Pinning removed fixtures and `--jobs` made reads ~4× cheaper, so we can afford more.
**What:** deterministic selection (use the reachability rank order instead of a model pick when
`pinned > budget`), and a higher default budget. Stabilises the scoreboard too.

## 5. Prove-stage provisioning: run-recipe detection (enables plan §5 stronger patch gate)
**Why:** confirmed=0 is partly because prove can't reliably build+run a framework app and drive the
real route. The tractable, deterministic half is detecting *how to run/test* a repo.
**What:** `agent/orchestrator/runrecipe.py` — static detection of package manager + build/run/test
commands + a persisted manifest (modeled on grok-cli's verify subsystem). Wire "run the repo's own
tests" into the patch reverify gate (plan §5). Full boot-and-drive is a larger follow-on.

---

Not in scope here: cloud sandbox backends (Modal/Daytona — declined); plan §1a Docker sink-secret
rewrite; the self-improving skill loop (plan deliberately dropped auto-self-improvement).
