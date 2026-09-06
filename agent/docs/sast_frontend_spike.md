# SAST Front-End Spike — Findings (2026-08-23)

## Purpose
Phase 0 validated the DYNAMIC half of the plan (DAST + instrumented-sink/differential oracle) on
3 real apps — but the STATIC candidate-discovery front-end (the plan's Phase 1, which decides *what
to even look at* and therefore owns RECALL) was never tested: in Phase 0 *I* hand-picked the
vulnerable endpoints. This spike evaluates the existing front-end (`scanner/flag.py`, Station 1 taint
+ pattern detectors) against the vulns actually exploited in Phase 0, to measure recall + noise.

## Method
Ran `python scanner/flag.py <app> --json` on the three Phase-0 apps and mapped candidates to the
exact vuln locations exploited earlier. No model, no dynamic run — pure static discovery.

## Result: recall is coverage-limited (framework- and sink-dependent)

| App (stack) | candidates | recall on exploited vulns | notes |
|---|---|---|---|
| **brokencrystals** (TS/NestJS) | 21 | **good** — partners (XPATH), users (mass-assign), app.controller:219 (eval RCE), chat/file/email (SSRF/path/inj) all surfaced | mostly generic **CWE-20 "xflow"** (input reaches a call) — high recall, low specificity, meant for model triage |
| **NodeGoat** (JS) | 13 | **partial** — eval RCE (contributions.js:32–34) ✓, **NoSQL `$where` (allocations-dao.js) ✗** | |
| **VAmPI** (Py/Connexion) | 1 | **poor — 0/2** (SQLi + IDOR both missed) | only found `debug=True` |

## Root causes (confirmed in `flag.py` source)
1. **Framework source coverage.** `_SRC_ATTR` recognizes `request.args/form/json/...` (Flask/Django)
   and — from prior work — NestJS decorators (`@Body/@Query/@Param`), which is why TS works. But it
   has **no "function-parameter = source"** concept, so **Connexion/FastAPI** route params
   (`get_user(username)`) are never tainted → VAmPI's SQLi + IDOR are invisible. **Recall is
   framework-dependent.**
2. **Sink coverage.** There are SQL (`.execute`, concat-SQL), cmd, eval, redirect, SSRF sinks — but
   **no NoSQL / mongo `$where` / operator-injection sink** → NodeGoat's `$where` NoSQLi is invisible.
   The static sink library lags the dynamic-side Registry.
3. **Variable-indirection.** VAmPI builds `q = f"SELECT..."` then `execute(text(q))`; the inline
   concat-SQL pattern only matches the string built *inside* the call, so the indirected form slips.
4. **Specificity.** Where it fires broadly (brokencrystals CWE-20 xflow ×14) it doesn't name the vuln
   type — acceptable *only because* the model triages Station-1 candidates (the "model in v1" choice).

## Verdict
**The plan is NOT proven on SAST.** The front-end's *design* is sound (strong recall where sources +
sinks are modeled), but its *coverage* is partial, so recall — the one thing SAST must provide — is
unreliable across stacks today. This is the biggest load-bearing gap the plan rests on, now measured.
Crucially, the gaps are **enumerable coverage work, not a fundamental flaw.**

## UPDATE — gaps closed + re-measured (2026-08-23)
Two surgical, precision-first patterns added to `scanner/flag.py` (no taint-seeding, no new false
positives): a **raw-SQL-string-built-by-interpolation** pattern (catches SQL built into a variable
f-string/template-literal/concat — the variable-indirection form the inline pattern missed) and a
**NoSQL `$where`-built-by-interpolation** pattern. (Caught a self-inflicted trap first: the apps on
disk still had my Phase-0 *patches*, so the scanner correctly reported the fixed code as clean —
restored the original vulnerable source before measuring.)

| App | before | after |
|---|---|---|
| **VAmPI** | SQLi ✗, IDOR ✗ | **SQLi ✓** (CWE-89 L72). IDOR still ✗ — **correct**: authz/logic is the DAST differential oracle's job (it caught it in Phase 0). |
| **NodeGoat** | NoSQLi ✗, eval ✓ | **NoSQLi `$where` ✓** (CWE-943 L78) + eval ✓ |
| **brokencrystals** | regions ✓ | still ✓, **+ raw-SQL `kid` injection** (CWE-89 L10) — an improvement, no noise regression |

**Result: every injection-class vuln hand-exploited in Phase 0 is now surfaced automatically.** The
architectural split holds — SAST owns the injection/sink classes; IDOR/authz belongs to DAST. Recall
harness: `scanner/_sast_recall.py`. Remaining coverage work (deferred, precision-sensitive, needs a
decorated-route target to test): general framework param-sources for Connexion/FastAPI/Flask handlers.

## (original) Next: close the gaps + re-measure (the fix)
1. **Framework sources** — add function-parameter sources for Connexion/FastAPI/Flask route handlers
   (Python), mirroring the working NestJS decorator support.
2. **Sink coverage** — add NoSQL/mongo `$where`/operator-injection sinks; align the static sink
   library with the dynamic Registry so both halves cover the same sinks.
3. **Variable-indirection** — follow tainted string vars into `execute(text(var))`.
4. Re-run this spike; **target: VAmPI 0/2 → 2/2, NodeGoat NoSQLi surfaced**, no regression on
   brokencrystals. That converts "SAST unproven" into "SAST recall measured on the 3 targets."

Harness: just `scanner/flag.py`; ground-truth vuln locations are the ones exploited in
`docs/phase0_findings.md`.
