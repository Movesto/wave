# Phase 0 — Manual MVP Findings (2026-08-22)

Executed the Phase-0 de-risking loop from `~/.claude/plans/eager-moseying-mountain.md`
autonomously. Goal: prove the revised architecture's loop **boot → instrument → auth →
exploit → sink-trace → patch → dual-gate verify** connects end-to-end by hand, no model,
no orchestration code, on the real substrate (Windows 11 + Docker Desktop / WSL2 backend).

## Result: TARGET 1 (VAmPI) — full loop PASSES end-to-end ✅
Cloned `erev0s/VAmPI` into `data/downloads/VAmPI`. Harness files added there:
`Dockerfile.otel`, `phase0.compose.yml`, `phase0_sink.py`, `phase0_exploit.sh`
(+ two tiny source edits, noted below).

| Step | Outcome |
|------|---------|
| 1. Boot | `docker compose -f phase0.compose.yml up` → app answers on :5002, `/createdb` seeds SQLite. ✅ |
| 2. Instrument | OTel auto-instrumentation emits **HTTP-route + DB-connection** spans (console exporter). **But NOT the SQL statement text** — see finding F1. ✅(partial) |
| 3. Auth Synthesizer | Standalone script registers **2 users** (alice/mallory), logs both in → JWTs, alice seeds an owned resource. Implements gap B. ✅ |
| 4. Identify vuln | SQLi (raw `text()` f-string in `get_user`) + IDOR/BOLA (`get_by_title`, no owner check). **Z3/CrossHair not used** — confirms gap C. ✅ |
| 5. Exploit + oracle | SQLi `' OR '1'='1'` returns a row (HTTP oracle) **and the instrumented sink shows the payload inside the query string** (proof). IDOR: mallory reads alice's secret with her own token (differential oracle). ✅ |
| 6. Patch + dual-gate | Parameterized the SQL + owner-scoped the book lookup, rebuilt. **Gate A:** both exploits blocked; sink now shows the payload as a **bound parameter** (`PARAMS=("' OR '1'='1",)`). **Gate B:** functional regression (benign lookups + alice's own read) still work. ✅ |

### The money shot — the instrumented-sink oracle discriminates mechanically
```
# vulnerable build:
PHASE0-SINK-SQL:: "SELECT * FROM users WHERE username = '' OR '1'='1'" :: PARAMS=()   <- payload IN the query
# patched build:
PHASE0-SINK-SQL:: 'SELECT * FROM users WHERE username = ?' :: PARAMS=("' OR '1'='1",) <- payload is a BOUND PARAM
```
This is exactly the plan's injection oracle ("payload appears in the query string logged
pre-exec = proven") working deterministically, and it *also* verifies the fix at the sink.

## Findings that refine the plan
- **F1 (matters). OTel auto-instrumentation does NOT capture the SQL statement text out of
  the box** here — only connection + HTTP spans. The payload-bearing query, which the whole
  DAST oracle depends on, required an **explicit `before_cursor_execute` hook**
  (`phase0_sink.py`) — i.e. the plan's own *"modified DB driver"*, not free auto-instrumentation.
  **Implication:** the "OTel Triple-Oracle" needs per-sink instrumentation hooks (DB driver,
  template engine, shell), which is R2 (per-stack instrumentation surface), confirmed early
  and concretely. Auto-instrumentation alone gives you routing/latency, not the sink proof.
- **F2. Flask debug reloader breaks `opentelemetry-instrument`.** The reloader re-execs a
  child that drops the wrapper → zero spans. Fixed with `use_reloader=False`. General lesson:
  the orchestrator must disable app auto-reloaders before instrumenting. (`WERKZEUG_RUN_MAIN=true`
  is NOT a valid workaround — it makes Werkzeug expect an inherited socket fd and crash.)
- **F3 (gap C confirmed). Z3/CrossHair contributed nothing on VAmPI.** Its live bugs (SQLi,
  IDOR, BOLA) are injection/authorization, not within-function math invariants. The DAST +
  instrumented-sink + differential path carried 100% of the detection. Reinforces the
  two-pipeline split: `web → DAST/OTel/taint` vs `compiled → angr/ASan`.
- **F4 (gap B confirmed). One dummy user is not enough.** IDOR/BOLA only became testable after
  provisioning **2 users + a victim-owned resource**. The Auth Fixture Protocol must seed N
  users + owned state, exactly as flagged.
- **F5 (R1). VAmPI ships NO native test suite** → Gate B could only be a functional smoke, not
  a native-suite regression. On repos like this the regression gate is inherently weaker.

## Target 2 (brokencrystals) — RAN interactively 2026-08-22. Boot + auth + 2 exploit classes ✅
8-service stack (Keycloak 26.1.2 OIDC/SSO + 2× Postgres 17 + NestJS + grpcwebproxy +
mailcatcher + ollama + watchtower). Harness file: `phase0_bc_exploit.sh`. Two reversible
`compose.yml` edits (db host port 5432→55432 to dodge a conflict; add nodejs `3000:3000`+`5000:5000`).

| Step | Outcome |
|------|---------|
| 1. Boot | All 8 services healthy (watchtower restart-loops — irrelevant, no Docker socket on WSL2). Needed: dodge a host-5432 conflict (another project's `teach-database`), and publish nodejs:3000 (the prebuilt `compose.yml` omits it; `compose.local.yml` has it). Then `/api/config`→200. ✅ |
| 3. Auth Synthesizer | **gap A did NOT block us.** brokencrystals exposes a **scriptable basic-auth API** (`POST /api/auth/login {op:basic}`, JWT in the `authorization` response header) *alongside* Keycloak. Script self-provisions users via `POST /api/users/basic`. ✅ |
| 5a. Mass-assignment priv-esc | Differential oracle: `regular_user`→`adminpermission`=403; `admin_user` created with hidden `isAdmin:true`→`{"isAdmin":true}`. Broken authorization proven. ✅ |
| 5b. XPATH injection | `GET /api/partners/partnerLogin?...&password=' or '1'='1` → dumps the full partner XML incl. cleartext passwords (baseline wrong-password = 403). Injection oracle via HTTP. ✅ |

### The go/no-go finding (revises the prediction)
The review predicted Keycloak SSO would block the Auth Synthesizer (gap A). **In reality it
did not** — brokencrystals, like many real apps, ships a non-SSO API login path. **Refined
lesson: gap A bites only when SSO is the *only* auth path; a scriptable API login (even
alongside SSO) is enough for the synthesizer.** So the operationalization risk is milder than
feared for API-first apps; it re-concentrates on (a) per-sink instrumentation (F1/R2) and
(b) apps that are SSO-*only*.

### Not done in this run (explicit scope, next increment)
- **OTel sink instrumentation + line-tracing:** the `nodejs` service is a *prebuilt* image, so
  the "modified DB driver"/OTel sink hook (the F1 lesson) needs a **from-source build**
  (`compose.local.yml --build`) with the NestJS bootstrap instrumented. Detection here used the
  HTTP + differential oracles only (which is a legitimate plan oracle for authz/injection).
- **Patch + Gate B:** brokencrystals ships jest e2e tests (`test/*.e2e-spec.ts`, run via
  `npm run test:e2e` against `SEC_TESTER_TARGET`), so a real native-suite regression gate is
  possible here — needs the from-source build + `npm ci`. This is the follow-on.

## Bottom line
The dynamic loop's **plumbing is proven** on a real containerized app on this exact
Windows/WSL2/Docker substrate: boot → instrument → synthesize auth → land SQLi + IDOR →
observe the payload at an instrumented sink → patch → confirm both exploits blocked at the
sink. The **crux risk is now operationalization**, precisely as the review predicted:
(1) sink instrumentation is per-stack, not free (F1/R2); (2) non-trivial auth (SSO) breaks
the synthesizer (gap A, brokencrystals); (3) thin/absent native tests weaken Gate B (F5/R1).
**UPDATE after running Target 2:** the auth reality is *milder* than the review feared — the
synthesizer worked against an SSO-stack app because it had a scriptable API login. The residual
crux narrows to: **(1) per-sink instrumentation is per-stack, not free (F1/R2)** — the biggest
real cost; (2) SSO-*only* apps still need an OIDC strategy or become DEFER; (3) thin/absent
native tests weaken Gate B (VAmPI), though brokencrystals shows many real apps DO ship a suite.
Both targets booted and were exploited via HTTP/differential oracles on this Windows/WSL2/Docker
box. Next increment: the from-source brokencrystals build to prove the OTel/sink line-tracing +
a real jest Gate-B regression — the two things this run deliberately deferred.

## Target 3 (OWASP NodeGoat) — FROM-SOURCE increment, RAN 2026-08-22 ✅
The deferred increment, done on a *different* repo and a *new stack* (Node/Express + **MongoDB**),
to prove: (1) sink instrumentation on a **from-source build** (not a prebuilt image), and (2) a
native-suite Gate B. Cloned `OWASP/NodeGoat` → `data/downloads/NodeGoat`. Harness: `phase0_sink.js`
(monkey-patches the `mongodb` driver's `Collection.find/findOne` = the "modified DB driver"),
`phase0_ng_exploit.sh`, `require("./phase0_sink")` added to `server.js`; the fix applied in
`app/data/allocations-dao.js`. Built from source via its own `docker-compose` (node:12-alpine + `mongo:4.4`).

| Step | Outcome |
|------|---------|
| 1. From-source build | `docker compose up --build` builds the app image from source (sink baked in) + mongo. App up on :4000, users seeded. ✅ |
| 2. Instrument (from-source) | The Mongo "modified DB driver" logs every query filter (`PHASE0-SINK-MONGO`). ✅ |
| 3. Auth | Session login (`user1/User1_123`), cookie jar. ✅ |
| 4/5. Exploit + oracle | **NoSQL `$where` injection** (`threshold=1'; return 1 == '1`). HTTP differential: baseline shows own data only; attack leaks **John+Will+Node Goat** (all 3 users). Sink oracle: filter logged as `{"$where":"... && this.stocks > '1'; return 1 == '1'"}` — the injected JS is visible at the driver (grep-on-source would miss a `$where` operator). ✅ |
| 6. Patch + Gate A | Fix = validate `threshold` as a bounded int, interpolate the int. Sink now logs `... this.stocks > 1` (payload stripped by `parseInt`); patched attack leaks **only John**. ✅ |
| 6. Gate B | Functional regression on patched build: login 302, dashboard/profile 200, own-allocations preserved (John only), out-of-range threshold → 500 (validation active). ✅ |

### New findings from the from-source increment
- **G1 (validates F1/R2 on a 2nd stack).** OTel/grep cannot see a NoSQL **operator** injection; the
  driver-level hook caught it cleanly. Confirms per-sink instrumentation is the real cost — and is
  **per-driver** (SQLAlchemy hook for VAmPI, mongodb `Collection` hook here — different code each time).
- **G2 (Gate B is infra-bound, sharper than VAmPI's "no tests").** NodeGoat *ships* a native suite, but
  it needs heavy external infra: **Cypress 3.3.1** (2019) + a browser for e2e, or **selenium +
  chromedriver + a ZAP proxy** for the mocha security test. Also the from-source **production image
  excludes devDependencies**, so the container can't self-test. So a real native-suite Gate B needs a
  dedicated test/browser environment stood up separately — the gate's cost is bounded by the target's
  test infra, not just whether tests exist (R1). Used a targeted functional regression here instead.
- **G3.** From-source instrumentation is *cleaner* than instrumenting a prebuilt image: you add the sink
  module + one `require` and rebuild. This is the mode the orchestrator should prefer when source is available.

## Reproduce
```
# --- Target 3: NodeGoat (from-source increment) ---
cd data/downloads/NodeGoat
docker compose up -d --build                 # builds app from source (sink baked in) + mongo
bash phase0_ng_exploit.sh                     # login + NoSQL $where injection
docker compose logs web | grep PHASE0-SINK-MONGO   # the modified-driver sink oracle
# patch already applied in app/data/allocations-dao.js ([PHASE-0 PATCH]); git-revert + rebuild to see vuln
docker compose down

# --- Target 1: VAmPI ---
cd data/downloads/VAmPI
docker compose -f phase0.compose.yml up -d --build   # boot instrumented VAmPI on :5002
bash phase0_exploit.sh                                # auth synth + SQLi/IDOR exploit
docker logs vampi-vuln-otel | grep PHASE0-SINK-SQL    # the instrumented-sink oracle
# patched code is already in models/user_model.py + api_views/books.py (marked [PHASE-0 PATCH]);
# to see the vulnerable behavior, git-revert those two edits and rebuild.
docker compose -f phase0.compose.yml down
```
