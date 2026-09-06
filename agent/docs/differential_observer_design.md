# Design: the Differential / State Observer (synthetic micro-harness)

*Status: BUILT 2026-09-06 (commit acd2fc4) — Tier 1 (function harness) shipped as the `differential` proof
mode: brief-guided 2-identity synthetic harness for IDOR / broken access control (CWE-639/284/862/863/566),
always landing `anomalous_state` (human-review). Tiers 2 (app test-client for auth/cookie/header) and 3
(whole-app boot) and the dedicated threat-model detection pin remain follow-ups; today the notebook surfaces
authz findings (prompt-nudged), which route to the observer. The general proof mechanism for the vuln classes
that have no dangerous sink — the "complex, unseen" half of the North Star, beyond the 9 injection classes.*

---

## 1. The problem it solves

Stage 3 today can only `confirm` a vuln when a **sink** fires (a canary in SQL/shell/path/URL, an XSS render,
a return-value check). But the highest-value real bugs often have **no sink at all**:

```python
@app.get("/orders/{order_id}")
def get_order(order_id, user):
    return db.get_order(order_id)      # never checks the order belongs to `user`  -> IDOR
```

There is nothing to tripwire. The only proof is **behavioural**: run it as user A asking for user B's order,
and observe that A received B's data — a **state boundary crossed**. That is the differential observer.

## 2. The key decision: synthetic micro-harness, NOT whole-app boot

The naive path is DAST — boot the whole production app and drive real HTTP requests. **We reject that as the
primary path** because it fails the core goal (*work on ANY repo*): most repos won't boot in a sandbox — they
need config, secrets, Node/other toolchains, supply-chain packages, and live third-party services (AWS, Stripe,
a message queue). Tying the observer to a clean boot limits it to the lucky repos.

**Instead: the harness owns the glue, the model owns the payload — extended from "call one function" to "stand
up a minimal app around the concern."** The model extracts *only the code under test*; the harness builds a
tiny synthetic app around it, seeds a fake in-memory store with two identities' data, drives the flow as each
identity, and diffs the result. The repo never runs as a whole; only the slice runs, inside a scaffold.

**There are THREE tiers, climb only as high as the vuln needs:**

| Tier | What runs | Reaches | Best for |
|---|---|---|---|
| **1. Function harness** | one function + fake store, in-process | seconds | logic / IDOR in a callable (`get_order(id, user)`) |
| **2. App test-client** | the app OBJECT + its built-in HTTP test client, in-process | seconds | **auth / cookie / header** — real HTTP + middleware, NO boot |
| **3. Whole-app boot** | the whole app via compose | minutes; often fails | flows needing the real integrated stack / external services |

**Tier 2 is the answer to "how do you test auth/cookie/header vulns?"** — those live in the HTTP layer
(request parsing, middleware, cookies), which a function call skips. But you do NOT need production: every
framework ships an in-process test client (Starlette/FastAPI `TestClient`, Flask `test_client()`, Django test
client; JS `supertest`) that sends real HTTP requests to the imported app object — real headers, real
middleware, real cookies — with **no server, no docker, no services running** (stub the external bits). The
differential is identical: same request, one variable changed, observe the delta.
- **auth bypass:** `GET /admin` with no cookie vs. as a normal user → a 200 = broken auth.
- **cookie hijack:** log in, inspect `Set-Cookie` (HttpOnly/Secure/SameSite); replay A's cookie from a fresh
  client → does it grant A's access? does the session id rotate on login (else fixation)?
- **header exploit:** send `Host: evil.com` / `X-Forwarded-For: 127.0.0.1` → did a security decision change?

Tier-2 limit: the app object must **import** (top-level imports must resolve). If it does `import boto3` /
connects to AWS at module load, the import fails → Tier 3, or stub that import.

Whole-app boot stays available (provisioning was just strengthened) for the cases that genuinely need the real
integrated stack — but it is the last resort, not the headline.

### When NOTHING will run: research like a pentester (the escalation)

Some targets can't be exercised at any tier — a supply-chain dependency that can't be installed, an import
that needs a live third-party service (AWS, Stripe, a queue). A real pentester who can't run the target does
not give up; they **read how the thing works** and reason to a conclusion. So the escalation ladder is:

> run → (can't provision) try to fix the env (≤2 attempts) → **still can't: RESEARCH it** (web_search +
> web_read the docs, understand how the dep/API actually behaves) → conclude a reasoned **`believed`** (cite
> the source) → only `blocked` if even research leaves it undecidable.

**Hard guardrail (grounding rule intact):** research informs a *belief*, it is not proof. A web-reasoned
verdict is **`believed`** (likely-vulnerable or likely-safe), **never `confirmed` or `refuted`** — those still
require actually running it and observing the effect. This turns a dead `blocked` into a useful researched
lead. *Example:* `jwt.decode(token, options={"verify_signature": False})` — sandbox can't forge the real
session flow → the model web_reads the PyJWT docs → learns signature verification is disabled → `believed:
auth bypass` (cited), human-review. *(Wired: the `--online` web_search/web_read tools + the escalation
instruction in `investigate.py`.)*

## 3. How the micro-harness works (the flow)

For a candidate that is a **business-logic / access-control** concern (not a sink class):

1. **Extract** — the harness pulls the enclosing function + its intra-repo dependencies (via codemap's call
   graph + imports: the sink function, the helpers it calls, the models it touches). Reuse
   `rung1._pkg_root` / `codemap` to gather the minimal import closure.
2. **Synthesize a mini-app** — the harness writes a tiny driver (like `repro.py`, one level up) that:
   - imports the extracted function,
   - installs a **fake store** (an in-memory dict standing in for the DB — the same stub philosophy as
     `rung1`'s tripwires, but returning *seeded owned/other-user rows* instead of recording),
   - seeds two identities: `userA` owns record 1, `userB` owns record 2.
3. **Drive the differential** — call the flow **as A requesting A's record** (baseline) and **as A requesting
   B's record** (attack), capturing the return / state each time. The model supplies the *identity + target*
   payload; the harness owns the seeding + invocation glue.
4. **Observe (the fact, never a verdict)** — a `StateObserver` compares: did the attack call return B's data,
   mutate B's record, or elevate A's role? The **delta** is the observed fact.
5. **Verdict** — a witnessed attacker-favourable state change → **`anomalous_state: human-reviewable`** (NOT
   `confirmed`): per the plan (§6/§10.7), "is this state *bad* or *intended*?" is a judgment no tool can make
   alone, so business-logic results are always human-review, anchored to a real observed delta — never silently
   confused with a witnessed injection.

## 4. What the model supplies vs. what the harness owns

- **Harness owns (deterministic glue):** the import closure, the fake in-memory store + seeding of two
  identities, the invocation harness, the before/after state capture, the diff.
- **Model owns (the reasoning):** *which* parameter carries identity vs. target, what "owned vs. other" means
  for this flow, and the interpretation of the observed delta. This is where the model earns its keep — it
  reads the slice and frames the tamper; it does not fight the glue (the repeated failure `repro.py` fixed).

## 5. Detection side (surfacing no-sink targets)

Differential candidates have no sink pin, so the current regex front-end never surfaces them. Detection needs a
**threat-model pin** (a follow-up, small): flag routes/handlers that take an **id/owner-bearing parameter**
(`{id}`, `user_id`, `account`, `order_id`) and touch a store — the classic IDOR/ownership shape — as
differential candidates, independent of any injection sink. (The legacy `idor.py` already has an
id-param-route heuristic to draw from; it just needs re-wiring to the new pipeline as a candidate source.)

## 6. Honest limits (state up front)

- The synthetic harness tests the logic **in isolation** — it can miss a check that lives in *middleware* the
  real app would apply (an `@requires_owner` decorator, a gateway auth layer). Mitigation: the extractor
  includes decorators + directly-referenced guards in the closure; anything cross-cutting that isn't in the
  slice is a known blind spot → the whole-app fallback covers those.
- It proves the *mechanism* of a logic flaw, not that it's reachable with a real session — same
  reachability/context caveat as elsewhere; the reachability gate still applies.
- Verdict is always `anomalous_state` (human-review), never `confirmed` — by design.

## 7. Build sketch (files, when approved)

- `agent/orchestrator/harness.py` *(new)* — the synthetic mini-app builder: import-closure extraction +
  fake-store seeding + two-identity driver (the `repro.py` "one level up").
- `agent/orchestrator/observers.py` *(new, or extend `rung1`)* — `StateObserver`: seed → call A/A, call A/B →
  diff → fact.
- `prove.py` — a `differential` proof mode for id/owner-bearing candidates, routed like the other modes;
  verdict fixed to `anomalous_state`.
- Detection: a threat-model pin for id/owner-bearing routes (rewire `idor.py`'s heuristic), so these surface
  without a sink.

## 8. Open questions for review

1. **Fake store fidelity.** A dict stub returns seeded rows without the app's real ORM/query semantics. Enough
   to prove "A got B's row," or do we need a real (throwaway sqlite) DB seeded with two users for higher
   fidelity? (Leaning: dict stub first; sqlite when the flow does real queries.)
2. **Identity model.** How does the harness know which param is the *caller identity* vs. the *target id*? The
   model frames it — but is a wrong framing a silent miss? (Mitigation: try both orderings; a delta on either
   is the signal.)
3. **Where the whole-app fallback kicks in.** Auto-fallback to boot when the closure can't be extracted /
   isolated (cross-cutting middleware), or only on explicit `--dynamic`?
