# Wave — Master Architecture Plan
### An autonomous, model-driven agent that finds *and* fixes complex vulnerabilities the way a senior pentester does

> **Status:** design spec, superseding `only_plan.md`, `revised_plan.md`, `new_plan.md`.
> **Revision:** v9 — adds **§17 Build discipline & de-risking** (gate-zero model spike, walking skeleton, ruthless MVP cut, provisioning-first, `compose_check` execution model, latency budget, N-of-M reproduction). v8 added **Operating Mode 2: Black-box DAST** (§16) — the same agent loop, given only a URL, acting as an external pentester against the deployed app, with verification swapped to *external* oracles (OAST callback, our own browser, response/timing differential). Optional Phase-2 check run after Mode 1 (grey-box SAST) has secured code + infra. Builds on the v7 two-tier model (Tier 1 *proven* / Tier 2 *demonstrated*) and five review rounds (change-logs at §14).
> **Audience:** an external reviewer. Section 14 lists the open risks I already know about — please attack those first, then everything else.
> **Hardware envelope:** single RTX 5070 Ti (16 GB VRAM, capped at 250 W), Windows 11 + WSL2 + Docker, fully local (no cloud inference, no data egress).

---

## 0. What "it works" means (success criteria)

We are not chasing a theorem. Finding *every* vulnerability in an arbitrary program is undecidable — no tool or human can do it. So we define success the way you'd judge a senior pentester: **does it work a target to a confirmed, fixed result, and is every claim it makes true?**

The system is successful when, on a target it has never seen:

1. **Grounded findings (the invariant we never break):** every reported vulnerability is backed by a *runtime demonstration*, never a bare model claim. Two tiers: **Tier 1** — a pre-built deterministic oracle witnessed it → **proven, zero false positives, by construction**; **Tier 2** — the model composed a check from the verification toolkit and *demonstrated* the exploit at runtime → **evidenced + confidence-scored → human review**. A pure hallucination with no runtime demonstration is never emitted at either tier.
2. **Unbounded hunting (the freedom we never remove):** the model may hypothesize and pursue *any* webapp vulnerability class — the architecture never restricts *what* it looks for. What differs by class is only *how strong the confirmation is* (Tier 1 vs Tier 2), never *whether it's allowed to try*. It can work a *complex* vulnerability — multi-step, cross-file, stateful, or behind auth — end to end: discover → demonstrate → exploit → fix → re-verify, driving its own tools and adapting to live feedback.
3. **Verified repair:** the fix it ships neutralizes the proven exploit *and* preserves behavior (no regression), or it is rejected.
4. **Measured, not asserted:** all of the above is demonstrated against a **graded benchmark of known-hard vulnerabilities** (§13) with a recall/precision number per vulnerability class — not a single hand-run demo.

Anything the system cannot yet prove is **deferred** with a reason. A deferral is a recall miss, never a wrong answer. This is the whole safety model: **all failure modes collapse to the safe side.**

**Threat model (explicit — several design choices depend on it).** The MVP targets **benign codebases with accidental vulnerabilities** — ordinary open-source/enterprise web apps whose code reaches sinks through normal library calls, not code actively trying to *evade* instrumentation. Under this model, application-layer instrumentation (audit hooks, driver proxies) is sound ground truth. The adversarial model — malware, payloads that bypass the stdlib via native FFI or custom interpreters, anti-instrumentation — is **explicitly out of MVP scope** and is what motivates the kernel-level (eBPF) upgrade path in §5.5. State which model a target belongs to; do not claim adversarial-grade evasion resistance the MVP does not have.

---

## 1. Core principles (the contract every component obeys)

These five principles resolve every design tension in the rest of the document. When in doubt, obey the principle.

**P1 — Neuro-symbolic division of labor.**
The **model decides**; **deterministic tools perceive and prove**. The model discovers what's suspicious, forms exploit hypotheses, crafts requests, and writes patches. Tools parse code, assemble slices, run the app, observe sinks, and verify fixes. We never hand-code a *decision* (which the old regex scanner did and why it was abandoned); we never trust the model's *claim* without a tool witnessing it.

**P2 — Grounded by construction, in two tiers.**
Nothing becomes a "finding" unless it was **demonstrated at runtime** — never a bare claim. But demonstration comes at two strengths:
- **Tier 1 — a pre-built deterministic oracle** witnessed it (marker in the SQL statement, differential leak, script executed in the DOM). Audited, reproducible → **proven, zero false positives.**
- **Tier 2 — a model-composed check.** For a class with no pre-built oracle, the model *assembles* a verification from the toolkit primitives (§5) and runs it; a pass is a real runtime demonstration, but its validity rests on the model's own check design → **evidenced, confidence-scored, human-reviewed** (false positives possible here, so it is never auto-shipped).
The model is still free to be wrong and take dead ends — a bad hypothesis or a weak check yields a *low-confidence or discarded* result, never a confident lie.

**P3 — Capability = the verification toolkit (not a fixed catalog).**
The model may hunt *anything*; the question is only how strongly a given class can be confirmed. **Tier-1 oracles** are the hardened witnesses for the highest-value classes (injection, authz, XSS, RCE, traversal, SSRF) — and the Tier-1 set grows by **adding oracles**. **Tier-2** is open-ended: from a small set of composable primitives — differential comparison, the egress proxy, the DOM oracle, the sink hooks, timing, response/state diffing, and the model's own assertion scripts — the model builds a bespoke check for whatever it suspects (CSRF, open redirect, business logic, IDOR variants, info leaks…). So capability is not a finite menu: it is a toolkit whose reach is *the model's ability to compose a demonstration*. Growth happens on both axes — **promote** a common Tier-2 pattern into a hardened Tier-1 oracle over time.

**P4 — Static is a hint; dynamic is truth.**
Static analysis (slicing, taint, symbolic solving) is fast, cheap, and *unsound on real dynamic-language code*. We therefore use it **only to focus attention** — to tell the model where to look. We never let it *decide* anything and we **never hard-prune** a path based on a static result, because a wrong static prune silently deletes a real vulnerability that the dynamic oracle could have caught. Static narrows; dynamic proves.

**P5 — The model is an agent, not a function.**
A senior pentester does not answer in one shot — they *try, observe the real result, adjust, chain, and retry*. The model is given a sandbox (hands), a search engine (lookup), episodic memory (notebook), and a **closed-loop feedback cycle**, and is allowed to work a target across many turns until an oracle confirms or a budget is exhausted. This closed loop — not any single prompt — is where complex-vuln capability comes from.

---

## 2. System overview

```
                         ┌──────────────────────────────────────────────┐
                         │              ORCHESTRATOR                     │
                         │   asyncio state machine · VRAM serialization  │
                         │   phase control · budget & guardrails         │
                         └───────────────┬──────────────────────────────┘
                                         │ drives
     ┌───────────────┬──────────────────┼───────────────────┬───────────────────┐
     ▼               ▼                  ▼                   ▼                   ▼
┌─────────┐   ┌──────────────┐   ┌───────────────┐   ┌──────────────┐   ┌──────────────┐
│ BRAIN   │   │ PERCEPTION   │   │  SANDBOX      │   │ ORACLE       │   │ MEMORY +     │
│ 14B via │   │ (hints only) │   │  (WSL2/Docker)│   │ CATALOG      │   │ SEARCH       │
│ vLLM    │   │ LSP+TS slice │   │ boot+seed+    │   │ instrumented │   │ DuckDB +     │
│ decides │   │ routes,surf. │   │ instrument    │   │ sink · diff  │   │ SearXNG      │
└─────────┘   └──────────────┘   └───────────────┘   │ · sanitizer  │   └──────────────┘
     ▲                                                └──────────────┘
     └──────────────── closed agentic loop: observe → reason → act → observe ─────────┘
```

- **Brain** — DeepSeek-R1-Distill-Qwen-14B, `Q4_K_M`, served by vLLM (~8.5 GB weights, ~4 GB KV cache for prefix-cached parallel hypotheses, ~3.5 GB headroom). Optionally a small fast non-reasoning model (e.g. Qwen2.5-7B-Instruct) for cheap triage; the 14B for hard reasoning, exploitation, and patching. Only one model resident at a time.
- **Perception** — deterministic, millisecond-scale. Produces *hints*: the route table, an attack-surface list, and a best-effort code slice per candidate (LSP-backed, §4). **Never authoritative** (P4).
- **Sandbox** — the target booted under Docker Compose on WSL2, instrumented, and **seeded from a per-target fixture with multi-user data** (§6).
- **Verification toolkit** — the crux (§5). Tier-1 pre-built oracles (proven) + Tier-2 model-composed checks (demonstrated). Capability lives here (P3).
- **Memory + Search** — DuckDB episodic memory (never repeat a failed vector) and a woken-on-demand SearXNG (look up a cryptic framework error like a human googling).

**Two operating modes over the same loop.** **Mode 1 (grey-box SAST + fix)** — §§3–15, the default: has the source, boots and instruments the app, finds and *fixes*. **Mode 2 (black-box DAST)** — §16, optional Phase 2: given only a URL, acts as an external pentester with the verification swapped to external oracles. Same agentic loop; different perception + oracle set.

---

## 3. The agentic loop (the heart of the system)

This is the piece the previous plans lacked. Everything else exists to feed this loop.

For each candidate the loop runs a **ReAct-style cycle** until an oracle confirms, the budget is spent, or the agent gives up (→ defer):

```
loop until (oracle CONFIRMS) or (budget exhausted) or (agent DEFERS):
    OBSERVATION  = bundle(
                      last HTTP response (status, headers, body, timing),
                      sink log (did any tracer reach a sink? in what position?
                                + the sink call-site file:line, captured by the hook — see §5.5),
                      OTel span context (HTTP + DB boundaries ONLY — not internal lines; §5.5),
                      app stderr (stack trace / ASan dump if any),
                      the State Ledger for this target ([persona]->[resource]->[IDs]; §6),
                      relevant DuckDB memories for this framework/class,
                   )
    THOUGHT       = model.reason(candidate slice, routes, OBSERVATION, history)
    ACTION        = model.choose one of:
                      • execute_probe(...) — the unified probe wrapper: an HTTP request OR a
                        browser-rendered probe (method/path/headers/body it composes itself).
                        Server-side classes fire HTTP; client-side classes (XSS) route through a
                        headless browser so the DOM oracle can witness execution (§5.6).
                      • run a multi-step sequence (create → capture id → mutate → trigger)
                      • store_artifact(key, value) — pin an exact string (a returned path,
                        token, or id) into the summarization-EXEMPT working-state, so it
                        survives context compaction and can be reused turns later (§ below)
                      • compose_check(hypothesis, steps) — for a class with NO pre-built oracle,
                        assemble a verification from toolkit primitives (differential / egress proxy /
                        DOM / sink hooks / timing / response+state diff / a self-written assertion),
                        run it, and if it demonstrates the exploit emit a Tier-2 finding + confidence
                      • ask SearXNG about an error string it doesn't understand
                      • request a different oracle be checked
                      • declare a finding — Tier 1 ("proven", oracle-backed) or Tier 2
                        ("demonstrated", compose_check-backed, carries confidence) — or "defer"
    EXECUTE(ACTION) → wait for async sinks to settle (§6 eager-mode + sink_flush_timeout),
                      then produces the next OBSERVATION
    record(THOUGHT, ACTION, OBSERVATION) into working memory
```

Key properties:

- **Stateful, multi-request exploitation.** Complex vulns are almost never one request. The action space includes *building state* (register users, create resources, capture returned IDs, then attack), which is where IDOR/logic/chained bugs live. The prior plans' "fire one payload" model cannot reach these.
- **The observation is rich and legible.** The quality of an agentic loop is bounded by the quality of what it can see each turn. We deliberately fuse HTTP + sink log (with call-site line) + OTel span + stderr + State Ledger + memory into one bundle so the model reasons on *ground truth*, not guesses.
- **The oracle is inside the loop, not after it.** "Declare proven" is only honored if an oracle witnessed it (P2). The model can *believe* it succeeded; the loop believes the oracle.
- **Convergence guardrails (anti-spinning), two independent signals:**
  1. **Two-dimensional canonicalized hash (primary, feedback-independent).** A single hash can't work: mask the payload strings and legit fuzzing (`admin' OR 1=1--` → `admin' OR 2=2--`) looks identical and gets killed after one try; keep the strings and a stuck model spins forever by incrementing a useless number past the threshold. So track **two hashes**, both computed after **canonicalization** (strip/blank high-entropy headers — `Authorization`, `X-CSRF-Token`, `Date`, HMAC sigs — and normalize dynamic UUIDs/timestamps to placeholders, or a refreshed CSRF/JWT alone would read as "novel"):
     - **Hash A — structural:** method + path template + sorted header/param keys (the *shape* of the request).
     - **Hash B — payload:** the injected exploit vector itself (edit-distance over the injected syntax).
     Backtrack rule: **if Hash A is identical across the last 3 attempts AND Hash B varies by <15%** (the model is only tweaking `1=1`→`2=2`), force a **hard backtrack** to a different hypothesis branch — *regardless of what the sink did*. This kills the "14B apology spiral" while still permitting genuine payload fuzzing on the same endpoint.
  2. **Sink-progress (secondary).** Did the tracer get *closer* to the sink, or did a new code path execute (per OTel/hooks)? Used to *reward continuing* a branch that is making measurable progress.
  Budget is *adaptive*: keep going while (2) shows progress and (1) shows genuine novelty; cut off when stalled — never a blind "3 tries" cap that would strangle genuinely hard vulns.
- **Breadth via prefix-cached branching.** vLLM prefix caching lets the model pursue 3–4 hypothesis branches sharing one context (cheap in VRAM). Breadth (branches) + depth (the loop) together = pentester behavior.
- **Everything learned is written to DuckDB** so the next candidate/target starts smarter.
- **Context budget & turn compaction (hard 16 GB constraint).** The math is unforgiving: Q4 weights ~8.5 GB + vLLM overhead ~1–2 GB leaves ~5.5 GB of KV cache ≈ **~20–30k tokens total** for a 14B. The observation bundle (HTTP + sink log + OTel + stderr + ledger + slice + history) can run 3–5k tokens/turn, so a naïve loop overflows by ~turn 5 → truncation (amnesia, which *breaks anti-spin*) or OOM. So context is split in two:
  - **Deterministic working-state (small, lossless, in the orchestrator — never summarized):** the two anti-spin hashes, the live State Ledger, tried-vector list, oracle results, current hypothesis branch, **and the artifact KV store** (below). The anti-spin and progress logic read *this*, so summarization can never corrupt them.
  - **Free-text context (summarized/compacted between turns):** prior thoughts and verbose observations. A deterministic compaction step trims LSP slices to the relevant span and DOM trees to the executing node, and summarizes older turns into a running brief, before the prompt is built. This keeps deep multi-step loops inside the KV budget.
  - **The artifact store solves "lost taint" (a compaction hazard).** A deterministic summarizer cannot tell a critical payload string from noise — e.g. Turn 1 uploads a file and the server returns an internal path `/tmp/blob_99xA.tmp` that Turn 2 must feed to a PDF endpoint to trigger LFI; a summarizer would drop it as low-semantic-weight, breaking the chain. So the model is given the `store_artifact(key, value)` action to *explicitly* pin exact ids/paths/tokens into the working-state, which is exempt from summarization — guaranteeing critical strings survive across deep exploitation chains.

---

## 4. Perception layer (hints, never verdicts)

Deterministic and fast, so the 14B only ever reads a small slice — *not* whole files (this is also the fix for the earlier scanning-speed problem: brute-reading the repo with the model is both slow and unnecessary).

- **Route/entrypoint extraction.** Per-framework route table `Route(method, path, file, handler)`: Connexion/OpenAPI, Express, NestJS, Flask, FastAPI. This is the SAST→DAST bridge — it tells the loop *what URL reaches a given handler*.
- **Attack-surface enumeration.** Rank files/handlers by proximity to known sink shapes and by taking untrusted input. This produces the *candidate list* the agentic loop will work through.
- **Best-effort interprocedural slice (a hint) — LSP-backed, not Tree-sitter alone.**
  Tree-sitter is a *syntactic parser only*; it cannot resolve data flow across files, because it has no semantic understanding of framework routing (FastAPI dependency injection, Express middleware chains, nested contexts). Relying on it alone gives near-zero slice recall beyond a single monolithic file. **So perception runs a Language Server (`pyright` for Python, `tsserver` for TS/JS) as the reference-resolution backend** — real go-to-definition / find-references across files — with Tree-sitter used only to parse and to extract the enclosing unit. From a candidate sink we walk backward toward untrusted sources across files via LSP references, assembling the ~30-line causal path.
  **Framework-aware AST walkers run *before* LSP (LSP alone is blind to framework magic).** LSP resolves standard language semantics but not runtime dependency-injection or reflective middleware: FastAPI's `def read_item(db = Depends(get_db))` and Express's `app.use(authMiddleware)` create causal links resolved *at runtime* that LSP cannot see, so the slice would truncate exactly at the framework boundary — losing the authorization logic that matters most. So lightweight per-framework walkers pre-process these constructs (link `Depends()` targets to their route, map middleware chains to their handlers) and feed **pseudo-references** into the LSP graph, bridging the gaps before slicing. This is per-framework work, on the same curation budget as routes and oracles.
  **Still explicitly best-effort:** even with the walkers, exotic reflective dispatch will slip through. That is fine — per P4 an incomplete slice costs a deferral, never a false result, and the dynamic oracle is the truth. **We do not invest in making static taint sound**; we invest in the loop and the oracles.

---

## 5. The Verification toolkit (the crux — capability lives here)

Per **P3**, confirmation runs in **two tiers**, and this section defines both.

### 5.0 Two tiers: pre-built oracles + model-composed checks
- **Tier 1 — pre-built oracles (§5.1–§5.6).** Hardened, audited, deterministic witnesses for the highest-value classes. Each answers *"did attacker input reach forbidden context at runtime?"* with a soundness argument. A pass here is **proven, zero-FP**. The Tier-1 set is an extensible registry — adding a class = adding an oracle with the same `(detect, instrument, witness_predicate)` shape (§5.4).
- **Tier 2 — model-composed checks (§5.7).** For anything without a pre-built oracle, the model *assembles* a verification from a small set of **composable primitives** and runs it live. A pass is a real runtime demonstration but is only as sound as the model's check design → **Tier-2 finding: evidence + confidence, human-reviewed, never auto-shipped.** This is what removes the fixed-catalog cap: the model is never limited in *what* it can hunt, only in *how strongly* a given result is guaranteed.

The composable primitives (shared by both tiers): the **differential comparator** (attacker vs victim vs baseline), the **L7 egress proxy**, the **DOM oracle**, the **sink hooks / DB proxy**, **timing**, **response- and state-diffing**, and a **model-authored assertion script** run against the live app. Tier-1 oracles are these primitives wired up and audited *for one class*; Tier-2 is the model wiring them up *ad hoc* for a class we didn't pre-build.

### 5.1 Instrumented-sink oracle — **injection** (SQL/NoSQL/command/template) — *built*
A per-sink observer logs the exact value reaching the sink **before execution**, tagged with a unique per-probe marker. The agentic loop places a benign tracer marker in the vector under test.
- **SQL:** marker appears in the **statement** (not in bound **params**) ⇒ injection proven. Marker in params ⇒ neutralized ⇒ safe.
- **NoSQL:** marker appears inside a `$where`/operator position (executable) ⇒ proven; as a plain field value ⇒ safe.
- **Command/template:** marker reaches `exec`/render context unescaped ⇒ proven.
- **Why sound:** we don't infer from a 500 or a guess — we *observe the value at the sink in an injectable position*. This survives URL-encoding and needs no crash.
- **Marker design (avoids the encoding false-negative trap).** Frameworks aggressively encode/serialize input, so a marker with special characters (`<wave_probe>`) may reach the sink HTML-/URL-/hex-/base64-encoded and defeat a naive string match — a silent false negative on deeply nested injections. So: (a) the marker is **high-entropy alphanumeric only** (e.g. `WAVE99X7A2`), nothing to encode; and (b) the sink observer does **multi-format matching** — it checks the raw marker *and* its common encoded equivalents (URL, HTML-entity, hex, base64) before declaring the sink clear.

> This **replaces** the prior plan's "crash/500 = confirmed" oracle, which was both unsound (500s happen benignly → false positives) and incomplete (successful/blind injection and IDOR return clean 200s → missed). Crash/500 is demoted to a *hint* the loop may act on, never a proof.

### 5.2 Differential-execution oracle — **authz / IDOR / multi-tenant** — *to build (high priority)*
The highest-value *complex* web class, and it has a clean, sound oracle. Requires **two seeded personas** with distinct private data **and a (dynamic) State Ledger of their resource IDs** (§6) — because the attacker context cannot test IDOR unless it *knows the victim's exact resource ID* (a UUID is unguessable). The ledger is kept live: resources the loop *creates* mid-run are attributed to the acting persona and appended in real time, so stateful IDOR (create-as-A → read-as-B) has ground-truth ownership too. The loop reads the live ledger, then performs the same operation as *attacker* and as *victim*:
- If the attacker context can read/modify the victim's resource (unauthorized state == authorized state) ⇒ **IDOR/authz bypass proven.**
- **Why sound:** it's a direct behavioral comparison against ground-truth ownership, not an inference. Ground-truth IDs from the ledger make the test deterministic even under unguessable identifiers.

### 5.3 Sanitizer oracle — **memory corruption / races** — *deferred (compiled targets only)*
Build the target with `-fsanitize=address,undefined` (and TSan for races); a crash dump on Docker stderr is the witness. Only meaningful for compiled code — **out of scope for the web MVP**, listed for completeness.

### 5.4 The extension pattern (how capability grows)
Every new class ships as `Oracle(detect, instrument, witness_predicate)`:
- `detect` — does this target use the relevant driver/surface?
- `instrument` — inject the hook/observer at build/boot.
- `witness_predicate` — the deterministic test that a tracer reached forbidden context.
Candidates to add next: **path traversal** (eBPF `openat` — did the resolved path escape the intended root?), **RCE/command injection** (eBPF `execve` — did an attacker string spawn a process?), **SSRF** (L7 egress proxy — did the app dial an attacker-chosen host? — *not* eBPF, see §5.5), **deserialization/SSTI** (user-space hook on the object/template evaluation — see §5.5). The two syscall classes share one eBPF module; SSRF shares the egress proxy; each interpreter-level class is a self-contained hook.

### 5.5 Instrumentation strategy & localization (answering "wrappers vs proxy", and the OTel line-number problem)
Two placement mechanisms, chosen by sink type — a deliberate **hybrid**:

- **Network-boundary sinks (DB queries, outbound HTTP) → a transparent protocol proxy.** Put a small proxy between the app and Postgres/Mongo/etc. The PostgreSQL extended-query protocol cleanly separates the prepared statement (`Parse`) from bound parameter values (`Bind`), so the proxy can apply the exact same "marker in statement, not in params" predicate — **driver- and language-agnostic**. One Postgres proxy covers psycopg2, SQLAlchemy, node-postgres, Go `pq`, etc., collapsing the per-driver curation cost for the entire DB-injection class. (Caveat: MySQL text-protocol clients that do client-side param substitution put params *in* the statement — there the proxy can't distinguish, and we fall back to an in-process hook; noted as an open risk.)
  - **Request↔query correlation (query-comment tagging).** A transparent TCP proxy has no HTTP context: under concurrency (the loop plus the app's own background traffic) it sees a *stream* of queries and, on spotting the marker, cannot tell *which* HTTP request produced it — breaking attribution of the finding to a candidate. Fix: at the ORM/driver level (part of the instrumentation shim), append the current **OTel Trace-ID as a SQL comment** to every outbound query (`SELECT ... /* traceparent: 00-0af76... */`). The proxy reads the comment and hands the Trace-ID back to the orchestrator, correlating the sink violation to the exact request. (This means the proxy is *statement*-agnostic but relies on a small per-language comment-injector — a caveat to the "fully language-agnostic" claim.)
- **In-process sinks (`eval`/`exec`/`subprocess`, file `open`) → native runtime audit hooks (not AST-rewrite).** There is no network to proxy. Rather than rewriting the AST (brittle under aliasing — `f = os.system; f(x)`), we use the language's *native security hook*, which fires no matter how the sink was aliased or dynamically invoked:
  - **Python:** `sys.addaudithook()` (PEP 578) — a C-level hook that natively intercepts `exec`, `eval`, `os.system`, `subprocess`, and `open`. The hook logs the tracer and walks the stack for the exact call-site.
  - **Node.js:** `async_hooks` plus monkey-patching the core `child_process` and `fs` modules at the V8 level *before the app imports anything* (via the `--require` shim).
  This captures the call-site (file:line) for localization and is robust to aliasing. (Sinks with no native audit event — e.g. some template engines / SSTI — still need a targeted per-engine hook; tracked in §14.)
- **Syscall-eBPF + user-space hooks are COMPLEMENTARY (decided — adopt both, per role).** Neither mechanism alone is complete; each is blind exactly where the other sees, so the execution/FS/egress oracles use both:
  - **Syscall-eBPF owns RCE + path traversal (NOT SSRF).** A kernel eBPF module on `execve` and `openat` is a single, **language-agnostic, un-bypassable** witness for **RCE-via-process-spawn and path traversal** — across Python, Node, Go, Rust, and native extensions at once (a compiled-language web app can't be covered by user-space hooks at all). These two classes map cleanly to OS process/file state, so eBPF is exact. Feasible on WSL2: containers share the WSL2 kernel and modern WSL2 kernels support BPF. (Note: this narrowly revisits `answer.md`'s eBPF rejection, which was about *memory-fault* tracing inside a guest VM — a different, harder case than syscall tracing.)
  - **SSRF uses a Layer-7 egress proxy, NOT eBPF.** eBPF `connect` is Layer 4 — it sees a TCP connect to an IP, but SSRF is a Layer-7 (HTTP/URL) concern. With connection pooling / HTTP keep-alive the malicious request multiplexes over an already-open socket, so **no new `connect` syscall fires** and eBPF is blind; L4→L7 correlation back to the triggering request is also unreliable. So SSRF is witnessed by a **transparent L7 egress proxy** (MITMproxy/Envoy) set as the container network's default gateway: it terminates TLS (via the Root-CA injection of §6), parses the outbound URL, and checks whether the app dialed an attacker-chosen host / the tracer marker. This reuses the proxy + CA machinery already in the plan.
  - **User-space audit hooks own what eBPF cannot see.** In-interpreter execution — Python/JS `eval`/`exec`, template render (SSTI) — runs inside the interpreter and **never makes a syscall**, so eBPF is blind to it; the PEP 578 / core-module hooks catch these. The hooks also provide the **call-site file:line** for localization, which eBPF (below the language) cannot.
  - **Threat-model note:** eBPF also gives the only real evasion resistance (payloads bypassing the stdlib via FFI), which is out of MVP scope (§0) but comes for free once eBPF is the execution oracle.
  - **Timing:** build order unchanged — steps 1–4 (injection, authz) use the DB proxy + differential oracle and need no eBPF; the eBPF module is built when the execution/FS/egress classes are (roadmap step 6).

**The OTel line-number illusion (Gap 1).** Standard OTel auto-instrumentation only wraps *network boundaries* (HTTP, DB, Redis spans); it does **not** give line-level granularity for internal calls like an `eval` or a formatting util deep in the code. So OTel is used only for **request/DB span context**, and **line-level localization comes from the oracle hooks themselves** (the call-site they capture at the sink) — not from OTel. This is why the observation bundle (§3) carries both: OTel for the boundary picture, hook call-site for the exact file:line to patch.

### 5.6 Client-side / DOM oracle — **XSS (reflected & DOM-based)** — *to build*
Client-side XSS executes entirely in the browser: the agent sends a payload, the backend returns a clean `200` with HTML, and **no backend hook fires** — so without a browser in the loop the system is blind to the entire client-layer class. The DOM oracle closes this: the unified `execute_probe()` action (§3) routes client-side probes through a **headless browser (Playwright)** with a pre-registered JS execution sink — `page.exposeFunction('xss_oracle', ...)` plus hooks on `alert`/`eval`/script execution. If the injected payload actually executes in the rendered DOM, the browser calls back into the oracle → **XSS proven**; the callback (with the executing payload) enters the observation bundle. **Why sound:** it witnesses real script execution in a real DOM, not a reflection heuristic.
**Resource serialization (mandatory).** Chromium is memory-hungry and will collide with Docker + vLLM(14B) on 16 GB / WSL2 → the Linux OOM-killer terminates vLLM or the browser. So XSS testing runs as its **own strictly-serialized sub-phase**: the 14B is offloaded/paused while the browser probes, and Chromium is launched constrained (JIT off, images off, single tab). The model plans the XSS probes *before* offload; the browser executes them headless; results feed back on the next 14B turn.

### 5.7 Tier-2 model-composed checks — **any class without a pre-built oracle**
When the model suspects a vuln the Tier-1 catalog doesn't cover (CSRF, open redirect, mass-assignment, a business-logic abuse, an info leak, a novel IDOR shape), it uses `compose_check` (§3) to build and run a demonstration from the primitives above. The pattern mirrors how a pentester improvises a PoC:
- **CSRF** → replay a state-changing request cross-origin without the token; the differential/state-diff shows the state changed → demonstrated.
- **Open redirect** → follow the `Location`; the egress/URL check shows an attacker-chosen host → demonstrated.
- **Business logic** (coupon twice, negative quantity) → the model writes an assertion script (apply twice, assert the price dropped twice) and runs it against the live app → demonstrated.
- **Info leak** → response-diff an authorized vs unauthorized fetch for fields that shouldn't appear → demonstrated.

Rules that keep Tier 2 honest:
- **It must run a real check** — a `compose_check` that *executed against the live app and observed the predicted effect*. A hypothesis the model can't demonstrate is a **defer**, never a finding.
- **Output is `{class, evidence, confidence, reproduction}`**, explicitly Tier-2, routed to **human review** — never auto-patched/auto-shipped, because its soundness rests on the model's own check design (false positives are possible here; that is the price of open-ended coverage).
- **Promotion path:** when a Tier-2 check for some class proves reliable across many targets, harden it into a Tier-1 oracle. This is how the catalog grows *from real usage* rather than up-front guessing — a lightweight, practical form of oracle synthesis.

> **Honest ceiling (state this to the reviewer):** the model may hunt anything (Tier 2), so it is **not** limited to a fixed class list. The real ceiling is now twofold: (a) **Tier-1 soundness** is absolute only for the pre-built oracles; (b) **Tier-2 reach** is bounded by whether the model can *compose a runtime demonstration* from the primitives — a class whose exploit leaves no observable runtime effect the primitives can capture still can't be confirmed (→ defer). "Complete for the catalog, best-effort-with-evidence beyond it, never a confident lie."

---

## 6. Environment, seeding & sandbox

- **Provisioning by compose-merge.** Reuse the target's own `docker-compose.yml` for build + DB + dependencies; merge in our instrumentation rather than reinventing the environment. Python: bind-mount hooks + `sitecustomize`/`PYTHONPATH`. Node: `NODE_OPTIONS=--require`. Health-gate before testing.
- **Instrumentation injection.** Attach the DB/egress **proxy**, register the **native audit hooks** (§5.5), and add OTel boundary instrumentation before boot. ASan only for compiled targets.
- **Async-worker sinks: timeout-wait by default, NOT eager-mode.** In queue-backed apps (Celery/RabbitMQ/Redis/Kafka) a vulnerable sink often fires *seconds later in a worker process*: the HTTP call returns `202` in 50 ms, so the loop must not read the sink log immediately. **Primary mechanism (async-preserving):** after each action `EXECUTE` waits a configurable **`sink_flush_timeout`** (e.g. 2 s) for cross-process spans to resolve before closing the observation bundle. **Eager-mode is NOT the default** — forcing `CELERY_TASK_ALWAYS_EAGER` flattens execution to synchronous and *engineers the vulnerable time-window out of existence*, giving **zero recall on race/TOCTOU and async state-machine bugs** (you'd be testing a synchronous mutant of the app). Eager-mode is therefore an **opt-in for pure injection triage only**, and is **forbidden on the T4/T5 (logic/race) tiers**, which depend on real temporal gaps.
- **Custom Root CA injection (required for any TLS-terminating proxy).** A transparent egress/DB proxy must terminate TLS to read the URL/statement — which makes strict HTTPS clients (AWS SDK, Stripe, pinned clients) throw `CERTIFICATE_VERIFY_FAILED` and break the app *before testing starts*. So at build time the orchestrator injects the proxy's self-signed Root CA into the container's trust store: `update-ca-certificates` (Debian/Alpine) for OS-level clients, and `NODE_EXTRA_CA_CERTS` for Node. Without this the SSRF/egress oracle can't run. (Certificate *pinning* that ignores the system store defeats even this — logged in §14.)
- **Seeding is a required per-target fixture — NOT autonomous (revised per review).** Autonomously generating realistic multi-tenant state via a 14B is a separate research project (autonomous QA generation); gating the vuln loop on it would stall the project. **The MVP demands a `seed_db.py` or a SQL dump per target**, provided as an input alongside the repo. Autonomous seeding is a later nice-to-have, never a blocker.
- **The fixture must emit a State Ledger (required for 5.2):** a machine-readable map `[persona] -> [resource type] -> [resource IDs]`, plus each persona's credentials. This ledger is injected into the loop's observation block (§3) so the model has the *exact* victim UUIDs to target for IDOR and knows every persona's owned resources.
- **The State Ledger is DYNAMIC, not read-only (required for stateful T5 IDOR).** Complex vulns often need the agent to *create* state first — act as User A, `POST /api/invoices`, receive a fresh `inv_99812`, then switch to User B and try to read it. That new ID is not in the seeded ledger, so a static ledger would leave the oracle with no ground-truth owner and the differential test would silently fail to validate. Therefore the orchestrator maintains the ledger live, with two sources — and the DB source is authoritative:
  - **Primary — DB-proxy `INSERT` watching (ground truth).** HTTP scraping breaks on async creation: a `POST /api/report` may return `202 + job_id` while the real `report_id` UUID is written seconds later by a background worker — scraping the response would store the *job* id and the oracle would test the wrong resource (false negative). So the orchestrator uses the DB proxy (§5.5) to watch `INSERT`s carrying the acting persona's Trace-ID comment and reads the returned primary key (`INSERT ... RETURNING`, or the driver's last-insert-id). This captures the true UUID regardless of whether the HTTP response ever echoed it or a worker generated it.
  - **Secondary — HTTP response scraping** (`201`/`Location`/body) as a fast path when creation is synchronous and REST-compliant.
  Ownership is attributed to whichever persona's token issued the creating request; the oracle always reads the *live* ledger.
- **Auth fixture synthesis (multi-user).** The model writes a standalone script that registers/logs-in **each** persona and returns their tokens; the orchestrator runs it, feeds back errors until it succeeds, and hands the tokens (and the ledger) to the loop. (The differential oracle needs ≥2 personas.)
- **Reset strategy — filesystem, not just DB (Gap 4).** A payload can pollute more than the DB: a file-upload/path-traversal probe can drop a webshell into `/app/uploads`, which `docker compose restart db` does nothing about. So: **mount all writable directories as `tmpfs`** (ephemeral, wiped on container restart) and, when a probe is classified FS-destructive (upload/write/traversal), **trigger a full container teardown+reboot** rather than a DB-only reset. DB-only reset (restart / SQL-dump restore, 2–4 s) remains the fast path for DB-only probes; full teardown is the correct-but-slower path for FS-mutating ones. No 5 ms-snapshot fantasy.
- **LocalStack** only when the target actually uses AWS services (parsed from IaC). Otherwise skipped.

---

## 7. Exploitation (model-driven, stateful, iterative)

Handled *inside* the agentic loop (§3). The model — not hand-coded heuristics — reads the slice + routes + live observations + State Ledger and composes requests, choosing the vector (path/query/body/header) and building multi-step state itself. The **grey-box seed** (§8) is an *optional first shot* when symbolic analysis produced a payload; otherwise the loop starts from the model's own hypothesis. There is no assumption that a symbolic payload exists (for web targets it usually won't).

---

## 8. Symbolic assist (optional accelerator, never the main path)

- The model writes **high-level `@pre`/`@post` contracts** (not raw Z3); **CrossHair** (Python) / **angr** (native) compiles them to Z3 and, if `SAT`, produces an exact byte payload written to the ledger.
- **Scoped honestly:** CrossHair symbolically executes *pure* functions. Real web handlers are I/O-heavy (DB, network, framework magic) and are **not** analyzable this way. So this leg fires usefully only on isolated computational guards (an integer/length check, a token/HMAC comparison, an offset calc). For most web routes the symbolic payload is **empty**, and that's expected.
- **Never hard-prune (P4).** A `SAT`/`UNSAT` result may *reorder* or *seed* the loop; it may **never delete** a candidate, because the contract translation is unsound (~27% OOD in our own spike). Z3 hangs are capped (2 s) and fall back to the loop.

---

## 9. Remediation (choke-point patching + functionality-preserving dual-gate)

- **Tier gates what auto-remediates.** **Tier-1 (proven)** findings enter the automatic patch + dual-gate loop below. **Tier-2 (demonstrated)** findings are written up as a report — class, evidence, confidence, reproduction steps — and routed to **human review first**; the agent *may* draft a candidate patch, but a Tier-2 fix is never auto-shipped, because Gate A's re-check for a Tier-2 vuln is itself a model-composed check (only as sound as its design). Auto-remediation soundness therefore inherits Tier-1's guarantee only.
- **Choke-point patching.** The model receives the taint slice + the sink call-site + the proven request, and emits a **unified diff** that may span files (fix at the entry, at the sink, or both). Where multiple routes converge on one vulnerable utility, cluster by sink node and patch once (dedup).
- **Code + dependency patches, but no schema migrations.** Two distinct axes, handled oppositely:
  - **Dependencies are allowed (and required).** Many real fixes need a library the repo doesn't yet have — XXE → a safe XML parser, XSS → `DOMPurify`/`bleach`. A code-only diff that `import`s an uninstalled module crashes Gate B with `ModuleNotFoundError` and pushes the model toward writing dangerous hand-rolled regex sanitizers. So the model **may emit multi-file diffs that edit dependency manifests** (`package.json`, `requirements.txt`, `go.mod`); the orchestrator intercepts manifest edits and runs an ephemeral `npm install`/`pip install` **before** Gates A and B.
  - **Schema migrations are deferred.** A code diff that assumes a new column/wider field desyncs the DB → boot crash → Gate B fails permanently. The remediation prompt states: *"You may edit code and dependency manifests, but you may NOT execute database migrations. If the fix requires a schema change, DEFER with reason 'Schema migration required'."* A clean deferral, never a boot-breaking patch (P2).
- **Atomic code + data reset (prevents rollback contamination AND state desync).** A rejected patch must be reverted *perfectly*, or attempt 2 lands on top of attempt 1's broken code. But resetting **code alone is not enough**: running Gate A/B for the failed attempt mutated the app's *state* (rows inserted, a test user deleted, a state machine advanced), so attempt 2's Gate B would be non-deterministic — failing because of attempt 1's mutations, not the new patch. So the reset is atomic across **both**: (a) code — `git commit -am baseline` before the first patch, then `git reset --hard baseline && git clean -fd` on any Gate failure, plus clearing `__pycache__`/build caches; **and** (b) data — the same **teardown+reboot / DB-restore protocol from §6** fires alongside the git reset, rolling the database back to the pre-attempt snapshot. Code and data are restored together or Gate B is meaningless.
- **Dual-gate verification (corrected against the "lazy patch" loophole, Gap 3).**
  - **Gate A — exploit closed:** re-fire the *exact* proven request; the oracle must now report **not proven** (the marker no longer reaches the sink / the differential no longer leaks).
  - **Gate B — no regression AND feature preserved, on the exact patched route.** *Not* "100% unit tests pass" (real repos are flaky/failing/testless), and *not* a generic "homepage still loads." A 14B will happily satisfy Gate A by making the route return `403` to *everyone* — destroying the feature. So Gate B **must exercise the exact patched route as the legitimate owner** and assert the positive contract:
    - the resource owner (e.g. User B) **can still** perform the legitimate operation (read/modify their own resource), **and**
    - the attacker (User A) **still cannot** — i.e. Gate A's block is *specific*, not a blanket denial.
    Plus the broader baseline-diff: capture the test result + a set of benign requests *before* patching; require **no new failures** afterward. Reject any patch that breaks boot/health.
  - **Honest scope of Gate B (it is not "feature preserved").** Replaying a handful of benign requests only proves *those* requests still work — a patch that breaks HTML export but not the CSV export of the same route passes if the baseline only exercised CSV. Without a comprehensive E2E suite (which most targets lack) Gate B **cannot** prove full functional preservation. So we (a) **broaden the baseline as far as available evidence allows** — every input variation / content-type / parameter combination observed in the app's own tests, its OpenAPI examples, and the traffic seen during exploitation; (b) **prefer minimal, low-risk patch shapes** at the choke point (parameterize the query, encode the output) over broad rewrites, and **flag high-risk shapes** (regex sanitizers, object-stripping) for reduced confidence; and (c) **scope the guarantee honestly**: a passed Gate B means "no regression *on observed behavior*," not "no regression ever." Autonomous patches are surfaced for **human review** before merge, carrying their confidence and the exact behaviors verified.
- Only when both gates clear is the patch logged as **verified** in DuckDB. Otherwise the patch is rejected and the loop may retry or defer — **a bad patch is never shipped** (P2).

---

## 10. Memory & learning (DuckDB)

Persistent episodic ledger queried before every prompt and written after every loop:
- failed attack vectors (never repeat them on this target/class),
- framework mitigations learned ("PyJWT ≥ 2.0 blocks alg-confusion"),
- successful exploit techniques per (framework, class) for reuse,
- per-target personas, tokens, and the State Ledger of resource IDs.
This is the "experience" that separates a returning agent from a cold one.

---

## 11. Search (SearXNG, woken on demand)

Kept asleep to save RAM. When the loop hits a *cryptic framework error* it doesn't understand (a `Pydantic` crash, an obscure ORM exception), the orchestrator queries a local SearXNG container with the exact error string, feeds the top few developer explanations back to the model, then shuts it down. The insight is cached in DuckDB. This is the model's "google it" reflex — a weakness-mitigation, not a decision-maker.

---

## 12. Resource serialization (16 GB reality)

Aggressively serialized to avoid WSL2 OOM:
- **Perception/SAST:** deterministic tools (LSP + Tree-sitter) + (optional) fast triage model run; 14B loads only for slice reasoning.
- **Build/boot:** 14B unloaded from VRAM; Docker Compose (+ LocalStack if needed) + proxy + OTel boot.
- **DAST loop:** 14B reloaded; SearXNG spun up only on an error, then down.
Only one model resident at a time; the orchestrator owns lifecycle.

---

## 13. Evaluation harness & benchmark (how we *prove* it works — build this FIRST)

The previous plans had no way to demonstrate complex-vuln capability; a passing hand-run on VAmPI's easy SQLi proves almost nothing. This is built **before** the loop, so every subsequent change is measured against the real goal.

- **A graded target set**, tiered by difficulty: (T1) direct single-file injection; (T2) cross-file handoff injection; (T3) auth-gated injection; (T4) IDOR/authz; (T5) stateful/chained/logic. Sourced from known-vulnerable apps (VAmPI, NodeGoat, brokencrystals, DVWA-class, Juice Shop, plus a few hand-authored to fill gaps), each shipped with its **per-target fixture + State Ledger** and annotated with ground-truth vuln locations and classes.
- **Metrics, split by tier:**
  - **Tier 1 (proven):** recall (of ground-truth vulns, how many proven) and **precision — which must stay ~1.0 by construction**; any Tier-1 FP is a soundness bug in an oracle and gets fixed.
  - **Tier 2 (demonstrated):** recall *and* precision are both measured (FPs are expected here), plus **confidence calibration** — does a Tier-2 "0.8 confidence" actually correspond to ~80% true positives? This is the number that tells us whether Tier-2 findings are trustworthy enough for review triage.
  - Both: fix-success rate (finding → verified patch) and mean loop iterations / wall-clock.
- **Regression gate:** runs CI-style on every change. **Tier-1 precision must stay 1.0** (hard gate); Tier-1 recall may only rise; Tier-2 recall should rise and its precision/calibration must not regress. The benchmark also **feeds the promotion path** — a Tier-2 class that reaches high precision across targets is a candidate to harden into a Tier-1 oracle.

---

## 14. Known open risks (reviewer: start here)

Stated honestly so a reviewer can attack the real soft spots rather than rediscover them. (Items marked ✔ were resolved by the `reply.md` review and folded into the body.)

1. ✔ **Interprocedural slicing** — resolved: framework-aware AST walkers (DI/`Depends`, middleware chains) feed pseudo-references into LSP (`pyright`/`tsserver`) reference resolution; Tree-sitter is parser-only (§4). *Residual:* the walkers are per-framework work, and exotic reflective dispatch still degrades slice recall → deferrals.
2. **Oracle coverage is the capability ceiling.** MVP covers injection (built) + authz/IDOR (to build). SSRF/path-traversal/deser/SSTI/logic need their own oracles. Is the extension pattern (5.4) truly uniform, or will some classes resist a clean witness predicate?
3. ✔/⚠ **Open-ended coverage** — partially adopted as **Tier-2 model-composed checks** (§5.7): the model composes a runtime demonstration for classes with no pre-built oracle, so it is no longer limited to a fixed list. *Residual (the core Tier-2 risk):* Tier-2 soundness rests on the model's own check design → false positives are possible, so Tier-2 is confidence-scored and human-reviewed, never auto-shipped. Open question: how well-calibrated is a 4-bit 14B's confidence, and how good is it at composing a *valid* check (vs one that looks like it passed)? This is the make-or-break for the two-tier model and must be measured hard on the benchmark (§13).
4. **Stateful exploitation depth.** The loop supports multi-step state, but very deep chains (5+ dependent requests) may exceed the model's planning reliability. Where's the practical ceiling, and does episodic memory + the State Ledger meaningfully raise it?
5. **Symbolic leg may rarely fire on web targets.** If CrossHair almost never produces a payload for I/O-heavy handlers, is the leg worth its complexity for the web MVP, or should it be deferred entirely until compiled targets are in scope?
6. ✔ **Convergence detection** — resolved: State-Space Hash on the request AST forces backtrack independent of sink feedback, defeating the apology spiral (§3). *Residual:* the 90%/last-3 thresholds need empirical tuning against the benchmark.
7. ✔ **Seeding realism** — resolved: seeding is a required per-target fixture (`seed_db.py`/SQL dump) emitting a State Ledger; autonomous seeding is explicitly *not* a blocker (§6).
8. **14B reasoning quality under 4-bit + 250 W.** The whole agent rests on the 14B's ability to reason over slices and observations. If quantized reasoning is too weak for T4/T5 tiers, the fallback is a better teacher/model, not more scaffolding.
9. **DB proxy protocol coverage.** The transparent proxy cleanly separates statement/params for the PostgreSQL extended protocol; MySQL text-protocol clients doing client-side substitution defeat it, forcing an in-process fallback. *TLS resolved* via Root-CA injection (§6). *Residual:* MySQL text-protocol needs the in-process fallback maintained in parallel; which target DBs are in scope?
10. ✔ **In-process sink instrumentation** — resolved: native audit hooks (`sys.addaudithook`/PEP 578 for Python; `async_hooks` + core-module patch for Node) replace AST-rewrite and are alias-proof (§5.5). *Residual:* sinks that raise no native audit event (some template engines → SSTI) still need a targeted per-engine hook.
11. **Dynamic-ledger ownership attribution (new).** The live ledger attributes a created resource to the persona whose token issued the `POST`, reading the ID from `201`/`Location`/body. This is heuristic — APIs return IDs inconsistently (nested body, no `Location`, async creation) and ownership isn't always the creator. Mis-attribution could make the IDOR oracle validate against the wrong owner. How robust must ID-extraction be, and should the oracle re-confirm ownership independently before declaring a bypass?
12. **Certificate pinning that ignores the system trust store (new).** Root-CA injection (§6) satisfies clients that honor the OS/Node store, but a client with hard-pinned certificates defeats the egress proxy entirely — that target's SSRF/egress oracle can't run and must defer.
13. ✔ **Eager-mode temporal destruction** — resolved: `sink_flush_timeout` is now the default and eager-mode is forbidden on T4/T5 (§6), so async race/logic recall is preserved. *Residual:* `sink_flush_timeout` trades wall-clock per turn; on very slow workers the timeout may need to be adaptive.
14. ✔ **DOM oracle resource collision** — resolved: XSS runs in its own serialized sub-phase with the 14B offloaded and a constrained Chromium (§5.6, §12). *Residual:* even constrained, Chromium peak RAM on heavy SPAs may still pressure WSL2 — needs empirical headroom testing.
15. **Query-comment tagging coverage.** Correlation (§5.5) needs a per-language ORM/driver interceptor to inject the Trace-ID comment; ORMs that strip comments, use prepared-statement caches, or batch statements may drop or misattach it. How many stacks need a bespoke injector before the "language-agnostic proxy" advantage erodes?
16. **Context-window compaction fidelity (new).** Turn compaction (§3) keeps anti-spin/ledger state deterministic and lossless, but summarizing free-text history risks dropping a detail the model needed to chain a deep T5 exploit. How lossy can compaction be before multi-step planning degrades — and does the deterministic working-state carry enough to compensate?
17. **Gate B cannot prove feature preservation (new, fundamental).** Even with a broadened baseline (§9), absent an E2E spec Gate B only certifies observed behavior. Silent regressions in unobserved code paths remain possible; this is why autonomous patches are surfaced for human review, not auto-merged. Is human-in-the-loop-on-patch acceptable for the product goal, or is a synthesized-E2E-suite phase warranted?
18. ✔ **Execution/FS/egress oracles — mechanism per class** (§5.5): syscall-eBPF (`execve`/`openat`) owns **RCE + path traversal** language-agnostically; **SSRF uses an L7 egress proxy** (eBPF `connect` is L4-blind under keep-alive); user-space hooks own in-interpreter `eval`/`exec`/SSTI + call-site localization. Built at roadmap step 6. *Residual:* verify BPF is enabled on the WSL2 kernel and that eBPF can attribute a syscall to the target container/request.
19. **Async ground-truth ledger via DB proxy (new).** The ledger now reads created IDs from `INSERT`s tagged with the persona's Trace-ID (§6) to survive async creation. *Residual:* depends on capturing the returned primary key (`INSERT ... RETURNING` / last-insert-id) and on the Trace-ID comment surviving to the `INSERT` — some ORMs batch or defer writes, and ownership still = creator (not always true).
20. **Artifact-store discipline (new).** `store_artifact` (§3) only preserves what the model *chooses* to save; if it fails to recognize a string as load-bearing, compaction still drops it. How reliably does a 4-bit 14B use the action, and should the compactor also heuristically retain high-entropy tokens/paths as a backstop?
21. **L7 egress proxy coverage (new).** The SSRF proxy (§5.5) needs TLS termination (Root-CA, §6) and clean gateway routing; raw-socket clients, non-HTTP egress, or DNS-rebinding-style SSRF may slip past an HTTP-aware proxy. Which egress protocols are in scope for the MVP?
22. **Black-box OAST reachability (Mode 2, new).** The strongest black-box witness (§16) needs the target to reach a *public* canary server; egress-filtered or air-gapped targets never call back, so blind SSRF/RCE/XXE drop to Tier-2 inference or defer. Is a hosted canary in scope, and what's the fallback when egress is blocked?
23. **Black-box self-registration reliability (Mode 2, new).** Bootstrapping ≥2 accounts against an arbitrary live site (CSRF, email verification, CAPTCHA, 2FA, invite-only) is brittle; failure collapses Mode 2 to the unauthenticated surface — losing most IDOR/authz/logic reach. How often can a 14B actually complete a novel signup flow unaided?
24. **Non-destructive constraint vs recall (Mode 2, new).** Forbidding destructive probes on a production target hides classes that only manifest via mutation (stored XSS, IDOR-write, upload→RCE). These need a disposable/staging target to test safely — so "production, URL only" is inherently lower-recall than a staging mirror the agent may mutate.

**Change-log (v1 → v2, from `reply.md`):** LSP replaces bare Tree-sitter (§4); State-Space-Hash anti-spin added (§3); seeding made a mandatory manual fixture emitting a State Ledger (§6); State Ledger added to the observation bundle and to the IDOR oracle (§3, §5.2); OTel demoted to boundaries with line-level localization moved into the oracle hooks (§5.5); hybrid proxy-vs-in-process instrumentation strategy specified (§5.5); Gate B rewritten to require owner-functionality preservation on the patched route (§9); reset strategy extended to filesystem state via tmpfs/teardown (§6); two new open risks logged (9, 10).

**Change-log (v4 → v5, from `reply.md` round 4):** explicit **threat model** added (benign accidental-vuln apps; adversarial evasion out of scope) (§0); **context-budget/turn-compaction** pipeline added for the 16 GB KV limit, splitting deterministic working-state (lossless) from summarized free-text (§3); **eager-mode reversed** — `sink_flush_timeout` is now default and eager-mode is forbidden on T4/T5 so race/async recall survives (§6); **XSS/DOM oracle serialized** into its own sub-phase with the 14B offloaded + constrained Chromium (§5.6, §12); **Gate B honestly rescoped** to "no regression on observed behavior" with a broadened baseline, low-risk-patch preference, and human-review-on-patch (§9); risks 13–14 resolved, new residuals 16–18 logged.
**eBPF decision (resolved, §5.5, §5.4, §14 #18):** adopt syscall-eBPF (`execve`/`openat`/`connect`) as the language-agnostic oracle for RCE/traversal/SSRF, **complementary to** user-space hooks (which own in-interpreter `eval`/`exec`/SSTI + localization); built at roadmap step 6. *(Superseded in part by v6: SSRF moved off eBPF to an L7 egress proxy — see below.)*

**Change-log (v7 → v8, Black-box DAST mode — per owner intent, "operate like a real pentester, URL only"):** added **§16 Operating Mode 2 — Black-box DAST**: same agentic loop, external recon (crawl/JS-parse/fingerprint) replacing code-based perception, **self-service account registration**, and an **external oracle toolkit** (OAST out-of-band callback + our own headless browser + response/timing differential) replacing internal instrumentation; documented what black-box *loses* (no sink proof, no ground-truth ledger, no localization, no reset → non-destructive default); output is a **pentest report** (findings handed back to Mode 1 for fixes); roadmap step 8 (optional) and risks 22–24 added; framed Mode 2 as the optional post-production external check after Mode 1 secures code + infra.

**Change-log (v6 → v7, two-tier verification reframe — per owner intent, "don't cap what the model may hunt"):** reframed **P2** (grounded-in-two-tiers) and **P3** (capability = verification *toolkit*, not a fixed catalog) so the model may pursue *any* webapp vuln (§1); §0 success criteria split into Tier-1 *proven* (zero-FP) vs Tier-2 *demonstrated* (evidence+confidence+review); §5 renamed to **Verification toolkit** with §5.0 (two tiers), the composable-primitives set, and **§5.7 model-composed checks** (CSRF/open-redirect/business-logic/info-leak patterns, honesty rules, and a Tier-2→Tier-1 **promotion path**); added the **`compose_check`** action (§3); remediation now **auto-patches Tier-1 only**, Tier-2 → human review (§9); benchmark metrics split by tier with **Tier-2 confidence calibration** as a first-class number (§13); risk #3 reframed from "research" to "partially adopted, calibration is the make-or-break" (§14).

**Change-log (v5 → v6, from `reply.md` round 5):** **SSRF split off eBPF to a Layer-7 egress proxy** (eBPF `connect` is L4-blind under connection pooling) while eBPF keeps RCE+traversal (§5.5, §5.4); **dynamic ledger now reads ground-truth IDs from DB-proxy `INSERT`s** (Trace-ID-tagged) to survive async resource creation, HTTP scraping demoted to fast-path (§6); **`store_artifact(key,value)` action added** so exact payload strings survive context compaction in the summarization-exempt working-state (§3); **remediation reset made atomic across code AND data** — the §6 DB-restore fires with the git reset so Gate B stays deterministic (§9); **framework-aware AST walkers now pre-feed LSP** (DI/`Depends`, middleware) so slices don't truncate at the framework boundary (§4); new residuals 19–21 logged.

**Change-log (v3 → v4, from `reply.md` round 3):** async-worker sinks handled via eager-mode env vars + `sink_flush_timeout` (§6, §3); anti-spin upgraded to a *two-dimensional* structural+payload hash so fuzzing survives but spinning dies (§3); DOM/XSS oracle added via headless browser behind a unified `execute_probe()` action (§5.6, §3); remediation now permits *dependency-manifest* patches with an install step (still deferring schema migrations) (§9); *query-comment tagging* (OTel Trace-ID in a SQL comment) added to correlate proxy sink hits with the causing request under concurrency (§5.5); marker made alphanumeric with *multi-format encoded matching* to kill encoding false-negatives (§5.1); *strict git-baseline ephemeral checkout* between patch attempts prevents rollback contamination (§9); new residual risks 13–15 logged.

**Change-log (v2 → v3, from `reply.md` round 2):** State Ledger made *dynamic* — orchestrator appends loop-created resource IDs in real time so stateful T5 IDOR validates (§6, §5.2); State-Space Hash *canonicalized* — strip high-entropy headers/tokens + normalize UUIDs before similarity so CSRF/JWT refresh can't mask a spiral (§3); remediation constrained to *code-only patches* with a "schema migration required" deferral to avoid boot-crash regressions (§9); *Custom Root-CA injection* added so TLS-terminating proxies don't break strict HTTPS clients (§6); in-process instrumentation switched from AST-rewrite to *native audit hooks* (`sys.addaudithook`/`async_hooks`), resolving old Risk #10 (§5.5); risks updated — #9 TLS resolved, #10 resolved, new #11 (dynamic-ledger attribution) and #12 (certificate pinning) logged.

---

## 15. Build roadmap (dependency-ordered)

1. **Benchmark + eval harness (§13)** — with per-target fixtures + State Ledgers — so everything after is measured.
2. **Sound injection loop end-to-end** — the instrumented-sink oracle (hybrid proxy + in-process, §5.5) inside the *agentic loop* (§3): observe→reason→act→confirm, stateful, on T1–T3 targets. Tightest provable win; exercises the whole spine.
3. **Authz/IDOR** — differential oracle (5.2) + multi-user auth + fixture/ledger seeding (§6) → unlock T4, the first genuinely *complex* class.
4. **Remediation with the functionality-preserving dual-gate** (§9) across T1–T4.
5. **Stateful/chained/logic (T5)** — deepen the loop, lean on episodic memory + State Ledger + search.
6. **Expand the oracle catalog** (SSRF, path traversal, …) one reviewable unit at a time.
7. **Defer** the compiled pipeline (Joern CPG, ASan/TSan, angr) until a compiled target is actually in scope.
8. **(Optional) Operating Mode 2 — Black-box DAST (§16)** — reuse the loop with external recon + self-registration + the external oracle toolkit (OAST canary, our browser, differential/timing). Ships the pentest-report output. Built after Mode 1 is solid, since it inherits the loop, memory, and two-tier machinery wholesale.

---

## 16. Operating Mode 2 — Black-box DAST (external pentest, optional Phase 2)

Everything above (Mode 1) is **grey-box**: it has the source, boots and *instruments* the app, and finds + fixes. **Mode 2 is a separate, optional run that behaves like a real external pentester** — given **only a URL**, no source and no ability to instrument the target, it asks *"is the deployed application still exploitable from the outside?"* Run it **after** Mode 1 has hardened the code + infrastructure, as the final adversarial validation from an attacker's vantage point.

**Same agent, swapped verification.** Mode 2 reuses the entire agentic loop (§3) unchanged — observe→reason→act→confirm, the two-tier output, the two-dimensional anti-spin hash, episodic memory, context compaction, the artifact store. Only **perception** and the **oracle set** change.

### Intake & external recon (replaces §4 perception)
Input is a single URL + scope + explicit authorization. With no source, the agent builds its own attack surface: **crawl/spider** the site, parse client-side JS for API routes, fingerprint the stack (headers, error pages, framework tells), enumerate forms and parameters. This is the black-box equivalent of the route table — derived from the live app, not the code.

### Self-service auth (the agent makes its own accounts)
Like a real pentester, it finds the register/login flow by crawling, **creates its own accounts** (≥2 personas, for the differential/IDOR oracle), handles the flow (CSRF tokens, cookie capture), and bootstraps its own authenticated sessions. No fixture, no provided credentials. Where registration is gated (email/2FA/CAPTCHA), it degrades to the unauthenticated surface plus any credentials the operator chooses to supply.

### The external oracle toolkit (the swap)
No internal witness exists — you cannot instrument someone else's live app — so confirmation comes from *outside*, and it still splits across the two tiers:
- **OAST out-of-band callback (the strongest black-box witness → Tier 1).** The agent controls a public canary server (interactsh/Collaborator-style). Blind SSRF, blind command injection, blind XXE, some RCE are **proven** when the target's server connects back to the canary — the app *literally reached attacker-controlled infrastructure*, unambiguous.
- **Our own headless browser (XSS → Tier 1).** The DOM oracle (§5.6) works unchanged, because the browser is *ours*: script execution is witnessed directly.
- **Loot-in-response (path traversal/LFI → Tier 1).** `../../etc/passwd` contents reflected in the response is a direct witness.
- **Two-account differential (IDOR/authz → Tier 1 when clean).** Using its self-made personas, attacker-vs-victim access comparison.
- **Inferential signals (→ Tier 2).** Boolean/time-based blind SQLi (response-diff, `sleep()` timing), error-string leakage, reflected-payload heuristics — real but FP-prone → confidence-scored, human-reviewed.

### What black-box loses (state it honestly)
- **No instrumented-sink proof** → most SQLi drops from "marker-in-statement" (Tier 1) to timing/boolean **inference (Tier 2)**, unless errors or UNION reflect data.
- **No DB-proxy ground-truth ledger** → the State Ledger is built *only* from the agent's own actions + HTTP responses; IDs a background worker writes silently are invisible.
- **No line-level localization** (no source/hooks) → findings are external reproduction steps, not `file:line`.
- **No reset/teardown** → you cannot roll back a production database. So Mode 2 probes are **non-destructive by default** (no webshell uploads, no data-mutating payloads) unless the operator points it at a disposable/staging target. A real pentester exercises the same restraint.

### Output & handoff
Not patches (there's no source here) — a **pentest report**: per finding, its class, tier (proven/demonstrated), confidence, evidence, and reproduction steps. If the operator wants fixes, a finding is handed back to **Mode 1 (SAST)**, which has the source, to remediate + dual-gate.

### Safety & authorization
Mode 2 runs **only against targets the operator is authorized to test**; it honors scope, rate-limits, and defaults to non-destructive probes. It is an authorized-pentest tool, not an open attack tool.

---

## 17. Build discipline & de-risking (read before writing any code)

This plan is large, and the way a plan this size fails is by being built **breadth-first** — assembling every sophisticated part before the core loop is proven on one vuln. The sequencing below is how we avoid that; it matters more than any single feature above.

1. **Gate zero — prove the model can do the core cognitive tasks *first* (capability spike).** Everything rests on a 4-bit R1-14B being able to: read a slice → craft a *reaching* exploit request; drive a multi-turn stateful loop; compose a *valid* Tier-2 check; write a *correct* patch. Our own benches suggest these reasoners are weak and over-flag. So before building any orchestration, hand the raw model 5–10 real slices by hand and measure it. **If it can't, change the model/approach now — no scaffolding rescues a model that can't reason about the code.** (This is risk #8, elevated to a precondition.)

2. **Build a walking skeleton before any breadth.** One target (VAmPI), one class (SQLi), grey-box, one instrumented-sink oracle, the loop, one patch, one dual-gate — end to end. *No* LSP walkers, eBPF, OAST, `compose_check`, or compaction yet. Get detect→prove→fix→verify working on **one thread**, then add pieces onto a spine that already works.

3. **Ruthless MVP cut.** First working system = **grey-box injection + IDOR, Tier-1 only**, on Postgres + Python/Node targets. **Defer:** the symbolic/CrossHair leg (§8), LocalStack, SearXNG, eBPF + all syscall classes, the compiled pipeline, Mode 2 black-box (§16), *and* Tier-2 `compose_check`. Each is a later increment on a proven core, not a launch dependency.

4. **Provisioning robustness is a first-class problem, not plumbing.** Booting arbitrary real repos (missing env/secrets, external deps, build failures) is where most targets die before testing even starts. **Measure the fraction of targets that boot**; treat "can't boot → defer" as a normal, reported outcome. Do not assume provisioning works — it usually won't, on the first try, for real repos.

5. **Pin the `compose_check` execution model before relying on Tier 2.** Tier-2 means *running model-generated code against a target* — decide its form (a sandboxed Python assertion script is the likely answer), its execution sandbox, and its safety boundary. Left unspecified this is both a functionality gap and a security hole (model-authored code with network access).

6. **Budget latency from day one.** One loop turn = one 14B generation; a stateful loop × many candidates × many targets can run to hours on a 250 W-capped GPU. Track **wall-clock-per-target** as a first-class metric next to recall/precision. A system too slow to use fails regardless of how sound it is (this already bit the project once).

7. **Protect soundness from flakiness (N-of-M).** Inferential/timing oracles are non-deterministic (docker-log lag already caused a desync once). Require **N-of-M reproduction** before any finding is emitted — especially Tier-2 timing/boolean signals — so a transient blip never hardens into a false "proof."

**The one-line rule:** prove the model, prove one thread end-to-end, prove provisioning — *then* add breadth. Anything else risks building an elaborate machine around a core that was never going to work.

---

### One-paragraph summary for the reviewer
Wave is a local, model-driven security agent built on one bet: **let the model hunt any vulnerability with total freedom, and let runtime demonstration — not the model's word — decide what counts.** The model works a target like a pentester — a closed observe→reason→act loop with a sandbox, search, and memory, guarded against spin by a request-hash backtrack — and confirms in two tiers: **Tier 1**, a pre-built deterministic oracle (instrumented sinks, differential execution, the DOM oracle, eBPF/L7 egress), gives *proven, zero-false-positive* findings; **Tier 2**, a check the model *composes from a shared toolkit of primitives*, gives *demonstrated, confidence-scored* findings for everything else — CSRF, business logic, open redirect, novel shapes — routed to human review. So the model is never limited in *what* it looks for, only in *how strongly* a result is guaranteed; Tier-1 fixes auto-verify through a functionality-preserving dual-gate or are rejected, Tier-2 goes to a human. It is deliberately *incomplete* but never *confidently wrong*, it is *measured* per-tier against a graded benchmark (Tier-1 precision pinned at 1.0, Tier-2 calibration tracked), and it *grows* by promoting reliable Tier-2 checks into hardened Tier-1 oracles.
