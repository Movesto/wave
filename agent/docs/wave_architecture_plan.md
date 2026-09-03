# wave — Architecture & Implementation Plan

*Consolidated single-file plan. Supersedes the scattered plan docs (evidence_grounded_plan, revised_plan,
master_plan) for the current direction. Written to be read cold by an outside reviewer — the last section
lists the open questions and suspected blind spots we most want a second opinion on.*

Last updated: 2026-09-02.

*An external architecture review (2026-09-02, `arch_feedback.md`) contributed several improvements that are
now folded into the stages below and flagged **[review-adopted]**. Suggestions we deliberately did **not**
promote to the main design — because they conflict with a hard-won lesson or risk regressing precision — are
kept separately in §12 so the reasoning is on record.*

---

## 1. What wave is

wave is a **local, autonomous vulnerability-discovery and repair agent**. You point it at a codebase; it
finds real vulnerabilities, **proves** them by making the bug actually happen in a sandbox, and proposes a
fix that it then **re-verifies**. It runs on one workstation GPU — no dependence on frontier cloud models
for the parts that matter.

**North star:** a system that can fix a *complex, previously unseen* vulnerability by reasoning over code,
driving deterministic tools (execution, sanitizers, CodeQL-style analysis), and — where allowed — consulting
external knowledge. Training/tooling teaches *discrimination* (is this specific flow actually exploitable?);
the harness owns *cross-file structure and proof*.

---

## 2. The core principle

> **The model DECIDES and TRANSLATES. Deterministic tools PERCEIVE and PROVE.**

The model is the intelligence: it reads code, forms hypotheses, writes payloads/patches, and renders the
final verdict. The tools are the senses and the courtroom: they hold the codebase's structure, run whatever
the model asks in the target's real environment, and report **what actually happened** — facts the model
cannot fabricate.

This split exists because of one empirically robust finding (ours and the literature's, see §3): **the
harness matters more than the model.** A weak local model inside a strong harness beats a strong model
reasoning in a vacuum, because the harness supplies (a) the structure the model can't hold in its head and
(b) the ground-truth the model would otherwise hallucinate.

### The one rule that keeps it honest

> **A verdict of `confirmed` must cite an effect the model actually caused and a tool actually observed.
> Reasoning alone can PROPOSE (`believed`); only an observed effect can CONFIRM.**

Every false positive we've seen (a fabricated CVE, CWE-89 reported on a browser call) came from the model
*concluding without acting*. This rule makes acting mandatory for confirmation while leaving the model free
to think and decide.

---

## 3. Why this design — what the field (and our own failures) taught us

We reviewed ~9 recent papers on LLM vulnerability discovery (Google's agentic source-code review, Visa's
harness, XBOW, AEGIS, DAGVUL, and others) and cross-checked against our own runs. The convergence was
strong and it shaped every choice below:

1. **Harness >> model.** No single scaffold dominates; the reliable wins come from structure + verification
   around the model, not from a bigger model.
2. **Ensembles beat single passes.** Majority-vote / adversarial framing (argue both sides) cuts the
   universal ~50% false-positive rate that afflicts *even frontier models*.
3. **Threat-model-first is the highest-ROI step.** Deciding *what* to attack and *where trust crosses*
   before diving in beats brute-force scanning.
4. **The knowledge–application gap is real and universal.** Models "know" what SQLi is and still fail to
   apply it to a specific flow. Discrimination on the concrete case is the hard part — not taxonomy recall.
5. **Cross-file understanding is a memory problem, not an intelligence problem** (see §4).

Our own prior flaws that this architecture targets:

- **Tool-decides was too narrow.** The old oracle proved vulns only by patching **Python** sinks and knew
  only ~9 injection classes → zero coverage on JS/TS projects, zero on business-logic/IDOR/workflow.
- **Reasoning in a vacuum hallucinated.** Without a forced observation step, the model invented findings.
- **No structural map.** The model was asked to hold whole-codebase cross-file structure in its context
  window and couldn't.

---

## 4. The cross-file / memory insight (why the harness holds the map)

A model is **stateless**; its context window is its only working memory. It cannot simultaneously hold a
whole codebase's structure *and* reason deeply about one slice — the two compete for the same limited space.
This is why "just use a bigger model" doesn't fix cross-file analysis: a bigger window still fills up, and
attention degrades over long contexts.

The fix that the successful harnesses share: **externalize the structure.** The harness becomes the map (an
explicit, tool-built call graph + reachability) and the conductor (a deterministic pipeline that hands the
model one *resolved slice* at a time: "untrusted input enters at X, flows through Y, reaches sink Z"). The
model then does what it's good at — judging that one concrete slice — instead of rediscovering structure it
can't retain.

---

## 5. The models

| Role | Model | Where | Notes |
|---|---|---|---|
| **Detection / exploit / patch** | Qwen3.8-27B-Uncensored (IQ3_XS GGUF, ~13GB) via **ollama** | **LOCAL** (GPU) | Native tool-calling through ollama's OpenAI-compatible API. This is the brain for everything that decides a verdict or writes an exploit. **Must stay local.** |
| **Comprehension / "the eyes"** | GLM-5.2 (`z-ai/glm-5.2:free`) via OpenRouter | Cloud, **best-effort** | Only for reading/summarizing code and auditing the tool-built map — *never* detection or exploit. Provider states it does not train on or retain prompt data. The free pool 429s intermittently, so **every call falls back to the local model**. GLM is an enhancement, not a dependency. |

**Hard constraint:** detection and exploitation are local, always. Only *comprehension* may touch the cloud,
and only the privacy-preserving free GLM endpoint, with a local fallback.

**Operational lesson (baked into `model.py`):** ollama defaults to a **4096-token context** (`num_ctx`). A
code slice plus a reasoning model's `<think>` phase overruns it and the reply is cut before the answer
(empty content, `finish_reason: length`). We now send `num_ctx: 16384` for the local endpoint. Also note
this MTP model **ignores `think:false` and `response_format`** — the working lever is giving it *room to
reason*, not trying to suppress the reasoning.

---

## 6. The architecture — four stages

```
   TARGET REPO
       │
   ┌───▼────────────────────────────────────────────────────────────┐
   │ STAGE 1 — THE EYES  (structure + comprehension)      [BUILT]    │
   │   codemap.py  : tree-sitter → entry points, call graph,          │
   │                 entry→sink reachability   (LOCAL, exact)         │
   │   eyes.py     : per-entry comprehension (purpose + candidate     │
   │                 sinks) + dynamic-blind-spot prescan              │
   │                 (GLM if reachable, else LOCAL)                   │
   │   → OUTPUT: an ENRICHED MAP (resolved slices + semantic notes)   │
   └───┬─────────────────────────────────────────────────────────────┘
       │
   ┌───▼────────────────────────────────────────────────────────────┐
   │ STAGE 2 — THE DETECTOR  (adversarial-ensemble confirm) [PLANNED]│
   │   For each candidate sink slice, the LOCAL model argues BOTH     │
   │   "prove exploitable" and "prove safe", cites evidence, N-vote.  │
   │   → OUTPUT: ranked hypotheses worth the cost of proving          │
   └───┬─────────────────────────────────────────────────────────────┘
       │
   ┌───▼─────────────────────────────────────────────────────────────┐
   │ STAGE 3 — THE PROOF LOOP  (hypothesize→act→observe→reason→       │
   │           conclude)                          [PARTLY BUILT]      │
   │   execute.py    : general executor — run anything, any language, │
   │                   in the target's real env, sandboxed            │
   │   investigate.py: the tool-use loop the model drives             │
   │   repro.py      : reproduction scaffold (harness owns the glue,  │
   │                   model supplies the payload)                    │
   │   observers     : canary-in-sink / reflection / differential /   │
   │                   crash / behaviour  → FACTS, never verdicts     │
   │   → OUTPUT: verdict (confirmed|believed|refuted|blocked) + cited │
   │             observation                                          │
   └───┬─────────────────────────────────────────────────────────────┘
       │
   ┌───▼─────────────────────────────────────────────────────────────┐
   │ STAGE 4 — PATCH + REVERIFY                    [BUILT (Python) /   │
   │   model writes a fix; the SAME proof re-runs;    EXTEND to JS]   │
   │   confirmed→still-exploitable? then the patch failed.            │
   └──────────────────────────────────────────────────────────────────┘
```

### Stage 1 — The Eyes  *(BUILT & verified)*

**`codemap.py`** — a local tree-sitter structural map, exact and cheap:
- functions (name, file, line, end), call graph, imports;
- **entry points** = where untrusted input can enter: exported functions, decorated routes, `main`/handlers.
  Handles Python (decorators, module-level defs) and JS/TS (**ESM `export` and CommonJS
  `module.exports`/`exports.x`**), correctly excluding functions merely *nested inside* an export;
- **`chain_to_entry(sink)`** — walks the call graph backward from a sink to an entry point, yielding the
  *resolved slice* the model reasons over.
- Deliberately **blind** to dynamic dispatch / eval / reflection / framework magic — those are handled by
  the audit below, not faked by the parser. Name-based call resolution (best-effort, not type-sound); the
  comprehension pass + ensemble cover the gaps.

**`eyes.py`** — two comprehension responsibilities, **both comprehension-only** (never a vuln verdict):
1. **Comprehend** — for each entry point, a JSON note: `purpose`, `untrusted_input` (which args/fields an
   external caller controls), and `candidate_sinks` (powerful operations + line + whether input reaches
   them). This is where a strong reader earns its keep: tree-sitter sees *calls*, not *meaning*.
2. **Audit / dynamic prescan** — a local, exact scan for the patterns the call graph structurally can't
   resolve (`eval`/`new Function`, dynamic `require(var)`/`import(var)`, reflection/`getattr`, `exec`,
   `obj[name]()` dispatch, route registration). These are the tool's known blind spots, handed to the
   reader/detector as explicit "look here."

Verified on serialize-javascript (independently surfaced `options.unsafe` + the escape-regex and
function-serialization sinks — the real CVE-2020-7660 surfaces) and launchpad (prescan pinpointed the actual
`exec(command)` command-injection line).

**[review-adopted, adapted] Security-pinned whole-repo map + Attack-Surface Ledger.** Additions that target
our big-repo timeouts and the scale/cost triage problem (§10.9). **We adapt the review here:** it proposed
compressing the whole repo to a ~2k-token skeleton, but the design intent is a **detailed whole-repo
inventory** — every file, what each is *composed of* (imports, functions/classes with signatures, exports,
decorators) and what it *does* (module docstring/purpose) — plus pinned targets, so the model knows the
repo bottom-to-top. **Depth-on-demand** (full source of a specific file) comes from the model's tool-calling
*after* the map, not from stuffing every line into the map. So the lever is completeness of *structure +
purpose + pins*, not aggressive compression.
1. **Detailed, ranked inventory.** A whole-repo structural map (signatures/exports/decorators, bodies
   omitted; full source fetched on demand via tool-calling). Built on our tree-sitter `codemap.py`; no
   `aider`/`grep-ast` dependency (we already extract more than grep-ast's tags — a real call graph +
   reachability).
2. **Invert the reference-count bias — pin high-value targets.** *Critical caveat from the review:* a
   vanilla PageRank/reference-count ranking (repomap's default) **demotes** security bugs, because they
   live in isolated routes and unreferenced wrappers that score *low*. So a deterministic regex/AST pass
   must **unconditionally pin to the top**: route decorators (`@app.get/post`, Express `router.*`, Nest
   controllers), and sensitive sinks (`exec`/`spawn`/`eval`, raw-SQL `execute`, deserialization
   `pickle`/`unserialize`, direct file ops). This overlaps what the dynamic prescan already pins; the new
   part is doing it as a *ranking* over the whole map — a PINNED section first, then the full inventory so
   nothing is hidden.
3. **Attack-Surface Ledger.** GLM-5.2 (local Qwen fallback) turns the pinned map into a structured
   ledger — entry points + their auth requirements, high-risk operations (financial logic, file uploads,
   role checks), and a ranked list of files for deep inspection. This ledger is the triage that keeps
   per-entry comprehension + detection tractable on one GPU and stops the read-all step from drowning on a
   monorepo.

### Stage 2 — The Detector  *(PLANNED — next build)*

Consumes the enriched map. For each candidate sink slice, the **local** model discriminates on the concrete
case, checked against itself.

**[review-adopted] Asymmetric clean-room falsification — replaces N identical votes.** The original design
here was "argue both sides + N independent votes." The external review made the decisive point (and it
matches our own open risk §10.3): running N *identically-primed* passes on the same local model just
**launders that model's bias N times** — the votes are correlated because the context is shared. The fix is
to decorrelate by **context asymmetry**, not by re-rolling the same prompt:
- **Step 1 — Generate (primed).** Local Qwen gets the resolved slice from Stage 1 and hypothesizes an
  exploit vector (e.g. IDOR on `/api/profile`, unsanitized input into `exec`).
- **Step 2 — Clean room (fresh context).** **Reset the conversation entirely** (`messages: []`), pass in
  **only** the raw ~40-line slice, single-turn, low temperature (0.1), and task the model *solely* with
  **disproving** the vuln against a falsification rubric: does framework routing/middleware sanitize before
  entry? is there an implicit cast or schema validator that blocks the payload? is the branch logically
  unreachable?
- Each side must **cite evidence from the slice** (a line, a missing check), not assert. Only hypotheses
  that survive the clean-room disproof get promoted to the (expensive) proof loop.
- **Zero extra VRAM** — the two calls run sequentially on the one GPU; the separation is contextual, not a
  second model.

This is the field's antidote to the ~50% FP rate and replaces the old closed "9-class oracle decides" with
"the model discriminates, then a fresh instance tries to knock it down." **Honest limit:** it's still the
same weights, so shared *training* bias survives — the reset kills anchoring/priming correlation, not the
model's fundamental blind spots. It is strictly better than N-identical-votes and costs nothing, but it is
not a guarantee; the proof loop remains the real arbiter.

### Stage 3 — The Proof Loop  *(PARTLY BUILT)*

The language-agnostic, class-agnostic core: `hypothesize → act → observe → reason → conclude`.

- **`execute.py`** *(built)* — general executor: `execute(command, stdin, image, mount, …) → ExecResult`.
  Runs anything in a throwaway Docker container (or `docker exec` into the target's own container), with
  caps (no network by default, memory/cpu limits, timeout). Not per-language — "run code" is general; only
  the interpreter differs.
- **`investigate.py`** *(built)* — the tool-use loop the model drives (native tool-calls when the backend
  supports them; text-protocol fallback otherwise), enforcing the grounding rule and nudging on repeated
  commands.
- **`repro.py`** *(built)* — reproduction scaffold: the harness owns the *glue* (module loading ESM/CJS/TS,
  browser boilerplate, async wiring), the model supplies only the *payload*. JS probe uses dynamic import;
  `render` mode drives headless chromium and reports an XSS canary.
- **JS/browser provisioning** *(built — `js_env.py`)* — tsx runner image + `node_modules` install + a
  Playwright/chromium image for DOM/XSS observation.
- **Observers** — a spectrum of *facts*, the general replacement for the closed oracle:

  | Observer | Reports (a fact) | Grounds |
  |---|---|---|
  | Canary-in-sink | marker landed unsafely in SQL/shell/path/URL | injection classes |
  | Reflection | marker came back in HTTP response / DOM | XSS, disclosure |
  | Differential / state | before→after state changed (balance, role, another user's record) | business logic, IDOR, workflow |
  | Crash / sanitizer | process crashed / ASan fired | memory safety |
  | Response / behaviour | status, timing, body, side effects | anything |

  Canary and differential observers are language-agnostic (string/behaviour/state comparisons). The
  sink-tripwire observer (strongest, near-zero-FP) is per-language and optional — a bonus automatic witness
  where built, not a requirement.

- **Verdict + evidence ledger** *(built — `recorder.py`)* — `believed` / `confirmed` / `refuted` /
  `blocked`. Every `confirmed` carries the triple: action taken, observation returned, model's reasoning —
  re-runnable by a human.

- **[review-adopted] Structured error escalation — never let a broken environment read as "safe."** A test
  that crashes with `ECONNREFUSED`, a missing mock, or a dependency/import error must **not** be marked
  `refuted`. It routes to an escalation handler: (1) the agent tries to fix the runtime scaffold — install
  a package, spin up a mock SQLite DB, start the missing service; (2) if the environment still can't be
  provisioned after **two** attempts, the verdict is **`blocked: under-provisioned`**, never a false
  `refuted`. This is our concrete answer to §10.8 (distinguishing "refuted because safe" from "refuted
  because under-provisioned").

- **[review-adopted] Distinct status for business-logic effects.** Business-logic/IDOR/workflow results
  get their own verdict **`anomalous_state: human-reviewable`**, kept *separate* from a witnessed
  `confirmed`, so a model-argued state change is never silently confused with a tool-witnessed injection.
  This answers §10.7.

**Graceful degradation (the honest part):** injection/memory/reflection get a self-proving witness
(near-zero FP) → `confirmed`. Business-logic/IDOR get a *fact* (state changed) plus the model's mechanism
argument → `anomalous_state: human-reviewable` — because "is this state *bad* or intended?" is a judgment no
tool (and no human without context) can make automatically. Strong classes get a strong witness; open-ended
classes get a reasoned argument anchored to a real observed effect — which is how expert humans deliver them.

**[review-adopted] Context discipline for the tool-use loop.** Multi-turn investigation saturates the 16k
window fast — we already hit an ollama 500 from a context bloated by `cat`/`grep` dumps, and band-aided it
with a blind 1200-char truncation (which can slice off the exact line carrying the proof). The proper fix:
**never pipe raw container `stdout`/`stderr` into the prompt.** Redirect execution output to a temp file on
the host and give the model lightweight query tools — `grep_output(pattern, lines=10)`, `tail_output(lines=20)`
— so it pulls only the relevant lines. Keeps tokens (and response time) minimal without ever discarding the
evidence line. *(Not yet built — supersedes the current truncation.)*

### Stage 4 — Patch + Reverify  *(BUILT for Python; extend to JS)*

The model writes a fix; the **same** proof re-runs; if the confirmed exploit no longer fires, the patch
holds; if it still fires, the patch failed and the loop continues. Full detect→prove→patch→reverify was
demonstrated end-to-end on VAmPI (Python).

---

## 7. Build status

| Component | State |
|---|---|
| `codemap.py` — structural map | ✅ Built, verified on 3 repos |
| `eyes.py` — comprehension + dynamic prescan | ✅ Built, verified (serialize-js, launchpad) |
| `model.py` — GLM/local split, num_ctx, json_mode, think | ✅ Built |
| `execute.py` — general executor | ✅ Built |
| `investigate.py` — tool-use loop | ✅ Built |
| `repro.py` / `js_env.py` — scaffold + JS/browser provisioning | ✅ Built |
| `recorder.py` — verdict/evidence ledger | ✅ Built |
| Proof of cmdi (py/js/ts) + XSS via scaffold | ✅ Demonstrated |
| Detect→prove→patch→reverify (Python) | ✅ Demonstrated (VAmPI) |
| **Stage 2 detector — clean-room asymmetric falsifier** | ✅ Built (`detector.py`), verified — [review-adopted] |
| Stage 1b notebook — persistent per-file notes + model target selection | ✅ Built (`notebook.py`) |
| Wire Eyes map → detector → proof loop into one pipeline | ⬜ Planned |
| Patch/reverify for JS/TS | ⬜ Planned |
| Stage 1 security-pinned ranking + Attack-Surface Ledger | ⬜ Planned — [review-adopted] |
| Stage 3 escalation handler (`blocked: under-provisioned`) | ⬜ Planned — [review-adopted] |
| `anomalous_state: human-reviewable` verdict status | ⬜ Planned — [review-adopted] |
| Context discipline: file logs + `grep_output`/`tail_output` | ⬜ Planned — [review-adopted] |
| GHSA real-CVE benchmark harness | ✅ Built; baseline 2/23 (see §8) |

---

## 8. Evaluation

- **Regression fixtures** — VAmPI, DVNA, NodeGoat, the cmdi/xss targets: used to confirm fixes, not to
  measure capability.
- **Capability testing** — a *different* real repo each time (never reuse except to confirm a fix).
- **GHSA benchmark** (`agent/bench/ghsa_bench.py`) — repurposes Cisco's 500-CVE
  vulnerability-localization-benchmark: we fetch the vulnerable commit, run the loop, and score whether wave
  **proved** a vuln that lands in the ground-truth patched files (stricter than their localization task).
  Current baseline **2/23** (both command-injection); misses are proof-shape gaps (DOM plugins, URL
  sanitizers, servers, async-exec) + giant-repo timeouts — i.e. exactly what Stages 1–2 are meant to close.

---

## 9. Design invariants (don't regress these)

- Detection + exploitation stay **local**; only comprehension may use the cloud GLM (best-effort + local
  fallback).
- Execution is **sandboxed** (container / WSL2), never the host; no network by default.
- `confirmed` **requires a cited, observed effect**. No observation → `believed` at most.
- Don't assume the target ships tests, entry-point scripts, or a working `docker-compose` — most real repos
  don't. The harness must provision what it needs.
- One GPU job at a time; never stack parallel GPU jobs.
- Verify your own output by hand — every builder here has passed its own gates while still being wrong.

---

## 10. Open questions & suspected blind spots — *what we most want reviewed*

These are the places we think the design is weakest or unproven. A reviewer's fresh eyes here are the point
of this document.

1. **Name-based call resolution.** `codemap`'s call graph matches on *callee name*, not resolved binding.
   Overloads, methods on different classes with the same name, and re-exports will produce wrong edges
   (false chains) or missing edges (missed reachability). How badly does this bite on real medium/large
   repos? Is a light scope/type resolution worth the cost, or does the comprehension pass absorb it?

2. **Entry-point completeness.** We treat exports + decorated routes + `main`/handlers as entry points.
   Framework-registered routes (Express `app.use(router)`, Nest decorators, dynamic route tables, plugin
   systems, message-queue consumers, CLI subcommands) may not surface. What entry classes are we missing,
   and does the dynamic prescan actually catch the ones the AST doesn't?

3. **The detector doesn't exist yet.** The adversarial-ensemble idea (§6, Stage 2) is the crux of FP
   control and is entirely unbuilt. Is "argue both sides + N-vote with a *local 27B*" strong enough, or
   does the ensemble just launder the same model's bias N times? What's the right N, and does adversarial
   framing genuinely decorrelate the votes?

4. **Cross-file *taint*, not just cross-file *reachability*.** We resolve entry→sink *reachability*, but we
   do not yet track whether the *specific tainted value* actually flows along that path (vs. a sanitized
   copy, or a different argument). Reachability without dataflow will over-propose. Where's the right line
   between "give the model the slice and let it judge" and "the harness should do real taint"?

5. **GLM reliance for comprehension quality.** When the free GLM pool 429s, comprehension falls to the
   local 27B. Is local-only comprehension good enough, or does quality drop meaningfully? We haven't
   measured the gap. (And is the "does not retain" guarantee something we should trust for *any* code?)

6. **Proof-shape coverage.** Stage 3 proves injection/XSS well. The long tail (SSRF egress, deserialization,
   SSTI, auth/IDOR needing multi-user state, race conditions) each needs a bespoke observer or provisioning.
   Which of these are worth building vs. leaving as `believed`+human-review? The GHSA misses suggest this is
   where most real-world coverage is lost.

7. **Business-logic verdicts.** We label these `confirmed`-by-model + human-reviewable when a state change
   is observed. Is "observed state change + model argument" a responsible bar for `confirmed`, or should
   those be a distinct status so they're never confused with witnessed injection?

8. **Sandbox fidelity.** Running a candidate in a throwaway container with no network and stubbed deps can
   make a real vuln *look* refuted (the dangerous path needed a DB/service that wasn't there). How do we
   distinguish "refuted because safe" from "refuted because under-provisioned"? Today that's `blocked` if we
   notice, but we may not always notice.

9. **Scale / cost.** Per-entry comprehension + N-vote detection + per-candidate proof runs multiply. On a
   large repo with hundreds of entry points, what's the triage that keeps this tractable on one GPU without
   dropping the real bug? Is threat-model-first prioritization (§3.3) enough?

---

## 11. External-review suggestions we did NOT adopt as main

These came from the same 2026-09-02 review. They are reasonable ideas, but each conflicts with a hard-won
lesson or risks regressing precision, so they are recorded as **suggestions** — pursue only with the caveat
attached, not as part of the main design.

1. **Full JIT scaffolding (let the model write its own test harness from scratch).** *Caveat:* this collides
   with our single most-repeated finding — **the model drowns in GLUE** (module systems ESM/CJS/TS, async
   wiring, browser boilerplate). `repro.py` exists precisely because "harness owns the glue, model owns the
   payload" fixed the 8-steps-of-loader-fighting failure. Blanket JIT would regress that. **Adopt only the
   hybrid form:** keep the scaffold for glue, let the model author JIT pieces *only* for the environment it
   genuinely can't template (e.g. a 10-line SSRF listener, a mock DB). Note `investigate.py` already is a
   model-driven JIT loop, so the real gap is provisioning/escalation (now [review-adopted] in Stage 3), not
   a new free-form harness generator.

2. **Experiential memory fed back into prompts.** The review proposes a JSON/SQLite ledger of per-target
   "lessons" that pre-seeds *future* runs. *Caveat:* seeding future prompts with past folklore can
   **poison** — one wrong lesson propagates into every matching run, and it is exactly the unvalidated soft
   heuristic our "tools prove, not reasoning" invariant exists to keep out of the confirmation path. Our real
   learning mechanism is the DAGVUL/training path, not prompt-seeded memory. **Keep it log-only** (post-run
   reflection appended to a store for humans/telemetry) until the base pipeline is solid; do **not** wire it
   back into detection or proof prompts yet.

**Framing caveat on the whole review.** It implicitly assumes wave is currently *false-positive-limited*, so
it centers Stage-2 filtering. Our measured reality is the opposite: at GHSA 2/23 we are **recall- and
agent-reliability-limited** — the misses are proof-shape coverage gaps + a borderline local agent, not an FP
flood, and no detector has run yet. So among the adopted items, **Stage 1 pinning (recall)** and **Stage 3
escalation/context (coverage + honesty of `blocked`)** move our actual metric more than the Stage 2 clean-room
does *today*; the clean-room banks its value once recall is up. Every adopted item still routes through the
same borderline local agent — the ceiling the bake-off identified — which the review does not address.

---

## 12. File map (current)

```
agent/orchestrator/
  codemap.py      Stage 1  structural map (tree-sitter)           [new]
  eyes.py         Stage 1  comprehension + dynamic prescan        [new]
  model.py        both     local/GLM model interface + governor
  execute.py      Stage 3  general executor (Docker)
  investigate.py  Stage 3  model-driven tool-use loop
  repro.py        Stage 3  reproduction scaffold
  js_env.py       Stage 3  JS/TS + browser provisioning
  rung1.py        Stage 3  Python micro-exec + canary observer
  recorder.py     Stage 3  verdict + evidence ledger
  state.py        —        run_loop orchestrator (to be re-wired to Stages 1-2)
  run.py          —        CLI entry
agent/bench/
  ghsa_bench.py   Eval     Cisco 500-CVE benchmark harness
agent/docs/
  wave_architecture_plan.md   ← this file
```
