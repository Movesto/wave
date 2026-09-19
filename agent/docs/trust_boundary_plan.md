# Trust-Boundary & Fail-Safe Reachability  *(BUILT — all three shifts + per-module desktop)*

*Author: session 2026-09-18. Motivated by the Stirling-PDF run: a CLI script's command-injection was reported
`confirmed`, and a SaaS IDOR got a repo-global "[desktop app]" tag. Both are blind spots in the Stage-3
context/reachability gates. This doc is about NOT solving them with yet another `is_X` heuristic.*

## 1. The pattern we want to stop

wave keeps discovering threat-model distinctions **reactively** and hardcoding each as a narrow gate:
`is_frontend`, `is_desktop_app`, the build-script note, and now a proposed `is_cli_script`. Each covers ONE
context, is name/path-based (brittle), and is found only after a repo trips it. It is whack-a-mole.

Two root causes:

1. **A semantic question answered with syntactic heuristics.** "Who controls this input? / what is the trust
   context of this code?" is a threat-model judgment. We answer it per-sink with name- and path-matching
   (`main`, `scripts/`, Tauri markers), and names are a shadow of the real thing, so they misfire.
2. **The default on an *unrecognized* context is the DANGEROUS one.** A gate must *affirmatively recognize*
   "CLI / frontend / desktop" to downgrade; if it does not recognize the context, the finding stays
   **`confirmed`**. So every context we have not yet hardcoded produces a *false confirm*. The failure mode is
   open-ended **by construction** — that is why it never ends.

## 2. The general fix — three shifts (not one more gate)

### Shift 1 — Establish the trust boundary ONCE, as an artifact
Instead of every gate re-deriving "is this untrusted?" per finding, Stage 1 produces one **trust model of the
target**: the set of *untrusted entry points* (HTTP routes, queues, file uploads, external deserialization) and
the *deployment context of each module* (multi-tenant web service / single-user desktop / CLI-and-build
tooling). Reachability then asks ONE consistent question — *does this sink trace back to an entry in the
untrusted set?* — with no per-sink heuristic soup. A CLI `main()` and a build script are simply **not in the
untrusted set**, so nothing downstream has to recognize them. (This promotes the existing Attack-Surface Ledger
/ entry_points concept into the single authority for reachability.)

### Shift 2 — The MODEL classifies entry/module trust context, grounded in evidence
The model is already good at this (its own notes correctly called `auto_translate.py` a CLI script and
`AiProxyController` a route). Today that judgment is unused; a brittle heuristic decides instead. If the model
classifies each entry point once during eyes ("web route / CLI tool / build script / test harness / cron /
internal / message consumer") and records it, the trust set **generalizes to contexts no heuristic
anticipated** — without new code. Guardrail: this classification may only mark things *trusted* (→ needs
review), never fabricate a confirm — safe direction, so a wrong call is conservative, not dangerous.

### Shift 3 — Make the default FAIL SAFE  *(building first)*
The word "confirmed" conflates two things: *mechanism proven* (the sink is injectable — what rung1/investigate
actually witness, and do well) vs *exploitable* (mechanism **and** a real untrusted source reaches it). Require
**positive evidence of a remote-untrusted path** to call something exploitable; absent that, degrade to
*"mechanism proven, remote reachability not established → review."* Then an **unrecognized context fails safe**:
you never get a false confirm from a context we did not foresee — only from one where remote reachability is
*affirmatively* shown. Gates then only ever *elevate* confidence; a blind spot's blast radius drops from "wrong
`confirmed`" to "conservatively flagged for a human."

This is why Shift 3 goes first: **it caps the damage of every future blind spot**, including ones Shifts 1–2
have not covered yet.

## 3. How this dissolves the current bugs (and the next ten)

- **CLI (the false confirm):** the CLI `main()` is a *local/process* entry, not a *remote* one. Under Shift 3 a
  `confirmed` needs a REMOTE-untrusted path; a sink reachable ONLY via a local `main()` degrades to review.
  `auto_translate.py`'s injection becomes "mechanism proven, needs review (real only if run on untrusted input,
  e.g. CI on an untrusted PR)". No `is_cli_script` path-heuristic — it keys on the *entry's trust nature*, so a
  CLI tool outside `scripts/`, a cron job, an internal admin tool are all caught the same way; a script that
  *is* a web handler (has a route) stays a remote confirm.
- **Desktop (the mislabel):** deployment context is a property of the *module* (Shift 1), decided once, so the
  `app/saas` web IDOR consults *its* module's context (multi-tenant web) rather than a repo-global boolean set
  by a sibling `app/desktop` build.
- **The next one:** if reachability cannot positively tie the sink to a remote-untrusted entry, it is *review*,
  not a false confirm — regardless of what the unforeseen context is.

## 4. Shift 3 — concrete design (build now)

Entry points gain a **trust tier**, and a `confirmed` requires a REMOTE tier:

- `reachability.entry_trust(func)` → `"remote"` (a route decorator, or a network/event handler name like
  `handler`/`lambda_handler`/`on_message`), `"local"` (a process/CLI entry — a bare `main()`), or `None`.
- `reaches_untrusted_entry` prefers a REMOTE entry: it keeps searching past a local entry and only falls back to
  `local` if no remote path exists (so a sink reachable from BOTH a route and a `main()` is `remote`).
- `gate(...)` returns `(reachable, confidence, note, trust)`.
- `prove._apply_gate`: after the existing "no untrusted path → review" downgrade, add — a `confirmed` whose only
  reaching entry is `local` → **`anomalous_state`** with a "reachable only via a local/CLI entry; remote
  attacker-control not established; real only if run on untrusted input" note. A `remote` reach is untouched.

Only `main` moves to the LOCAL tier for now (the observed bug); `handler`/`handle`/`lambda_handler`/etc. stay
REMOTE (they are typically network/event handlers — moving them would cost real recall). The *mechanism* (trust
tiers + local→review) is what generalizes; the exact name→tier mapping is tuning.

## 5. Tradeoffs (honest)

- **Recall cost:** a real vuln reachable only via a `main()` now sits in review until a remote path is shown.
  For genuine CLI/CI-injection targets that is the correct, honest state (it *is* a judgment call). Route-based
  web vulns are unaffected.
- **Shift 2 introduces a model judgment** — bounded by the safe-direction guardrail (can only lower a claim to
  review, never fabricate a confirm).
- **Existing gates become inputs, not rivals:** `is_frontend`, `is_desktop_app`, `not_exploitable`, the taint
  gate — all become *contributors to the one trust model* over time, rather than independent per-sink checks.

## 6. Build order

1. **Shift 3 — fail-safe default (entry trust tiers + local→review). ✅ BUILT** (`reachability.entry_trust`,
   `gate` returns trust, `prove._apply_gate` downgrades a local-only confirm). Verified on Stirling.
2. **Per-module desktop. ✅ BUILT** (`is_desktop_app(target, file)` module-scoped + `is_server_endpoint`
   override; `_desktop_authz` per-finding).
3. **Shift 1 — trust-boundary artifact. ✅ BUILT** (`trust.py`: `TrustModel{entries, modules}`, built once from
   the codemap, persisted to `wave_trust.json`, viewable via `wave trust <target>`). Each entry is attributed
   to its OWNING module (nearest-module rule); modules classify as web/desktop/cli/library, with test/CLI PATH
   signals winning over the aggregate. `prove` builds+saves it and consults it: a `confirmed` in a TEST-HARNESS
   module → review. Consumers (`_apply_gate`, `_desktop_authz`) take the model; fall back to live checks when
   absent. Verified on Stirling (scripts→cli, cucumber→test, saas→web).
4. **Shift 2 — model-classified trust. ✅ BUILT** (`trust.enrich`): the model reviews the `web` modules and may
   DOWNGRADE any that are not really remote-facing (internal/admin-only, test, cli, library), with a cited
   reason. Safe direction is ENFORCED in `_apply_cluster_actions`-style code, not just prompted: only an
   existing `web` module, only TO a trusted context, only with a reason — a promote-to-`web` is rejected. The
   reason is recorded in `wave_trust.json.refined`. New `internal` context: a `confirmed` there → review.
   Opt-in: `wave trust <t> --deep`, and folded into `wave all --deep-reconcile`. A wrong call downgrades a real
   finding to review (still shown), never mints a false confirm.

**Net:** the three gate blind spots are closed at the root, the fail-safe default caps future ones, and the
`is_X` heuristics are consolidating into one inspectable, model-enrichable artifact (`wave_trust.json`).

## 8. Front-door breadth (the untrusted-entry set)

Shift 1's entry set started with HTTP routes + a few handler names. The uptime-kuma run exposed that
event-driven backends have OTHER front doors the set missed. Extended (no new architecture — just more door
shapes on the same map):
- **Decorator/annotation entries** (`reachability._ROUTE_HINTS`): GraphQL (`@Query`/`@Mutation`/`@Resolver`),
  NestJS messaging + websockets (`@MessagePattern`/`@EventPattern`/`@SubscribeMessage`/`@WebSocketGateway`),
  gRPC (`@GrpcMethod`), Spring/JVM messaging (`@KafkaListener`/`@RabbitListener`/`@JmsListener`/
  `@MessageMapping`), Celery (`@task`/`@shared_task`), cloud functions (Azure `*_trigger`, GCP
  `functions_framework`), Tauri IPC (`#[tauri::command]`). Distinctive strings → near-zero false positives.
- **Handler NAMES** (`_REMOTE_ENTRY_NAMES`): realtime/consumer conventions (`onMessage`, `on_data`,
  `handle_message`, `handle_event`, `resolver`).
- **Named registered handlers** (`codemap`): a fn passed to `socket.on("evt", fn)` / `emitter.once(...)` /
  `.addListener(...)` / `.subscribe(...)` is tagged `wave:event-handler` (a front door). Second pass in
  `codemap.build`.

**Honest residual:** an INLINE ANONYMOUS handler — `socket.on("evt", (data) => { ...sink... })` — has no name,
so it can't be a node in the name-based call graph and can't join the entry set. That is uptime-kuma's exact
shape, and covering it needs more than a list (synthetic-naming of inline handlers, or value/data-flow
reachability) — a real mechanism, deferred. Safe direction holds meanwhile: such findings stay `believed`
(review), never a false confirm.

## 7. Open questions

1. Name→tier mapping: is `handler`/`handle` remote enough, or should ambiguous bare-name entries also be
   `local` (more review, less recall)? Default: keep them remote; revisit with data.
2. Should Shift 3 also require HIGH-confidence (non-ambiguous) reachability for *every* confirm, or only apply
   the local-tier downgrade? Default: only the local-tier downgrade now (requiring high-confidence everywhere
   would cost too much recall given the coarse name-based graph); revisit once value-taint (§10.4) lands.
