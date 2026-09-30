# Changelog

All notable changes to wave. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] — 2026-09-29

First tagged release. wave is a local-first, neuro-symbolic vulnerability-discovery & repair
agent: the model proposes, deterministic tools prove. A finding is `confirmed` only when a tool
witnessed the exploit succeed.

### Core pipeline
- Four resumable stages — **eyes** (tree-sitter map + call graph + security pins + model notebook),
  **detect** (clean-room falsification), **prove** (sandbox exploitation), **patch** (fix + re-verify).
- **Proof loop** — the model drives a throwaway Docker sandbox; a tool witnesses the effect. Proof
  paths for 17 languages (Python/JS interpreter, Rust/Go/Java/C# compile-run, C/C++ with
  AddressSanitizer, and more).
- **SARIF 2.1.0 export** for GitHub code scanning / CI / IDE.
- **Parallel stages** — `--jobs N` runs notebook/detect/prove/patch/reconcile concurrently on a
  cloud model (install steps serialized to avoid OOM).

### Honesty & trust
- **Trust boundary model** — per-module trust map (remote route vs local CLI vs test vs desktop),
  fail-safe default (unrecognized context → human review, never a false confirm).
- **Honesty gates** — reachability, execution-context, value-taint, grounded-confirm bar.
- **Reachability is witnessed, not guessed** — the prover drives the *real* route via the framework's
  in-process test client (Flask/FastAPI, Express, NestJS, Spring, ASP.NET, Go, Rails, Laravel, Rust,
  **and file-based Next.js / SvelteKit / Nuxt**); each confirm records `reach_proof` (witnessed/inferred).
- **Tool-grounded witness** — the harness reads its own planted markers from the sandbox output
  (`oracle.py`, a per-class evidence dispatch), so a confirm rests on the tape, not the model's account.
- **Decorrelated second-model audit** — set `WAVE_AUDIT_MODEL` for an independent model to judge the
  no-marker (judgment) confirms; conservative on disagreement.
- **Stage 5 reconcile** — deterministic dedup + contradiction resolution; a tool-witnessed verdict is
  never overturned by reasoning alone.
- Verdicts: `confirmed`, `anomalous_state` (human review), `believed`, `blocked`, `refuted`,
  `not_exploitable`.

### Detection recall
- Detect seeds candidates from the codemap's classified sink-pins **and** the notebook, so a whiffed
  note can't blank a file; a blank note on a pin-rich file is retried.
- Custom sink detection (`run_shell_command`/`exec_sql`), authz/IDOR pins (no injection sink),
  inline anonymous handler synthetic-naming.
- Deterministic detection-recall benchmark (`agent.bench.detect_recall`): 100% across 23 cases / 9
  CWEs / 11 languages, run in CI.

### Notable fixes
- taint: aggregate over all calls on a line (chained sink `run(...).decode()` no longer false-`unrelated`).
- reachability: binding-aware call walk (name-collision chains), Typer/Click commands are LOCAL,
  fail-safe entry-trust tiers.
- Behavioral guardrails: read-thrash nudge, repro-force gate, try-another-method, methodology logging.

### Tooling
- GitHub Actions CI (`pytest` + the detection-recall gate).
- 233 deterministic tests.

### Known limits
- The model is the ceiling on the prove/patch stages — a capable (cloud) model proves far more than a
  small local one; the architecture is model-agnostic (any OpenAI-compatible endpoint).
- Cross-function taint is single-function today (cross-function flow falls to the model).
- No dependency-CVE scanning or missing-control detection yet.
