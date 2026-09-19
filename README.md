# wave — a local, autonomous vulnerability-discovery & repair agent

You point it at a codebase; it **finds** real vulnerabilities, **proves** them by making the bug actually
happen in a sandbox, and proposes a **fix** that it then **re-verifies** — running on one workstation GPU, with
no dependence on a frontier cloud model for the parts that matter.

> This README is the honest project log. wave began as a chain-of-thought *scanner* (fine-tuning an 8B model
> to emit reasoned verdicts — that history and its central finding live in
> [`docs/TECHNICAL_REPORT.md`](docs/TECHNICAL_REPORT.md)). It has since **pivoted** to the neuro-symbolic
> agent described below: the model reasons, deterministic tools prove. The full design is in
> [`agent/docs/wave_architecture_plan.md`](agent/docs/wave_architecture_plan.md).

---

## Quickstart

```bash
# 1. install as a CLI (Docker must also be running -- proofs run in throwaway containers)
pip install -e .                     # gives you the `wave` command

# 2. point at a model ONCE (saved to ~/.wave/config -- no need to re-set it each run)
wave config set base  "http://localhost:11434/v1"        # LOCAL via ollama (private, the design intent)
wave config set model "hf.co/<your-gguf>:<tag>"
#    ...or a CLOUD OpenAI-compatible endpoint (stronger, off-box -- sends code out):
# wave config set base  "https://openrouter.ai/api/v1"
# wave config set model "deepseek/deepseek-v4-flash-0731"
# wave config set key   "<your key>"

# 3. run the whole pipeline on a repo (find -> prove -> patch)
wave all /path/to/target-repo --patch
```

Then read **`target-repo/wave_results/wave_report.md`** — a human-readable report of what the model found:
what it **proved** (with the cited evidence), what **needs review**, what it **cleared as safe**, and any
**fixes**. A `confirmed` was witnessed by a tool; `anomalous_state` needs human judgment; `believed`/`blocked`
are unproven leads. (`wave report <repo>` regenerates it; the raw machine artifacts are `wave_findings.jsonl`
+ `casefile.json`.)

It's resumable — re-run to continue. The first run pulls a couple of Docker images (and, for XSS, a chromium
image — a one-time download).

<details><summary>No model yet? Fastest path with ollama</summary>

```bash
# install ollama (https://ollama.com), then serve a capable local model, e.g.:
ollama pull <a-qwen3-family-model>
ollama serve            # exposes the OpenAI-compatible API on :11434
```
Then set `WAVE_API_BASE`/`WAVE_MODEL` as above. A stronger model proves more; see **Models** below.
</details>

---

## The one idea

> **The model DECIDES and TRANSLATES. Deterministic tools PERCEIVE and PROVE.**

The model reads code, forms a hypothesis, writes a payload or a patch, and renders the verdict. The tools hold
the codebase's structure and run whatever the model asks in a sandbox, reporting **what actually happened** —
facts the model cannot fabricate. The rule that keeps it honest:

> **A verdict of `confirmed` requires an effect the model actually caused and a tool actually observed.**
> Reasoning alone can only *propose* (`believed`); only an observed effect can *confirm*.

Every false positive we ever saw came from a model concluding without acting. This makes acting mandatory for
a confirmation.

---

## The pipeline — four stages

```
TARGET REPO
   │
   ▼  STAGE 1  EYES        tree-sitter whole-repo map + call graph + security pins;
   │                       a model "notebook" reads the pinned files into per-file notes
   ▼  STAGE 2  DETECTOR    clean-room asymmetric falsification: a fresh model instance,
   │                       shown only the slice, tries to DISPROVE each believed finding
   ▼  STAGE 3  PROOF LOOP  the model drives a sandbox to make the exploit happen; a tool
   │                       WITNESSES the effect (marker in a sink, ASan report, state delta)
   ▼  STAGE 4  PATCH       the model writes a fix; the SAME proof re-runs; certified `fixed`
                           only if the exploit demonstrably no longer fires
```

Between the stages sit **honesty gates** that keep verdicts trustworthy:

- **Reachability gate** — a proven sink with no path from an untrusted-facing entry → human-review, not a
  false confirm (and it flags *ambiguous* name-based call edges as low-confidence).
- **Context gate** — a browser/frontend file can't host a server-side vuln (a client `fetch` is not SSRF).
- **Value-taint** — does the *specific* untrusted value actually reach the sink, or a sanitized copy?
- **Evidence audit** — every `confirmed` is re-checked by a fresh clean-room skeptic + an independent second
  proof; it upholds only what it can ground.

---

## What it can do today

**Languages mapped** (tree-sitter): Python, JavaScript/TypeScript, Ruby, PHP, Go, Java, C#, Rust, C, C++.

**Vulnerability classes it can *prove* (a tool witnesses the effect):**

| Class | How it's witnessed |
|---|---|
| Command injection | injected `; touch /work/wave_HIT` runs → the marker file appears |
| SQL / NoSQL injection | the marker reaches the query in an unsafe (unparameterized / operator) position |
| SSRF | the marker controls the outbound request host |
| Path traversal | a `../` payload survives to the file open |
| XSS | rendered in headless chromium (DOM) **or** a sanitizer's return still yields a `javascript:` URL |
| SSTI / eval | `{{7*7}}` evaluates to `49` |
| Prototype pollution | a `__proto__` payload pollutes a fresh object |
| Deserialization | a crafted object fires a marker side-effect on load |
| **C/C++ memory safety** | compiled with **AddressSanitizer** → a crafted input trips a sanitizer report |
| **IDOR / broken access control** | a synthetic 2-identity harness: user A's call returns user B's data |

Classes it can't yet witness (missing deps, business logic beyond IDOR, gadget chains) are reported as
`believed` (a reasoned lead) or `blocked` — never a false `confirmed`.

---

## How to run it

### 1. Prerequisites

- **Python** 3.11+; install the CLI with `pip install -e .` (pulls `tree-sitter-language-pack`, `requests`,
  `PyYAML`). This gives you the `wave` command.
- **Docker** running (the proof loop executes everything in throwaway containers — never on your host).
- **A model** (pick one, next section).

### 2. Point it at a model (once)

`wave config set` saves to `~/.wave/config`, so you set it a single time and never pass env again. (An
existing `WAVE_*` env var or `.env` still wins if present.)

**Local (default, private — the design intent):** an ollama server serving a capable local model.

```bash
wave config set base  "http://localhost:11434/v1"
wave config set model "hf.co/<your-gguf>:<tag>"     # e.g. a Qwen3-family 27B
```

**Cloud (stronger reasoning, off-box — for testing / hard targets):** any OpenAI-compatible endpoint, e.g.
OpenRouter. This sends code off-box; use it deliberately.

```bash
wave config set base  "https://openrouter.ai/api/v1"
wave config set model "deepseek/deepseek-v4-flash-0731"
wave config set key   "<your OpenRouter key>"
```

`wave config show` prints the current settings.

### 3. Run the whole pipeline

```bash
wave all /path/to/target-repo --patch
```

Useful flags:
- `--all-files` — deep-read **every** parsed source file, not just the ones with a recognized sink pin.
  Pinning becomes a priority *order* rather than a filter, so a vuln in a file with no matched sink pattern is
  still read. Best for small/medium repos; cost scales with repo size (this is the "scan everything" mode).
- `--interactive` — before deep-reading, wave proposes the file set and lets you **prune or extend** it
  (`drop N,M` / `add <substr>` / `list` / `quit`); tree-sitter effectively proposes the file list and you
  curate it. Without it, wave auto-proceeds.
- `--notes-budget N` / `--detect-budget N` / `--prove-budget N` — bound each stage. For the notebook: **at or
  below N, ALL pinned files are read** (full coverage, default 40); only when pinned files *exceed* N does the
  model select the N worth deep-reading. Lower it on a monorepo, raise it for full small-repo coverage.
- `--online` — give the model opt-in `web_search`/`web_read` (network egress) for unfamiliar APIs; off by
  default (the box stays local).
- `--jobs N` — run **N model tasks at the same time** across every model-heavy stage — the **notebook**
  (Stage 1b, the slow one on big repos), **detect**, **prove**, **patch**, and deep-reconcile (default **1** =
  serial). You must give a **number** — there is no "use all cores" mode; `N` is the max concurrency.
  - **Cloud model only.** Parallelism runs N model calls + N docker sandboxes at once. That's fine for a cloud
    model (deepseek/OpenRouter), so it's enabled there. A **local** single-GPU model can't generate in
    parallel, so wave **auto-falls back to `--jobs 1`** and prints a note.
  - **Sizing (per box, not cores):** each proof uses a light container (~0.5 GB) but a *compiled build*
    (cargo/gradle/npm) can spike ~2 GB + 2 CPUs. On a **32 GB / 6-core** box, **`--jobs 4`** is the sweet spot;
    drop to `2` for repos full of compiled-language builds, go up to `6` for light Python/JS. **Dependency
    installs** (`pip install <bigpkg>` / `npm install`) are serialized across jobs by default (they're
    memory-heavy — 4 at once can OOM the box); raise with `WAVE_INSTALL_JOBS=2` if you have RAM to spare.
  - It's a **speed** knob only (turns the ~45-min serial runs / timeouts into ~4× faster) — it does **not**
    change *which* findings you get. Distinct from the `--*-budget` flags below, which set *how many* items each
    stage looks at.
- `--patch` — run Stage 4 (dry-run by default; add `--write` to keep a patch that passed both gates).
- `--no-reach-gate` — disable the reachability gate (use on libraries with public-API entry points, no routes).

Read **`<repo>/wave_results/wave_report.md`** — the human-readable findings (regenerate anytime with
`wave report <repo>`). The machine artifacts also land in the repo: `wave_findings.jsonl` (verdicts) and
`casefile.json` (full investigation report). Every stage is **resumable** — re-run to continue; a terminal
verdict is skipped, a `believed`/`blocked` lead is retried.

### 4. Or run a single stage

```bash
wave eyes   <repo> [--notes] [--all-files] [--interactive]  # map + index; --notes runs the notebook
wave detect <repo>                                          # clean-room falsify the notebook's findings
wave prove  <repo> [--online]                               # the confirmation ladder
wave patch  <repo> [--write]                                # patch + reverify the confirmed findings
wave report <repo>                                          # (re)generate the readable report
```

`wave eyes <repo>` with no flags is instant (deterministic map + attack-surface index, no model). Add
`--notes` to run the model's per-file notebook; combine with `--all-files` to read the whole repo or
`--interactive` to curate the file set first. Model/endpoint settings live under `wave config set`/`wave config show`.

---

## Models & the local-model plan

Detection and exploitation are meant to stay **local**; a strong cloud model is supported for capability
testing and hard targets. A measured experiment (see the docs) showed a stronger reasoner turning the local
model's *timeouts* into real, tool-witnessed confirms — so the harness is mature and the model is the ceiling.

The path back to a capable *local* model is **trace distillation**: use a strong model to drive the harness,
let the harness **certify** which drives ended in a real observed effect, and fine-tune the local model to
imitate only those. The trace-logger and a plain-language guide are built:

- turn capture on with `WAVE_TRACE=1` (or `WAVE_TRACE_DIR=<path>`) and run normally — every *verified* drive
  is banked to `traces/wave_traces.jsonl`;
- see [`agent/docs/trace_training.md`](agent/docs/trace_training.md) for the how and why.

---

## Repo layout

```
agent/orchestrator/     the pipeline
  codemap.py  repomap.py       Stage 1  structure map + security pins (11 languages)
  notebook.py                  Stage 1b per-file model notes
  detector.py                  Stage 2  clean-room falsification
  prove.py  rung1.py           Stage 3  driver + deterministic canary observer
  investigate.py  execute.py   Stage 3  model tool-use loop + sandboxed executor
  briefs.py  repro.py js_env.py Stage 3 per-class proof recipes + scaffolds
  reachability.py  taint.py    the honesty gates
  audit.py                     Stage 3  the fresh-auditor evidence audit
  patch.py                     Stage 4  patch + reverify
  traces.py                    trace-logger (training data)
  model.py                     local/cloud model interface
  run.py                       CLI entry
agent/bench/ghsa_bench.py      the real-CVE benchmark harness
agent/docs/                    the architecture plan + design docs
tests/                         `pytest tests/ -q`  (deterministic; no GPU/docker/model)
```

---

## Status & honest limits

- **Proven end-to-end on real code and fixtures:** command injection, IDOR (differential), C/C++ buffer
  overflow (ASan), deserialization — each a real, grounded, tool-witnessed confirmation.
- **Detection is the current recall bottleneck for libraries** — the map is sink-driven, so a library whose
  vuln lives in an exported function with no classic sink can go unsurfaced (the proof engine never gets a
  shot). Apps with routes/sinks work well.
- **No deterministic canary for non-Python/JS languages** — they prove via the model-driven path.
- **The local model is the ceiling.** The harness is mature; a weak reasoner thrashes where a strong one
  drives straight to a proof. That's what trace distillation is for.

Run the tests to see what's verified:

```
pytest tests/ -q
```
