# Wave Scanner — a multi-stage AI security analyst

A "car wash" pipeline where each station is a specialized tool. Fast deterministic
engines **find** candidate vulnerabilities; the fine-tuned model **triages and
explains** them; a patch library **suggests the fix**. The model only ever runs on
the handful of flagged functions — not the whole repo — so it's fast *and* precise.

This is the opposite of "run an LLM on every function" (slow, and it hallucinates on
clean code). Here the LLM does what it's good at — reasoning about flagged code —
while cheap, precise tools do the scanning.

## The stations

| Station | Tool | Job | Runs on |
|---|---|---|---|
| **1a** | `flag.py` | taint (source→sink) + pattern anti-patterns | CPU, ms/file |
| **1b** | `embed.py` / `retrieve.py` | semantic resemblance to 23K known CVEs | CPU |
| **2** | `pipeline.py` → model | triage: "real vuln or false positive?" + reasoning | GPU |
| **2c** | `guard_witness.py` | **proves** a present guard is bypassable (deterministic) | CPU |
| **3** | `patches.py` | concrete before→after remediation for the CWE | CPU |

**Confidence tiers** (from combining signals):
- **HIGH** — taint engine *and* model agree
- **MEDIUM** — CVE-resemblance *and* model agree, **or the witness proved a guard bypassable**
- **REVIEW** — a single signal only

### Station 2c — the guard-witness verifier

The model's weak spot is *completeness*: it sees `if (!file.includes("/"))`, decides the
code is guarded, and calls it safe — without checking that `..%2f..%2f` sails through. The
witness closes that gap deterministically. For six guard classes it reimplements the guard's
actual logic and runs it against known bypass inputs; if the guard admits one, it's a finding
**even when the model said safe**, and the report prints the exact bypass.

| Class | CWE | Example bypass it proves |
|---|---|---|
| open redirect | 601 | `/\evil.com` |
| path traversal | 22 | `..%2f..%2f`, `/etc/passwd` |
| command injection | 78 | `--output=/etc/passwd` (argument injection past `escapeshellcmd`) |
| SSRF | 918 | `127.1`, `169.254.169.254` (past a localhost denylist) |
| prototype pollution | 1321 | `constructor` (past a `__proto__`-only blocklist) |
| XSS | 79 | `<img src=x onerror=…>` (past a `<script>`-only filter) |

It only ever speaks when it can **prove** insufficiency — a proper guard (`new URL().origin`
allowlist, `realpath`+prefix, `escapeshellarg`, DOMPurify, a resolve-then-check SSRF guard)
is left alone, never flagged.

## Test it on your own code

Point it at a file or a whole project directory (Python + JS/TS/JSX/TSX). It skips
`node_modules`, `venv`, `.git`, tests, and minified bundles automatically.

**Fastest way to try it — no GPU, no model download, instant:**

```bash
python scanner/pipeline.py path/to/your/project --no-model --no-recall
```

`--no-model` runs Stations 1a + 2c + 3 only: taint finds the sinks, the **guard-witness
verifier proves any bypassable guards**, and the patch library suggests fixes — all on CPU
in milliseconds. This is the best way to see the witness in action without waiting on the 8B.
Confidence reads `MEDIUM (witness: guard proven insufficient)` when it defeats a guard, and
`REVIEW (taint flags)` for a raw sink.

**Full pipeline (adds the model's triage + reasoning — needs the GPU):**

```bash
python scanner/pipeline.py path/to/your/project          # flag → triage → witness → patch
python scanner/pipeline.py app.py --json                 # machine-readable output
python scanner/pipeline.py app.py --fix                  # annotate files with review comments (backs up to .bak)
python scanner/pipeline.py app.py --no-recall            # skip the CVE-resemblance net (a bit faster)
```

The model is only loaded for the full run, and only triages the handful of flagged
functions — so even a large repo runs the GPU on a few functions, not the whole tree.

**Other entry points:**

```bash
python scanner/flag.py src/                     # Station 1 only: the raw taint/pattern candidates
python scanner/deps.py path/to/project          # dependency (SCA) scan: known-vulnerable npm versions vs OSV
python scanner/scan.py app.py --sarif           # standalone model scan → SARIF for GitHub Code Scanning / IDEs

# one-time, only needed for the CVE-resemblance net (Layer B); not needed with --no-recall
python scanner/embed.py build                   # neural (semantic, recommended)
python scanner/retrieve.py build                # or TF-IDF (no model download)
```

**Reading the output:** findings are grouped `CONFIRMED` (HIGH/MEDIUM) and `FOR REVIEW`
(single signal). Each shows the file, function, line, the taint sink, the model's verdict
(or `None` with `--no-model`), and — when the witness fired — the **exact bypass input** that
defeats the guard, plus a before→after patch.

## Coverage

**Taint (source→sink), Python + JS/TS:** SQL injection (CWE-89), command injection
(78), path traversal (22), SSRF (918), XSS (79), code injection (94), deserialization
(502), prototype pollution (1321).

**Pattern anti-patterns** (precision-gated), both languages: weak crypto (327),
verbose-error info-exposure (209), TLS-verify-disabled (295), hardcoded secrets (798),
dynamic eval (95), insecure randomness (338), XXE (611).

**Guard-witness (Station 2c), deterministic:** open redirect (601), path traversal (22),
command injection (78), SSRF (918), prototype pollution (1321), XSS (79) — proves a
*present but insufficient* guard, with the concrete bypass.

**Retrieval:** semantic resemblance to 23,475 real known-vulnerable snippets across
224 CWEs, mined from CVE patches + R2Vul.

**Dependencies (`deps.py`):** matches `package.json` versions against the OSV npm advisory
dump (SCA) — the one class wave's code-analysis stations do *not* cover.

## Why this beats a model-only scanner

On a real, well-secured FastAPI app, the model alone produced **10 findings — all
false positives** (it flags any SQL/HTTP-shaped code). The taint engine produced
**0 false positives** on the same files and correctly caught the one real issue
(a verbose-error info leak) via a pattern detector. The pipeline runs the model only
on genuine candidates, so it inherits the tools' precision.

## Requirements

```
pip install -r scanner/requirements.txt
```
Station 1 (flag/retrieve) is CPU-only. The neural embedder is a small (~90 MB) CPU
model. Only Station 2/3 (the fine-tuned 8B) uses the GPU — so the whole tool group
runs alongside it without contention.
