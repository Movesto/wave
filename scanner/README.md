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
| **3** | `patches.py` | concrete before→after remediation for the CWE | CPU |

**Confidence tiers** (from combining signals):
- **HIGH** — taint engine *and* model agree
- **MEDIUM** — CVE-resemblance *and* model agree
- **REVIEW** — a single signal only

## Usage

```bash
# one-time: build the CVE-resemblance index (Layer B)
python scanner/embed.py build          # neural (semantic, recommended)
python scanner/retrieve.py build       # or TF-IDF (no model download)

# scan (the full car wash: flag → triage → fix → patch)
python scanner/pipeline.py path/to/code.py
python scanner/pipeline.py src/ --json
python scanner/pipeline.py app.py --no-recall   # skip Layer B (taint only, fastest)
python scanner/pipeline.py app.py --fix         # annotate files with security review comments (backs up to .bak)

# just the fast flagger (Station 1 only, no model/GPU)
python scanner/flag.py src/

# standalone model scan + SARIF (for GitHub Code Scanning / IDEs)
python scanner/scan.py app.py --sarif
```

## Coverage

**Taint (source→sink), Python + JS/TS:** SQL injection (CWE-89), command injection
(78), path traversal (22), SSRF (918), XSS (79), code injection (94), deserialization
(502).

**Pattern anti-patterns** (precision-gated), both languages: weak crypto (327),
verbose-error info-exposure (209), TLS-verify-disabled (295), hardcoded secrets (798),
dynamic eval (95), insecure randomness (338), XXE (611).

**Retrieval:** semantic resemblance to 23,475 real known-vulnerable snippets across
224 CWEs, mined from CVE patches + R2Vul.

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
