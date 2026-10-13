# wave

A local, autonomous agent that finds, **proves**, and fixes vulnerabilities — in a code repo (SAST) or against a live URL (DAST).

Its one rule keeps it honest:

> **A finding is `confirmed` only when the model caused an effect a tool actually observed.**
> Reasoning alone can only *propose* (`believed`). Only a witnessed effect confirms. Every false positive we ever saw came from a model concluding without acting — so acting is mandatory.

You run everything from one interactive CLI: type `wave`, then pick from a menu.

---

## 1. Install

Needs **Python 3.11+**. From the repo root:

```bash
pip install -e .
```

Add extras for what you'll run:

| To run… | Also install |
|---|---|
| **DAST** (`/dast`) — live-URL scanning, XSS, recon crawl | `pip install -e ".[dast]"` then `playwright install chromium` |
| A **local** model via transformers + LoRA | `pip install -e ".[local-model]"` |

- **Docker** is only needed for the white-box **proof** loop (it runs each exploit/patch check in a throwaway container). **DAST needs no Docker.**

---

## 2. Point it at a model

Copy the template and fill in four lines:

```bash
cp .env.example .env        # Windows: copy .env.example .env
```

```ini
WAVE_API_BASE=http://localhost:11434/v1          # local ollama (private) — or a cloud URL below
WAVE_API_KEY=                                    # blank for local ollama
WAVE_MODEL=<your-model>                           # the primary reasoner (finds / proves / patches)
WAVE_AUDIT_MODEL=<a-different-model>              # optional: a 2nd model that audits judgment calls
```

Cloud instead of local (stronger, but sends code off-box):

```ini
WAVE_API_BASE=https://openrouter.ai/api/v1
WAVE_API_KEY=sk-or-...
WAVE_MODEL=deepseek/deepseek-v4-flash-0731
```

Or just run `wave` → `/setup` and it writes the `.env` for you. (DAST needs no model.)

---

## 3. Run it

```bash
wave
```

That opens the interactive shell. The menu:

| Command | What it does |
|---|---|
| `/setup` | configure the model + endpoint |
| `/sast` | scan a **code repo** — paste the path, pick a depth (below) |
| `/dast` | scan a **live URL** — black-box, requires you confirm you're authorized |
| `/both` | SAST then DAST |
| `/help` | help, per feature: `/help sast`, `/help dast` |
| `/status`, `/config` | show readiness / current settings |

**`/sast` depths:**

```
1) discover        fast static candidates, no model (a quick look)
2) all             full scan of the security-surface files, NO patch      ← default
3) all --all-files full scan of EVERY source file, NO patch (thorough)
4) all --patch     full scan, plus auto-patch & re-verify confirmations
5) quick           eyes + detect + deps, no prove/Docker (fast first look)
```

Read the result in **`<repo>/WAVE_REPORT.md`** — what it **proved** (with evidence), what **needs review**, what it **cleared as safe**, and any **fixes**. Runs are resumable — re-run to continue.

> You never need to type a subcommand or a flag. The shell runs them for you. (Subcommands still exist as an advanced/scripting interface — `wave <command> -h` — but day-to-day use is just the menu.)

---

## What it finds

**SAST — vulnerability classes it can *prove* (a tool witnesses the effect):**

| Class | How it's witnessed |
|---|---|
| SQL / NoSQL injection | the payload reaches the query unparameterized |
| Command injection / eval | the injected command/code runs |
| SSRF | the payload controls the outbound request |
| Path traversal | a `../` payload survives to the file open |
| XSS | it executes in a headless browser |
| SSTI | `{{7*7}}` evaluates to `49` |
| Prototype pollution · Deserialization · ReDoS | a crafted input trips the specific effect |
| **C/C++ memory safety** | AddressSanitizer reports on a crafted input |
| **IDOR / broken access control** | a 2-identity differential: user A reads user B's data |

Classes it can't yet witness are reported as `believed` (a reasoned lead) — never a false `confirmed`.

**Also included in a full scan** (deterministic, no model): known-CVE **dependencies** (OSV.dev, ranked by whether the app actually imports them), **missing controls** (CSRF / rate-limit / cookie flags), **IaC** misconfig (Dockerfile / Compose / CI), and **secrets** in git history.

**DAST (`/dast <url>`)** — from a single URL, like an external pentester: DNS/TLS/port recon, HTTP posture (headers/cookies/CORS), OpenAPI/robots ingestion, injection (sqli/xss/stored-xss/path/redirect/ssti/eval/nosqli, + SSRF/RCE via an out-of-band callback), and differential IDOR / broken-access / rate-limit. It sends live attack traffic, so it refuses to run without you confirming authorization.

---

## Honest limits

- **SAST recall is sink- and route-driven.** Apps with routes and recognized sinks work well; a vuln in a function with no classic sink pattern can be missed. "No findings" means *wave didn't surface a provable one* — not a guarantee of safety.
- **The model is the ceiling.** A stronger reasoner proves more; a weak one leaves leads unproven. That's what the local-model trace-distillation path (see `agent/docs/`) is for.
- **DAST is black-box.** The output is a replayable HTTP PoC, not a patch; auth/IDOR/logic classes need the running app, and a WAF in front will mask app findings.

---

## Repo layout

```
agent/orchestrator/   the agent: the CLI (run.py), the interactive shell (shell.py),
                      the SAST pipeline (codemap/detector/prove/investigate/patch/…),
                      and the DAST engine (dast_*.py)
agent/docs/           the architecture plan + design notes
tests/                deterministic test suite  (pytest tests/ -q)
```
