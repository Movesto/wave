# Wave — Data Inventory & Topic Report
*Generated 2026-06-26 by direct inspection of every dataset on disk.*

This report answers: **what data do we actually have, what topics does it cover,
what's converted vs. raw, and what to consider before using each source.**

---

## 0. Executive summary

| Layer | What it is | Volume |
|---|---|---|
| **CoT traces (converted)** | What the scanner trains on today | **8,132** traces |
| **SFT pairs** | Instruction/response pairs (detect / generate / explain) | **172,733** pairs |
| **Raw vuln sources** | Patches + labeled code, convertible to traces | **~80K** items (~5 GB) |
| **Pretrain corpus** | Plain code text for domain pretraining | **4.2 GB** |

**Headline:** we have converted **~5%** of what's convertible. The data is heavily
**web-vuln / injection focused** (XSS, SQLi, path traversal, SSRF dominate) and
heavily **Python/JS/TS**. The biggest untapped, highest-quality reservoir is
**R2Vul's C/Java/C# rows (~13K, ship expert reasoning + CWE)** and the
**32K patch corpus** (PHP/C/Java/Go barely touched).

---

## 1. Converted CoT traces — 8,132 (what the model learns from)

### By task shape
| Shape | Count | Meaning |
|---|---|---|
| shape1 | 4,062 | local scan (py/js, R2Vul expert reasoning) |
| shape1_verified_safe | 854 | safe code, oracle-gated |
| shape1_verified | 825 | vuln, oracle-gated |
| shape_react_syn | 600 | synthetic React |
| shape1_ts_safe | 534 | safe TypeScript |
| shape1_ts | 454 | vuln TypeScript |
| shape4 / shape3 / shape2 | 321 / 204 / 113 | synthesis / cross-file / needs-context |
| shape1_react_safe / shape1_react | 107 / 58 | React safe / vuln |

### By quality tier
`expert` 4,062 · `oracle` 1,679 · `weak` 1,153 · `context` 638 · `synthetic` 600

### By label  (well balanced)
`safe` 4,004 · `vuln` 3,598 · `synthesis` 321 · `needs_context` 113 · `confirmed` 96

### By language
`python` 3,304 · `javascript` 2,487 · `typescript` 1,175 · `react` 845 · `mixed` 321

### Topics covered — 166 distinct CWEs. Top 25:
```
CWE-79  XSS .................. 1341     CWE-352 CSRF ............... 108
CWE-89  SQL injection .........313     CWE-502 deserialization .... 97
CWE-22  path traversal ........296     CWE-400 resource exhaust ... 96
CWE-918 SSRF ..................270     CWE-863 authz .............. 87
CWE-94  code injection ........264     CWE-287 authentication ..... 83
CWE-20  improper input val ....250     CWE-284 access control ..... 76
CWE-200 info exposure .........240     CWE-532 log info leak ...... 73
CWE-601 open redirect .........236     CWE-611 XXE ................ 71
CWE-1321 prototype pollution ..220     CWE-74  injection (generic). 66
CWE-78  OS command injection ..150     CWE-347 sig verification ... 58
                                       CWE-1333 ReDoS ............. 57
                                       CWE-95  eval injection ..... 54
                                       CWE-327 weak crypto ........ 40
```
**Reading:** strong on **web injection** (XSS/SQLi/SSRF/path-traversal/redirect),
decent on **auth/access & deserialization**, thin on **crypto, ReDoS, resource
exhaustion (DoS)** — consistent with the eval blind spots.

---

## 2. SFT pair datasets — 172,733 pairs (27 files)

### By task type
| Tag | Task | Pairs |
|---|---|---|
| `<SCAN>` | detect vulnerability | **143,967** |
| `<GENERATE>` | write code | 22,438 |
| `<EXPLAIN>` | explain code | 6,200 |
| other/plain | misc | 128 |

### Per-file (sorted by size)
| File | Pairs | What it is | Notes / quality |
|---|---|---|---|
| bandit_vuln_pairs | 71,638 | Python, Bandit-flagged vuln/safe | static-analyzer labels (noisy) |
| kaggle_vuln_pairs | 35,000 | **Java** SQLi etc. | templated/synthetic → **dedup risk** |
| morefixes_pairs | 24,040 | CVE fix hunks (multi-lang) | overlaps the patch corpus; fragmenty |
| alpaca_generate_pairs | 18,238 | code-generation prompts | `<GENERATE>` task |
| all_sft_pairs | 9,489 | combined/curated mix | aggregate of others |
| cybernative_vuln_pairs | 3,100 | multi-lang vuln examples | model-sourced |
| codefeedback / glaive_explain / rstarcoder | 2,000 each | generate / explain / explain | task variety |
| securecode_pairs | 1,102 | secure-coding Q&A | `<SCAN>` style Q&A |
| python_remediation_pairs | 1,005 | Python fix suggestions | remediation |
| clean_code_mined | 800 | known-safe Python | safe-side training |
| explain_pairs / generate_pairs | 600 each | explain / generate | |
| cvefixes_pairs | 566 | CVEfixes-derived | multi-lang |
| clean_code_pairs / claude_generated | 158 / 136 | safe / Claude-authored | high quality, small |
| vuln_pairs / clean_code_generated | 64 / 65 | seed vuln / safe | tiny |
| js_vulns / python_vulns / clean_js_react / clean_python | 30 each | hand seeds | tiny, clean |
| multi_function | 20 | multi-function scans | tiny |
| **fixjs / lingcoder / secjs** | **0** | **EMPTY** | never populated — investigate or drop |

**Consider:** the SFT layer is dominated by **bandit (72K, analyzer-noisy)** and
**kaggle (35K, synthetic Java — high duplication risk)**. The *clean* hand/Claude
sets are tiny but trustworthy. Most `<SCAN>` pairs lack CWE + an oracle, so they're
weaker raw material than patches/R2Vul for the verified pipeline.

---

## 3. Raw vulnerability sources (convertible to traces)

### 3a. morefixes patch corpus — 32,008 `.patch` files (3.2 GB)
- Clean unified diffs → the **patch-diff oracle** localizes the vuln (high quality).
- Sink-relevance-filtered hunks seen: **python 5,231 · javascript 5,195 ·
  typescript 1,133 · react 254** (React is a hard ceiling).
- **Untapped:** PHP / C / Java / Go hunks are largely unconverted — the **biggest
  language-expansion opportunity**.
- Converted so far: ~1,679 verified traces. **~30K patches unconverted.**

### 3b. R2Vul — 18,334 rows (train 14,678 / val 1,818 / test 1,838) — 133 MB
- **Richest metadata:** `lang, vulnerable, function, file, repo, cve_id, cwe_id` +
  ships expert reasoning → **cheapest to convert (no model call, CWE included).**
- Languages: **C 9,581 · Python 3,093 · Java 3,074 · JavaScript 2,142 · C# 444**.
- Labels ~50/50 vuln/safe.
- **Used so far: Python + JS only (~4,191).** → **C / Java / C# (~13K) untapped and
  highest-value to convert next.**

### 3c. CVEfixes CSV — ~31,194 rows (1.5 GB)
- Columns: `code, language, safety` only. **No CWE, no fix-pairing/oracle.**
- Perfectly balanced: **15,597 vulnerable / 15,597 safe.**
- Languages: C 8,632 · Other 6,122 · **PHP 5,590** · py 1,564 · js 1,562 · java
  1,162 · ruby 1,120 · cpp · go · html …
- **Consider:** convertible to *safe-explain* traces easily, but VULN traces would
  need CWE classification + can't be oracle-localized → **lower-quality raw material**
  than patches/R2Vul. Best used for the safe side or after a CWE-labeling pass.

---

## 4. Pretrain corpus — 4.2 GB
Plain code text (`data/pretrain/`). Not trace-convertible — it's for an optional
**domain-adaptive pretraining** stage (continue-pretraining the base model on
security-relevant code before fine-tuning). Separate lever, not part of the trace
pipeline.

---

## 5. Coverage map — what's well covered vs. gaps

| Dimension | Well covered | Thin / gap |
|---|---|---|
| **Vuln class** | XSS, SQLi, SSRF, path traversal, open redirect, code injection | crypto (327/347), ReDoS (1333), DoS/resource (400/770), auth edge cases |
| **Language** | Python, JavaScript, TypeScript | React (genuine ceiling), **C, Java, C#, PHP, Go (lots of raw, little converted)** |
| **Task type** | detect (`<SCAN>`) | generate / explain present but secondary |
| **Label balance** | safe vs vuln ~balanced in traces & raw | — |

---

## 6. What to consider (quality & pitfalls)

- **Oracle availability tiers the quality:** patches & R2Vul carry a ground-truth
  localizer (diff / cwe_id) → best traces. CVEfixes & most SFT `<SCAN>` pairs don't
  → weaker, need extra labeling.
- **Duplication risk** on synthetic/templated sets (kaggle 35K, react_syn) — always
  dedup by content before training (we've been bitten by this before).
- **CWE presence** is the divider: R2Vul + patches have it; CVEfixes + bandit don't.
- **Three empty SFT files** (fixjs, lingcoder, secjs) — collection never completed.
- **morefixes_pairs (SFT) overlaps the patch corpus** — don't double-count.
- **Pretrain & CVEfixes are big in GB but not directly trace-usable** — size ≠ usable traces.

---

## 7. Best conversion opportunities (ranked by value/effort)

1. **R2Vul C / Java / C# (~13K)** — cheapest & highest quality (expert reasoning +
   CWE, no model call). Adds 3 new languages instantly.
2. **Patch corpus other-languages (PHP/C/Java/Go)** — oracle-gated, large supply.
3. **Target weak CWE families** (crypto / ReDoS / DoS) by mining patches + R2Vul for
   those `cwe_id`s — fills the eval blind spots.
4. **CVEfixes safe side (~15.6K)** — easy safe-explain traces to cut false positives
   (no CWE needed for the safe branch).

*Bottom line: ~5% converted; the remaining 95% is dominated by other-language
vuln code (C/Java/PHP) that the current py/js/ts-centric pipeline hasn't touched.*

---

## 8. FULL-DISK SWEEP (2026-06-26) — everything, incl. previously-unlisted

A complete pass over `data/` and the repo root turned up sources not in the
sections above:

### Newly surfaced datasets
| Source | Size / count | What it is | Status |
|---|---|---|---|
| **FixJS** (`data/downloads/FixJS`) | **66,497 before/after JS function pairs** (133K files) | general JavaScript **bug-fix** pairs (size-bucketed before/after) | **RAW, unconverted.** Not security-labeled — mostly general bugs; would need security filtering. The empty `fixjs_pairs.jsonl` was never built from this. Big JS reservoir. |
| **cve-fix-pairs** (`.../cve_fix_pairs.csv`) | **40 rows** | high-quality cross-lang CVE fix pairs (Go/PHP/Py/Java/C) w/ `vulnerability_type`, method granularity | tiny but clean; likely already a fix_pairs source |
| **vulnerability-fix-dataset** (`.../vulnerability_fix_dataset.csv`) | **35,000 rows** | synthetic XSS/SQLi/cmd/path-trav/buffer-overflow templates | **= the raw form of `kaggle_vuln_pairs` (already in SFT).** Synthetic, dedup risk. Not new. |
| **SecJS** (`data/downloads/SecJS`) | 64 files | a JS-CVE collection **tool** (ArenaJS/ForgeJS/JudgeJS), not data | **no dataset** — explains the empty `secjs_pairs.jsonl` |

### Archives at repo root — all duplicates of already-extracted data
- `archive (2).zip` (374 MB) → CVEFixes.csv (already in `data/downloads/CVEfixes`)
- `archive.zip` → vulnerability_fix_dataset.csv (already extracted)
- `archive (1).zip` → cve_fix_pairs.csv (already extracted)
- `cvedataset-patches.zip` (1.8 GB) → the morefixes patches (already extracted)
- `r2vul_dataset.zip` (35 MB) → R2Vul (already extracted)
- `files.zip` → collection scripts (code, not data)
→ **No new data hiding in the zips.**

### Pretrain corpora (`data/pretrain/`) — for domain pretraining, not traces
- `all_python.txt` 579 MB · `thestack_python.txt` 487 MB · `github_python.txt` 72 MB · `security_python.txt` 21 MB
- `security_repos/` 26,057 files · `repos/` 34,019 files (cloned Python repos)
- Python-only; usable to continue-pretrain the base model, **not trace-convertible**.

### Model checkpoints (not data) — for reference
`pretrain_500m.pt` 1.2 GB, `pretrained_model.pt` 30 MB, `sft_model.pt` 30 MB,
`merges.pkl` — artifacts of an earlier from-scratch/SFT effort, plus all the
`qwen_cot_v1…v8`, `qwen_r1_14b`, `qwen_scanner` adapter dirs.

### Cross-file / multi-hop material (patch corpus only)
- **17,342 / 32,008 patches are multi-file** (≥2 files changed).
- Multi-file **with ≥2 code files** by language: c 2,655 · php 2,134 · py 1,506 ·
  java 1,363 · js 1,205 · go 1,192 · ts 313 · tsx 47 …
- **JS/TS cross-file candidates: 1,738** (incl. Vue). **React-specific: 139** (.jsx/.tsx).
- Many are **full-stack** (TS/JSX frontend + Go/Py backend) → ideal multi-hop flow.
- R2Vul / CVEfixes / SFT are **single-unit** (one function/snippet) → no cross-file.

### FINAL TALLY — unconverted but usable
| Reservoir | Approx usable | Quality |
|---|---|---|
| morefixes patches (other langs + cross-file) | ~30,000 patches | high (oracle) |
| R2Vul C/Java/C# | ~13,000 | **highest (expert reasoning + CWE)** |
| CVEfixes (multi-lang, safe side esp.) | ~31,000 | medium (no CWE/oracle) |
| FixJS JS bug-fix pairs | ~66,000 | low for vuln (general bugs; filter needed) |
| cve-fix-pairs | 40 | high but tiny |
| (synthetic vuln-fix-dataset = kaggle) | (35,000) | already used / synthetic |

**Grand total genuinely-new convertible: ~75K–140K items** depending on how much
FixJS/CVEfixes you accept. Cross-file JS/TS/React specifically: **~1,700 candidates
(139 pure React).** Pretrain corpora (~1.1 GB Python text) are a separate lever.
