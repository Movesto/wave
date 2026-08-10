# CPG (Joern) build — scope

## Why

The agentic audit (witness + `prove_safe`) reached **5/8 pairs** on the harder set. Every
remaining failure is **battery coverage**, not model reasoning: a guard/sink shape the
6-class witness and `prove_safe` don't model (command metachar-strip, ssrf host-allowlist,
path resolve+prefix). A Code Property Graph gives **general dataflow** instead of hand-coded
shapes, which is what generalises past the long tail. This is also AEGIS's design (its −54%
FPR comes from CPG-grounded audit) and CPRVUL's (selective CPG context).

## What the CPG changes (and does NOT)

The CPG does **not replace** the witness/`prove_safe`. It supplies the *precise evidence*
they judge:

- Today: `witness_scan(code, kind)` scans the **whole function** with regex → over-flags when
  a guard is on the wrong variable or a neutraliser comes after (the `witness_slice.py` bug).
- With CPG: query the real **source→sink flow** and the guards/transforms **on that path**,
  then run the witness/`prove_safe` on that slice. Fixes wrong-variable + order-of-ops.
- For the long tail (no witness shape): the CPG-grounded path still **bounds the model's
  reasoning** (AEGIS) — it reasons about the actual flow, not a fabricated one.

So the CPG feeds three existing seams: `witness_scan`, `prove_safe`, and the agent audit.
It is a general version of `witness_slice.backward_chain` (regex → real PDG slice) and of
`flag._js_taint` (regex taint → CPG dataflow).

## THE GATE (Phase 0) — do this before committing anything else

Everything rests on one question: **can Joern's JS/TS frontend give us, for one of our real
functions, the source→sink flow AND the guard on that path, as machine-readable output?**
If not, the whole plan is dead and we stop at ~1 day sunk instead of ~2 weeks.

Phase 0 tasks:
1. Install a JDK 21 (no Java on this box today) + Joern (`joern-install`). Decide runtime:
   **Windows-native JVM vs WSL vs Docker** (WSL likely smoothest; Docker most reproducible).
2. `joern-parse` a CPG for `harder_cases` case 0 (path decode-after-check) and case 7
   (execFile arg-array), written to real `.ts` files.
3. Write ONE CPGQL/Scala query that emits JSON: does `name`/`file` reach the fs sink, and
   what calls (`decodeURIComponent`, `basename`, `execFile`) sit on the path?
4. **Gate check:** the JSON must let us reconstruct "guard/transform X is on the path from
   source to sink." If Joern mis-parses modern TS or can't express the path query cleanly →
   NO-GO on Joern; fall back to the lighter alternatives below.

Effort: **0.5–1 day.** Decisive.

## Phased build (only past the gate)

- **Phase 1 — slice extractor** (2–3 d): Python↔Joern via `joern --script` Scala queries
  emitting JSON; per-repo CPG cache; a `cpg_slice(file, fn, sink) -> {source, sink, path,
  guards[], transforms[]}` contract. Test on all 16 harder cases.
- **Phase 2 — rewire + re-eval** (2–3 d): `witness_scan` and `prove_safe` consume the slice
  (guards/transforms on the path) instead of the whole function. Re-run the 16 harder cases
  and the 20 real-corpus cases; measure vs the current 5/8 and 1/10.
- **Phase 3 — grounded reasoning for the tail** (3–5 d): feed the CPG slice to Qwen3.5-9B as
  bounded evidence (AEGIS "closed factual substrate"), so its judgment on un-modelled shapes
  is grounded not hallucinated. Re-eval.
- **Phase 4 — real repos / languages** (open): CPG on Juice Shop/DVNA; broaden beyond JS/TS.

**Total to a working CPG-grounded audit: ~2 weeks focused.**

## Risks (honest)

1. **Joern's JS/TS frontend** is weaker than its C/C++/Java frontends; modern TS may
   mis-parse. → Phase-0 gate is exactly this check, on our real files.
2. **Per-repo CPG build cost** (minutes) → cache CPGs; only rebuild on change.
3. **Windows + JVM friction** → prefer WSL/Docker; decide in Phase 0.
4. **Heavier stack** (JVM subprocess + Scala) than our pure-Python tools → isolate behind the
   `cpg_slice` contract so the rest of the code doesn't know Joern exists.
5. **The tail still leans on the model** for semantics no analysis interprets — CPG makes that
   grounded, not solved.

## Lighter alternatives (decision point — user asked to scope Joern, but for honesty)

| Option | Coverage | Weight | Note |
|---|---|---|---|
| **Joern CPG** | full dataflow, any lang | heavy (JVM) | this doc; AEGIS/CPRVUL use it |
| **Semgrep taint mode** | good intra/some inter-proc | medium, Python-friendly | faster to integrate, less complete |
| **tree-sitter + hand slice** | intra-proc only | light | ~ extends `witness_slice.py`; no real PDG |

If the Phase-0 gate fails or 2 weeks is too much, **Semgrep taint** is the medium fallback: it
gives real dataflow with far less setup, at the cost of completeness.

## Decision points for the user

1. Runtime: **WSL / Docker / Windows-native** for the JVM+Joern.
2. Commit to the **Phase-0 gate first** (1 day) before the full ~2-week build — recommended.
3. **Joern vs Semgrep-taint** as the dataflow engine (scope both; gate decides).
4. Scope **JS/TS only** first (our domain), not general multi-language.

---

## Phase 0 RESULT (2026-08-08) — GATE PASSED, via Semgrep (the hedge won)

Environment: no JDK on box; Docker 29.3.1 available (daemon started); WSL Ubuntu present but
no passwordless sudo / no pip. Chose **Docker** as the runtime (no JVM/Windows friction).

Hedged the gate: tried the LIGHTER engine (Semgrep taint) first. It **passed cleanly**, so the
heavy Joern install was not needed for Phase 0.

Test: two real `.ts` files (phase0_cpg/) — a path-traversal SOURCE→SINK where the only
difference is what sits on the path (decodeURIComponent-after-check vs path.basename). A
custom Semgrep taint rule (source `req.query.$X`, sink `fs.readFileSync(...)`, sanitizer
`path.basename(...)`):
    vuln_path.ts (basename NOT on path) -> FLAGGED         (want flagged)  ✓
    safe_path.ts (basename ON path)     -> not flagged      (want cleared)  ✓
    trace: reports SOURCE line 6, SINK line 9, "intermediate variables" on the path ✓

This is exactly the gate: the engine expresses source / sink / **neutraliser-on-the-path**
and correctly discriminates the case where whole-function regex over-flags. `pattern-
sanitizers` == our `prove_safe` neutraliser, evaluated on the real dataflow path.

**DECISION: use Semgrep taint as the dataflow engine.** It answers the gate with far less
weight than Joern (Docker image, CLI/JSON, no JVM/Scala), and maps cleanly onto our seams:
Semgrep sources/sinks/sanitizers -> the slice that `witness_scan` / `prove_safe` judge.

**Joern DEFERRED to Phase 4**, only if cross-file / deep inter-procedural CPG queries exceed
Semgrep taint's reach (Semgrep is strong intra-proc + limited inter-proc; Joern is a full CPG).

Phase-1 starting point: phase0_cpg/taint_rule.yaml + the Docker invocation in
run_semgrep.sh. Open detail: get the dataflow trace into JSON (flag/version), for AEGIS-style
grounding — the text output already contains it.

---

## Cross-file test across all repos (2026-08-08) — JOERN IS JUSTIFIED (flips the DVNA call)

Tested the dataflow audit on every repo we've used, specifically for CROSS-FILE flows
(free/OSS Semgrep taint is INTRA-FILE only; interfile needs Semgrep Pro or a CPG like Joern).

| Repo | Architecture | Intra-file Semgrep | Finding |
|---|---|---|---|
| DVNA | Express, one controller | 6/6 caught | intra-file; no gap |
| brokencrystals | NestJS controller->service | **0 across 324 files** | ALL flows cross-file -> MISSED |
| juice-shop | Express, mixed | 11 (mostly self-contained codefix snippets) | real route->model flows likely missed |
| Manga_Ryu | FastAPI (Python) + React | 0 | language mismatch (JS rules) -- not measured |

**A/B PROOF (phase3_xfile/ab_*):** the SAME NestJS command-injection flow (@Body -> spawn):
    inlined in ONE file  -> Semgrep FINDS it   (1)
    split controller.ts + service.ts -> Semgrep MISSES it (0)
Same source, same sink; the only variable is the file boundary. Isolates cross-file as the
cause, not source patterns.

**brokencrystals real flow:** `@Body() data` (app.controller.ts) -> `this.appService
.launchCommand(data.command)` -> `spawn(exec, args)` (app.service.ts, DIFFERENT FILE).
Intra-file taint cannot connect them; 0 findings on the whole repo despite it being
deliberately vulnerable.

**VERDICT — this FLIPS the DVNA conclusion.** DVNA said "Joern not needed" because DVNA is a
toy with source+sink in one function. Real production frameworks (NestJS, and any
controller/service or route/model split) put source and sink in DIFFERENT files -> free
intra-file Semgrep is blind to them. So: Joern (or Semgrep Pro interfile) IS justified, and
the repo class that needs it is exactly the realistic one. DVNA/juice-codefixes were the
easy intra-file case; brokencrystals is the real one.

Next: Phase-0-style gate for Joern's JS/TS INTERFILE dataflow on the brokencrystals
controller->service flow (the phase3_xfile/ab_split A/B is the ready-made test case).

---

## Python precision measurement (2026-08-09) -- the concern was WRONG; recall is the real gap

Set out to measure the broad PHP/Python rules' precision (false-positive rate) on real safe
Python, using mined corpus data + the data/clones repos.

What happened:
- **Clones unusable**: data/clones/* are BARE git repos (only .git packfiles, no working
  tree; `git -C` even falls back to our repo). No files to scan without repair.
- **Corpus safe snippets (76 with a request source)**: 0 flagged -- but only 6 had a
  dangerous sink, so 0 FP is near-trivial.
- **Contrastive Python pairs with request-source AND sink (16 vuln + 16 safe)**: with a
  Python SQL sink added, recall was **1/16 vuln**, 0/16 safe.

**FINDING (honest, and it flips the concern):** on real corpus Python the rules barely fire
(recall ~1/16), so precision (over-flagging) is NOT the binding constraint -- 0 FP everywhere
is a symptom of UNDER-firing, not accuracy. Root causes: (1) real flows go request -> var ->
`"...{}".format(var)`/f-string -> `cursor.execute` and Semgrep intra-file taint doesn't track
the string-building reliably; (2) diverse/indirect sinks; (3) 7/32 corpus records are function
FRAGMENTS (start mid-function) that break taint scope.

Same shape as the cross-file result: Semgrep taint works on SIMPLE/DIRECT flows (YWH snippets
14 flagged, DVNA 6/6) but under-fires on realistic Python with indirection. The lever for real
Python is stronger dataflow (Semgrep Pro interfile, or format-string-aware sink patterns), not
precision tuning. Sanitizer mechanism itself is sound (prior 5/5 escapeshellarg/basename/
shlex.quote test). Added py-sql rule (cursor.execute) to rules.yaml regardless.

---

## CodeQL on the REAL repos (2026-08-09) -- benchmark result HOLDS on production code

Ran CodeQL (javascript-security-extended) on the actual repos, vs Semgrep OSS:

| Repo | Semgrep OSS | CodeQL total | CodeQL real-injection | CodeQL cross-file |
|---|---|---|---|---|
| brokencrystals (NestJS) | **0** | 30 | 23 | **18** |
| DVNA (Node, toy) | 6/6 | 33 | 6 | 1 |
| juice-shop (mixed) | 11 | 91 | 26 | 9 |

**Headline: brokencrystals 0 -> 30 (18 cross-file).** CodeQL traced controller->service flows
(email.controller.ts:57 -> email.service.ts:74, file.controller.ts:86 -> file.service.ts:17,
etc.) that intra-file Semgrep is structurally blind to -- and it recognised NestJS @Body/
@Controller sources. DVNA has only 1 cross-file finding -> confirms it's a TOY (same-file
flows), which is why Semgrep did fine on it. juice-shop has 9 real cross-file flows Semgrep
missed.

**Honest caveat:** the security-EXTENDED suite adds quality-check NOISE (missing-rate-limiting,
stack-trace-exposure, polynomial-redos): 6/30 on bc, 25/33 on DVNA, 40/91 on juice. Use the
standard `javascript-security.qls` suite (not -extended) to cut it, or filter to injection
classes. The real injection signal (23 / 6 / 26) is what matters.

CONCLUSION: the interfile ceiling is resolved on real code, not just the synthetic benchmark.
CodeQL is the cross-file engine; keep Semgrep for fast intra-file and witness/prove_safe for
guard reasoning. Wiring CodeQL into scanner/pipeline.py as Station 1c (cross-file find) is the
concrete next build.
