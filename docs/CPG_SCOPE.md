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
