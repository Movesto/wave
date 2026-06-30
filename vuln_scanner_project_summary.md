# Vuln-Scanner Training Data — Project Summary

## The project
Fine-tuning Qwen3-8B as a chain-of-thought (CoT) source-code vulnerability scanner.
Training on CoT traces: code + reasoning -> verdict + CWE + fix.
Hardware: RTX 5070 Ti (16GB). Currently stuck at ~70% balanced accuracy.

## The data (from DATA_INVENTORY.md)
- **8,132 converted CoT traces** — what the model trains on now. Already multi-pass
  improved; this is your *best* data, NOT representative of the rest.
- **172,733 SFT pairs** — but weak raw material (72K Bandit analyzer-noise,
  35K synthetic Java w/ duplication risk, mostly no CWE/oracle).
- **Raw convertible sources:** morefixes patch corpus (~30K unconverted, oracle-gated),
  R2Vul (~13K C/Java/C# untapped, ships reasoning + CWE), CVEfixes (~31K, no CWE).
- **~5% converted.** Heavily web-injection focused (XSS/SQLi/SSRF/path-traversal),
  Python/JS/TS.

## Key findings from analyzing the 8K
- Verdict accuracy is already good — the false-positive problem is largely fixed in v8.
- Coverage: 9/10 OWASP categories present, but ~78% concentrated in injection +
  access control. Thin on crypto, auth, ReDoS, DoS.
- Complexity: ~88% single-file, 1–2 hop. Only ~11% are 3+ hop. Real provenance
  (R2Vul/morefixes/CVEfixes = real CVEs, not toy code).
- Concentration: 20 CWEs cover 80% of data; 40 cover 90%.
- **Verdict:** realistic outcome is a fast *first-pass triage scanner* for common
  classes — not an autonomous auditor. Better reasoning lifts the ~78% you cover well;
  it cannot create coverage you don't have.

## The core problem
You want traces with genuinely good, CWE-faithful reasoning (no cross-CWE bleed).
Available free/local generators (gpt-oss, R1-distill, Qwen3) all cap at ~72% — the
same ceiling that produced the weak traces. **Weak models can't produce above-weak
reasoning.** Quality must be injected from above that ceiling.

## What breaks the 72% ceiling (cheapest first)
1. **Deterministic cleanup** — fix malformed fields, strip markdown/CVE noise.
   Free, no model.
2. **Static analysis (CodeQL/Semgrep)** — extract verified source->sink skeleton.
   Free, but only covers the taint-shaped ~2/3; logic/semantic bugs and subtly-safe
   cases still need real reasoning.
3. **Per-CWE reasoning contracts** (~20–40, written once) — encode each CWE's
   source/sink/control + discriminators vs. neighbor CWEs. This prevents cross-CWE
   bleed and makes a weak model usable *downstream* (it applies a fixed contract
   instead of choosing one).
4. **Verifier** — checks each generated trace: status matches label, CWE correct,
   no neighbor-CWE signatures, real arrow chain, no truncation. Lets you trust any
   model's output.
5. **Rejection sampling** — best-of-N locally, keep only verifier-passing drafts.

## Cost reality (generating reasoning at scale)
- **Free APIs can't do bulk** — rate-limited by design (Groq ~100 records/day via
  token caps; Gemini now needs a card; DeepSeek free grant burns fast).
- **GPT-5.4 (batched):** ~$400–800 for 170K.
- **DeepSeek V4 Flash (thinking):** ~$40–100 for 170K. ~10x cheaper, above the
  72% line. **Recommended paid option.**
- **Claude (this chat):** good for the *seed* (~40 contracts + ~200 gold exemplars
  + verifier), NOT the bulk — bulk would take months of turns.

## Revised scope (current focus)
NOT pursuing C / Java / C# / PHP / Go. Focus only on:
1. **React** — your genuine ceiling. No dedicated React vuln dataset exists; mine
   JS/TS for .jsx/.tsx + sink signatures (dangerouslySetInnerHTML, href/javascript:
   injection, unsanitized props to DOM, fetch SSRF, prototype pollution).
2. **Multi-hop / cross-file** — filter your existing patch corpus for multi-file
   diffs (free, oracle-gated); run CodeQL for interprocedural source->sink paths.
3. **Crypto / ReDoS / DoS** — pull by cwe_id (327/328/347/1333/400/770).

**Best source for all three:** GitHub Advisory Database (free, CWE-tagged, links to
fixing commits = oracle, npm/JS coverage = closest to React).
Caveat: none ship reasoning — you find well-labeled JS/TS data, then GENERATE the
reasoning oracle-gated.

## Plan moving forward
1. Find/assemble labeled data for React + cross-file + crypto/ReDoS/DoS
   (GitHub Advisory DB, your own patch corpus, CodeQL output).
2. Dedup first (Kaggle, react_syn — duplication has bitten this project before).
3. Write ~40 per-CWE contracts + the verifier (seed work — Claude can help).
4. Test a 50-record quality batch: GPT-5.4 vs DeepSeek V4 Flash, compare outputs.
5. Run bulk generation on the winner — oracle-gated, verifier-filtered.
6. Reformat any ready-reasoning data (R2Vul-style) into trace schema via a script
   (no model call) where it fits the React/cross-file/crypto scope.

## Key principle to carry forward
The weak model never *authors* quality — it *applies* a contract you authored, under
a verifier that enforces the CWE boundary. Above-72% capability is spent once, on
~40 contracts + a few hundred gold exemplars — not on every record.
