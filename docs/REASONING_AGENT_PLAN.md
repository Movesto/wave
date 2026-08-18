# Wave — Reasoning-Agent Plan (detailed, for external review)

*Recorded 2026-08-18. This is a design document meant to be handed to an outside reviewer to judge
soundness and find gaps. It states the thesis, the concrete methodology (traces, generation, gates,
sandbox, training, evaluation), and the WHY behind each choice — and is explicit about what is
already validated vs. hypothesized, and where we want critique. Nothing here has been run yet.*

Reviewer TL;DR: we are building a small (9B) model + tool loop that finds and repairs software
vulnerabilities — with the explicit aim of the classes that **static scanners cannot** catch (logic,
novel, cross-file). The bet is that generalization comes from an *inference-time reasoning procedure
+ tools*, not from training coverage; training is optimization on top. **Please pressure-test that
bet and tell us what we're missing.**

---

## 0. Glossary (so the doc is self-contained)
- **SAST / DAST** — static (read the code) vs dynamic (run the code) analysis.
- **CWE / CVE** — weakness *type* (e.g. CWE-89 SQLi) / a specific disclosed vulnerability.
- **vulnrichment** — a public dataset (167,465 CVEs, 1990–present) mapping CVE → CWE + references,
  often including a GitHub **fix-commit**. On disk.
- **morefixes** — 32,008 real CVE fix patches on disk; our current "bridge" is the sha-overlap of
  vulnrichment × morefixes (3,159 CWE-labelled patches).
- **The loop / agent** — the model driving tools turn-by-turn (reason → tool → re-reason).
- **The witness / prove_safe** — our deterministic verifiers that PROVE a guard bypassable/sufficient
  for 6 classes (path, command, ssrf, redirect, proto, xss-subset).
- **Oracle** — anything giving ground truth (witness, CodeQL, checkov, or *running the code*).
- **Teacher / student** — the model that authors training traces (DeepSeek-V4-Flash, + Claude & the
  human for hard cases) vs the model we fine-tune (Qwen3.5-9B).

---

## 1. Goal (destination) and the value thesis

**Goal.** A model that **detects, understands, and repairs** a security flaw it may never have seen
or been trained on — by *reasoning*, using tools + internet — across the whole **shipping surface**:
application code AND infrastructure-as-code (Docker, Terraform, K8s, CI).

**Value thesis (and the sharpest claim to critique).** Existing tools (CodeQL, semgrep, checkov)
already catch the *pattern* classes cheaply. The model's value is precisely the vulns **no signature
and no oracle** can catch: **logic / business-logic flaws, multi-step chains, cross-file,
cross-language, novel classes.** Therefore CVE/CWE data is a **warm-up, not the destination** — it
teaches method on solved cases; the destination is reasoning on the un-toolable ones.

*Why this framing:* a prior 8B fine-tune ("v14") trained on ~30k known-vuln records learned "a form,
not reasoning" (measured: 508 of 662 traces shared one skeleton; it flagged anything that *looked*
dangerous and could not tell safe-but-similar code apart). More known-vuln data made a better
*recognizer*, not a *reasoner*. That failure is the reason for everything below.

---

## 2. Core hypothesis (why a 9B can reach this)

**Claim: the gap between the 9B and a strong reasoner is not knowledge and not code-understanding —
it is STANCE and PROCEDURE.** Qwen3.5-9B has already read OWASP/CWE/security texts (it knows what
SQLi/auth/deserialization *are*) and understands code at a high level. What it lacks:

- **Stance.** It reads code *charitably* (assumes the code does what the author intended — which is
  how you understand *what code does*). A vulnerability lives exactly where the **charitable and
  adversarial readings diverge**: the code works for normal input and breaks for a malicious one. To
  *find* it, the model must read **adversarially** — assume an attacker is actively trying to break
  it, and try to break it.
- **Procedure.** The **assumption-violation method**, which it has the ingredients for but doesn't
  natively invoke:
  1. identify the **untrusted source** (trust boundary),
  2. **follow the flow** to the operation it reaches (the sink),
  3. **state the sink's safety ASSUMPTION** (its implicit contract: "input is an int" / "path stays
     under base" / "caller owns this row"),
  4. **construct a concrete input that VIOLATES** that assumption (the exploit),
  5. **test any guard** — does it block *every* violating input, or is there a bypass?
  6. **reachability + consequence** — is it reachable, and what does the attacker gain?
  7. **verdict + repair** (repair = restore the violated assumption), or **defer** ("unsure — I need
     X").

**Why a small model can do this.** It cannot make the *gestalt leap* a large model makes (see the
whole exploit at once), but it **can do each step** (identify untrusted input; state an assumption;
write an input) — each is within a 9B's ability. **The procedure turns a leap it can't make into a
sequence of steps it can.** We install the procedure; we do not grow the brain.

**Four levers to install it** (we already have partial pieces of each):
1. **Decompose** — force the procedure as an explicit turn-by-turn sequence at inference.
2. **Distill** — fine-tune on traces from a *strong* teacher that make the assumption +
   adversarial-construction spine explicit and varied. (Self-generation was measured to fail — the
   9B can't teach itself the step it can't reliably do.)
3. **Stance** — train/prompt the hard rule: *never conclude "safe" from reading; only from a failed
   attack.* Prove **vuln** by construction; prove **safe** by showing the exploit is blocked.
4. **Verifier-reward (RLVR)** — where an oracle exists, reward a *verified* exploit, penalize a
   plausible-but-wrong one. (Prior art, DAGVUL: an 8B + verifiable reward beats a 30B on this task.)

**Honest status: this is a HYPOTHESIS.** Section 9 says how we'd validate/falsify it.

---

## 3. The loop is the reasoning SUBSTRATE, not a detector (capacity offload)

Chain-depth and cross-file are real 9B limits (a 9B cannot hold a 10-step chain or 4 files at once).
The design does **not** require it to — it **offloads capacity to external structure**; the 9B only
ever does **one short reliable step at a time**:

- **Chain depth → externalized into loop TURNS.** Each turn does one step and writes it down; the
  transcript is the working memory. A 10-hop chain = 10 short steps. *The chain lives in the text,
  not the model's activations.*
- **Cross-file → externalized via a `retrieve` tool.** The model holds one file, fetches the next
  function into context when it needs it, and reasons one hop at a time. Cross-file "memory" = the
  retrieved snippets accumulated in the transcript.
- **Correctness → externalized via the verifier / the experiment (below).**

**Why this generalizes to an UNTRAINED class.** The class label is *downstream* of the reasoning. If
the model reasons "this input makes the path escape the base directory," it has *found* a path
traversal without knowing the name "CWE-22." The verdict is the procedure's **output** (did the
constructed exploit work?), which is class-independent. So per-class training coverage is not what
buys generalization; reliable execution of a class-independent procedure is.

---

## 4. The three legs + the ceiling-breaker (loop architecture)

```
REASON (deduction) → RETRIEVE (context) → EXPERIMENT (empirical) → VERIFY (oracle) → CONCLUDE / DEFER
```

- **REASON + RETRIEVE** — *already built and validated* (see §10). The model reasons the procedure
  and calls `retrieve(symbol)` to pull unseen cross-file definitions from the project on disk.
- **VERIFY** — `witness`/`prove_safe` (6 classes) + CodeQL (interprocedural) + (later) checkov (IaC).
  This is **narrow** — it was the wall (most classes have no verifier).
- **EXPERIMENT — the ceiling-breaker (NEW, not yet built).** When deduction hits an insight the 9B
  can't make, do not guess: **build a proof-of-concept, run it in a sandbox, observe the outcome,
  and conclude from what actually happened.** This is empirical reasoning (the scientific method),
  and it does two things at once:
  1. **Breaks the reasoning ceiling** — *observing* is far easier than *deducing*. A 9B can write a
     harness and read "the function returned the contents of /etc/passwd" that it could never reason
     its way to.
  2. **Is a universal verifier** — *running the actual code* is an oracle for **any testable class**,
     fixing the narrow-oracle problem without hand-building a checker per CWE.
- **DEFER** — where an experiment can't be run (needs a full live system) or the insight is out of
  reach: **"unsure — I'd need X."** Honest, still useful (flags for a human). This is a *first-class*
  output, not a failure.

**Experiment reach (scoped honestly):** *function-level* PoCs — extract the suspect function, wrap it
in a minimal harness, run with a crafted input. Full live-app exploitation (a running server + DB) is
**out of scope for v1** and falls to DEFER.

---

## 5. Data — the traces we generate, how, and why

The training signal is **not "which code is vulnerable."** It is the **procedure** (§2) made explicit
on varied cases. Five trace types, each with a purpose, a format, a generation method, and a gate.

### 5.1 The trace format spec (every trace obeys this)
Continuous prose, no templated headers (v14 failed by templating), following the §2 spine and ending
in exactly one status line. Concretely, a **vuln** trace must: name the real untrusted source and the
real sink (grounded in *this* code), **state the sink's assumption**, give a **concrete attacker
payload** that violates it, and (if a guard exists) show the **bypass**. A **safe** trace must
**point to the specific control** and show *which* violating input it blocks and why nothing slips
past (safe = a positive finding, never "found nothing"). An **unsure** trace must name the exact code
it would need to decide. *Why:* forcing the assumption + adversarial-construction spine is what makes
the model learn *method* (transfers) instead of *pattern* (doesn't).

### 5.2 The five trace types
1. **Contrastive discrimination pairs** — the same code vulnerable (pre-fix) vs fixed (post-fix).
   *Purpose:* teach the vuln-vs-safe *boundary* (mechanism, not topic) — the exact thing v14 lacked.
   *Format:* two records sharing a `pair_id`, one `status: vuln` one `status: safe`, on aligned code.
   *Why paired:* the two sides differ only by the real flaw, so the model cannot pass by surface
   memorization — it must learn the mechanism.
2. **Agentic tool-use traces** — reason → `retrieve`/`experiment`/`witness` → re-reason → conclude,
   across turns. *Purpose:* teach the model to *drive the loop* — to ask for missing code and to run
   experiments instead of guessing. *Format:* multi-turn transcript preserving the request→result→
   continue shape. *Why:* this is what carries it on multi-file / hard cases (§3).
3. **Experiment traces** — `hypothesis → crafted input → observed sandbox outcome → conclusion`.
   *Purpose:* teach the empirical method AND concrete input→behavior facts; **self-improving** (each
   real experiment becomes new training data). *Why:* the specialist gets deep by *running
   experiments and remembering*, not by reading a map.
4. **Defer / "ask-for-X" traces** — reason to the boundary, name the missing code, `status: unsure`.
   *Purpose:* teach epistemic humility + what to fetch; these are the *agentic* signal for cross-file.
   *Why:* a model that knows what it can't see and asks is safer and more useful than one that guesses.
5. **Logic / no-oracle traces (the destination)** — business-logic, authz-logic, multi-step chains
   with no signature and no deterministic verifier. *Purpose:* the actual goal — reasoning where
   tools can't. *Why:* these are scarce, don't map to a clean CWE, and can't be auto-verified, so
   they need the strong teacher + human review (below).

### 5.3 Where the data comes from (source) and why
- **Warm-up (bulk): mine `vulnrichment` directly**, not just the morefixes overlap. Method:
  scan the 167k CVE JSONs for records that (a) carry a **CWE we want** and (b) reference a **GitHub
  fix-commit**; fetch that commit's `.patch` from GitHub (`github.com/o/r/commit/<sha>.patch` serves
  the full pre/post diff — verified); extract the vulnerable pre-image and fixed post-image
  (`patch_extract`). *Measured headroom:* ~7% of CVEs have a fix-commit → **~5,000–8,000 commit-backed
  CVEs**, and the commit-backed set is **web-dominated** (XSS/SQLi/auth/CSRF/authz/command/path) —
  exactly the discrimination-rich data we want, and better than the morefixes leftover (which is
  ~50% C memory-safety the scanner can't use). *Filter to* web languages (PHP/JS/TS/Python/Ruby) +
  the classes we're thin on; *down-weight* the tool-catchable pattern classes. *Caveat:* raw commit
  fetches are noisier than curated patches (a fix may bundle 42 unrelated files) → filter to commits
  touching ≤ N files; the hunk-ranker + gates handle the rest.
- **Destination (hard): authored logic-flaw traces.** No CVE source suffices for logic flaws; here the
  *teacher* matters more than the source (see §5.4).

### 5.4 Who authors, and the review gate (settled 2026-08-18)
- **DeepSeek-V4-Flash is the primary teacher for the bulk** (cheap, ~$0.075/1M tokens; strong enough
  to produce the §5.1 spine on standard cases). *Why not the 9B itself:* self-generation was measured
  to fail on the safe side (it over-flags) — a strong teacher is required.
- **Claude + the human author/handle the HARD tasks** (logic/no-oracle traces, the seed exemplars
  that set the bar) **and REVIEW DeepSeek's output** (hand-read every batch — gate-pass ≠ correct is
  a repeatedly-observed trap here).
- **No-oracle trust gate = hand review.** Logic-flaw traces have no automatic verifier, so a human
  (+ Claude) reviews each for a *correct, concrete* exploit-or-defense before it enters training.
  *Why:* for these classes the model's judgment is the only signal — a wrong trace poisons directly.
  (Where the trace is *runnable*, the experiment tool self-verifies it — a PoC that runs is its own
  gate; review covers the un-runnable.)

### 5.5 Automatic gates (before human review, to cut the volume)
Reuse the existing stack, all measured: **grounding** (cited identifiers appear in the code),
**diff-aware grounding** (cites a token the fix touched), **verdict-agreement** (model verdict ==
patch-derived label; *disagreement is a label-audit signal, not a discard*), **grounding-leak**
(reject traces that reason from the CVE/advisory instead of the code), **sink-plausibility** (a
modelled CWE with no matching construct = mis-extraction → drop), **pair-alignment** (both sides
describe the same region). *Why a stack:* each gate catches a different failure mode we actually hit;
none alone is sufficient, and none replaces the hand-read.

### 5.6 What we do NOT do
- We do **not** train on the raw v14 "trash reasoning." Its labels are good; its reasoning is
  templated. **Regenerate its reasoning later** (rewrite to the §5.1 bar, keep the labels), then use
  it — never before. (The current `train_qwen_cot.py` still *down-weights* v14 rather than dropping
  it; that wiring is rejected and must be fixed before any training.)
- We do **not** center the corpus on the tool-catchable pattern classes — those are down-weighted.

---

## 6. Infrastructure — the experiment sandbox ($0, on-prem)

*Why on-prem:* no cloud budget (free AWS/Oracle exhausted); also keeps code under our control.

- **Persistent, network-isolated Hyper-V Linux VM** (Windows 11 Pro ships Hyper-V free). It is a
  **long-running service**, *not* booted per test — start once/auto-start; the experiment tool sends
  requests to an **executor service** already running inside it over a local-only channel.
- **Per-test ephemeral inner sandbox:** a **Firecracker microVM** (enable nested virtualization on
  the guest; ~125 ms boot, throwaway) for strong isolation — OR Docker/gVisor for a simpler v1.
  Swappable behind the executor interface. *Defense in depth:* Windows → Hyper-V boundary →
  Firecracker/container boundary → the PoC.
- **Hygiene (non-negotiable):** no network egress; ephemeral / destroyed per test; hard CPU/mem/wall-
  time limits (the DoS PoCs *will* try to hang or fork-bomb it); throwaway filesystem.
- **Resource budget:** the model runs on the **GPU VRAM (16 GB)** — the real constraint, untouched by
  this. The sandbox VM lives in **system RAM (31 GB)** at ~2–4 GB; Firecracker microVMs are
  128–512 MB. Both run at once with headroom; storage is a non-issue.
- **What "experiment" means concretely:** the executor receives `(harness, input, runtime)`, runs it
  in a fresh inner sandbox with the language runtime, and returns `stdout / stderr / exit code /
  observable side-effects` (files touched, exceptions). The model interprets that as ground truth.

---

## 7. The specialist bet (why the small model can win)

A **deep specialist beats a generalist in its area** — measured (DAGVUL: 8B + RLVR > 30B). The 9B's
fine-tuning capacity all pours into one slice (vuln-reasoning) → richer local representation +
*automatic* procedure invocation + verified in-domain correctness. It **loses** out-of-domain (a
framework/context it never trained on) and at extreme complexity → those are covered by **tools**
(retrieve/experiment) and **honest "unsure."** The bet in one line: *don't build a bigger brain —
build a driver who owns one neighborhood so completely he beats the generalist there, and knows to
ask directions and run a test-drive when the fare leaves it.*

---

## 8. Training (OPTIMIZATION, not a requirement)

*Key claim for the reviewer:* **the loop already works with the 9B untrained** (§10). Training does
not create the capability; it makes the model *drive the loop natively* (fewer prompt-scaffolds and
fallbacks) and sharpens per-step reliability.

- **Stage 1 — SFT / distillation.** Fine-tune Qwen3.5-9B (QLoRA; multimodal loader already wired) on
  the good traces (§5), high-weight, on the ALL-GOOD corpus only. *Why:* installs the procedure +
  stance as defaults.
- **Stage 2 — RLVR (reinforcement from verifiable reward).** Where an oracle exists (witness / the
  experiment sandbox), reward the model when its constructed exploit is *verified*; penalize
  plausible-but-wrong. *Why:* this is what makes the adversarial constructions *correct*, not just
  fluent — and it uses the experiment sandbox as the reward signal (the same infra as §6).
- **Only when there's enough all-good data to justify GPU days** (prior runs are multi-day on the
  16 GB card). Data volume is the historical blocker, not the training method.

---

## 9. Evaluation — the honest yardstick

*The central risk is building a recognizer that looks like a reasoner.* So the eval must test
**reasoning, not recall:**
- A **held-out set of vulns the model has never seen**, repo-disjoint from training, **including
  logic / no-oracle classes** and at least some classes *absent from training entirely*.
- **Metric:** does the model **CONSTRUCT the assumption-violation** (a concrete, correct exploit — or
  a concrete defense for safe) — not merely emit the right label? For runnable cases, the experiment
  sandbox scores the exploit objectively; for un-runnable, human review scores it.
- **Falsification:** if the model only produces correct exploits on *training-like* classes and
  collapses (or guesses) on the genuinely novel/no-oracle ones, we have built a recognizer and the
  §2 hypothesis is wrong. We want to know that.
- Secondary: **patched-FPR** (does it flag the *fix* as vulnerable — the pattern-matching tell) and
  **pair-accuracy** on a repo-disjoint holdout, both already wired.

---

## 10. What is already built and validated (grounding for the reviewer)

- **The loop, untrained**, on real repos: on a labelled cross-file benchmark it scored **4/4 recall,
  0 false positives** and *discriminated* a vulnerable `searchUser` (concat SQL) from its safe twin
  `getUser` (parameterised) by retrieving the service across files. On the real OWASP app **DVNA** it
  confirmed 3 genuine vulns (command-injection, eval RCE, open-redirect), cleared the false
  positives, and went *honest-unsure* on the hardest (a multi-step deserialization). On **brokencrystals**
  (NestJS) it found path-traversal and SSRF across files. **All untrained** — evidence that the loop,
  not the training data, carries the generalization on the toolable/near classes.
- **The data pipeline** (honest-verdict generation, contrastive pairs, two-pass cross-file retrieval,
  the gate stack, the corpus auditor) is built; a ~1,200-CVE corpus exists (small, warm-up quality).
- **NOT built:** the experiment tool + sandbox (§4/§6); the vulnrichment miner (§5.3); RLVR (§8);
  the reasoning-focused eval (§9); the logic/no-oracle authored set (§5.2).

---

## 11. Priority order (BINDING)

1. **LOOP FIRST (the reasoning substrate).**
   1a. Sharpen the loop prompt to force the **assumption → adversarial-construction** spine (§2).
   1b. **Build the EXPERIMENT tool + the Hyper-V/Firecracker executor sandbox** (§4/§6) — the
       ceiling-breaker.
   1c. Recall on hard multi-step chains (the DVNA deser type).
2. **DATA (optimization).** Build the vulnrichment miner (§5.3); generate with DeepSeek + gates +
   human review; hand-author the logic/no-oracle set; keep experiment traces as training data.
3. **REGENERATE v14 reasoning** — later.
4. **TRAIN** — SFT then RLVR, all-good corpus only, when volume justifies it.
5. **IaC (Docker/Terraform)** — same loop, swap the oracle to **checkov** (its rules ARE the labels,
   sidestepping the CVE-label problem). Then host/network/AD posture (same pattern, new oracle).

---

## 12. Risks, assumptions, and where we want the reviewer's input

**Assumptions we are betting on (please challenge):**
- A1. A 9B, given the decomposed procedure + externalized memory (turns/retrieve) + experiment, can
  reason to a *correct* verdict on *unseen* vulns — up to an "insight ceiling," beyond which it
  should defer. *(Is the insight ceiling low enough to make this useful, or does it swallow most
  logic flaws?)*
- A2. Distilling the *procedure* from DeepSeek (with human review of the hard cases) installs
  transferable method, not just better pattern recall. *(v14 shows the failure mode is real; is our
  data bar — contrastive + adversarial spine + varied — actually sufficient to avoid it?)*
- A3. The experiment (function-level PoC in a sandbox) covers enough vulns to matter, i.e. enough
  suspect functions are *runnable in isolation*. *(What fraction of real vulns need a full live
  system and thus fall to DEFER?)*
- A4. RLVR with the experiment/witness as reward improves correctness without reward-hacking the
  checkers (we have been fooled by our own checkers before).

**Known risks / open questions we'd like judged:**
- The destination data (logic/no-oracle) is scarce, unlabelled, and hand-review-gated → **throughput
  and reviewer bias** are real limits. Is hand-review a sound gate at the volume we'd need, or does
  it cap us too low?
- **Evaluation of no-oracle reasoning** is itself hard (no ground truth) — is the "construct the
  exploit, human-scored" yardstick (§9) rigorous enough to trust?
- Is prioritizing the **loop + experiment** over more training data the right call, or are we
  under-investing in the model's raw ability?
- Anything structurally missing — a class of vuln, a failure mode, a better source of logic-flaw
  data, a better verifier — that we haven't considered?

---

*Cross-references (internal): the loop and its validation, the generation pipeline and its measured
gate-traps, and the prior-art papers (AEGIS ≈ the loop; DAGVUL ≈ distill + RLVR) are in the project
memory. This document is the master plan; it supersedes the earlier short roadmap note.*
