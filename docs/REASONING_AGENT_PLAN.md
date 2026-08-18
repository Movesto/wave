# Wave — Reasoning-Agent Plan

*Recorded 2026-08-18. The strategy that came out of the deep design thread. This is the destination
and how a small model (Qwen3.5-9B) reaches it. Priority order at the bottom is binding.*

---

## 1. North Star (the destination — unchanged, sharpened)

A model that **detects, understands, and repairs** a security flaw it may **never have seen or been
trained on** — by *reasoning*, using tools + internet — across the **whole shipping surface**:
application code **and** infrastructure-as-code (Docker, Terraform, K8s, CI).

**The value-add is precisely the vulns tools CANNOT catch** — logic / business-logic flaws,
multi-step chains, cross-file, cross-language, novel classes. Scanners (CodeQL/semgrep/checkov)
already handle the pattern classes; training the model to re-find SQLi/XSS is near-worthless. The
frontier is the **reasoning-required, no-signature, no-oracle** vulns. CVE/CWE data (vulnrichment,
the bridge) is a **warm-up, not the destination.**

## 2. Core hypothesis (why a 9B can reach this)

The gap between the 9B and a strong reasoner is **NOT knowledge and NOT code-understanding** — it
already read OWASP/CWE/security texts and understands code at a high level. The gap is:

- **STANCE** — it reads code *charitably* (assumes it works as intended). A vuln lives exactly where
  the *charitable* and *adversarial* readings diverge. It must read *adversarially*: assume an
  attacker is trying to break it.
- **PROCEDURE** — the *assumption-violation method*, which it has the ingredients for but doesn't
  natively invoke: **untrusted source → follow flow → state the sink's safety ASSUMPTION →
  CONSTRUCT an input that violates it → test the guard for a bypass → consequence → verdict/repair.**

A 9B can't make the *gestalt leap* a large model makes, but it **can do each step** (identify
untrusted input, state an assumption, construct an input) if forced. **The procedure turns a leap it
can't make into a sequence of steps it can.** Install the procedure, don't grow the brain.

Install it via four levers (we have pieces of each):
1. **Decompose** the reasoning into a forced sequence (inference-time scaffold).
2. **Distill** the procedure from a STRONG teacher (self-gen fails — proven). Traces make the
   assumption + adversarial-construction spine explicit and varied.
3. **Stance**: never conclude *safe* from reading — only from a *failed attack*; prove *vuln* by
   construction. ("safe = positive finding" was the first piece of this.)
4. **Verifier-reward (RLVR)** where an oracle exists: reward when the constructed exploit is verified
   (DAGVUL recipe — 8B + verifiable reward beats 30B).

## 3. The loop is the reasoning SUBSTRATE, not a detector (capacity offload)

Chain-depth and cross-file are real 9B limits. The strategy does **not** require the 9B to hold them
— it **offloads capacity to external structure**; the 9B only ever does **one short reliable step at
a time**:
- **Chain depth → externalized into loop TURNS.** Each turn does one step and writes it down; the
  transcript is the working memory. A 10-hop chain = 10 short steps. The chain lives in the text.
- **Cross-file → externalized via `retrieve`.** It holds one file, fetches the next into context,
  reasons one hop at a time. Cross-file memory = the retrieved snippets in the transcript.
- **Correctness → externalized via the verifier / experiment.**

**Discernment on an UNTRAINED class works because the class label is DOWNSTREAM of the reasoning.**
If it reasons "this input escapes the base dir," it has *found* a path traversal without knowing
"CWE-22". Verdict = the procedure's OUTPUT (did the exploit work?), which is class-independent.

## 4. The three legs + the ceiling-breaker

`REASON (deduction) → RETRIEVE (context) → EXPERIMENT (empirical) → VERIFY (oracle) → conclude / defer`

- **REASON + RETRIEVE** — built (agent_loop.py, local_retrieve.py). Validated on real repos.
- **VERIFY** — witness/prove_safe (6 classes) + CodeQL + (later) checkov. NARROW — this was the wall.
- **EXPERIMENT — the ceiling-breaker (NEW).** When deduction hits an insight it can't make, don't
  guess: **build a PoC, run it in a sandbox, observe the outcome, conclude from what actually
  happened.** This is empirical reasoning (the scientific method) — and it does two things at once:
  1. **Breaks the reasoning ceiling** — *observing* is far easier than *deducing*; a 9B can run a
     harness and read "returned /etc/passwd" it could never reason its way to.
  2. **Universal verifier** — *running the actual code* is an oracle for ANY testable class, fixing
     the narrow-oracle problem without hand-building a checker per CWE.
- **DEFER** — where even an experiment can't be run (needs a full live system) or the insight is out
  of reach: say **"unsure — I'd need X"**. Honest, still useful (flags for a human).

Experiment reach = **function-level PoCs** (extract the suspicious function, harness it, run with a
crafted input). Full live-app exploitation is out of scope for v1.

## 5. Infrastructure — the sandbox ($0, on-prem, off the Windows side)

No cloud (budget). Run untrusted PoCs isolated from the main machine:
- **Persistent Hyper-V Linux VM** (Win 11 Pro has Hyper-V free), **network-isolated** (no NIC /
  internal-only switch), auto-start, ~4GB RAM. It is a **running service**, NOT booted per test.
- Inside it, an **executor service** the experiment tool calls over a local-only channel.
- **Per-test ephemeral inner sandbox:** **Firecracker microVM** (enable nested virt on the guest;
  ~125ms boot, throwaway) for max isolation — OR Docker/gVisor for a simpler v1. Swappable behind
  the executor interface.
- **Hygiene (non-negotiable):** no network egress, ephemeral/destroy-per-test, hard CPU/mem/time
  limits, throwaway FS.
- **RAM:** the model is on the **GPU VRAM (16GB)** — the constraint, unchanged. The sandbox VM lives
  in **system RAM (31GB)** at ~2-4GB; Firecracker microVMs are 128-512MB. Plenty of headroom; both
  run at once. Storage is a non-issue.

## 6. The specialist bet (why the 9B can win)

A deep specialist beats a generalist **in its area** (DAGVUL: 8B+RLVR > 30B). The 9B's fine-tuning
capacity all pours into vuln-reasoning → richer local representation + automatic procedure + verified
correctness in-domain. It **loses** out-of-domain / at extreme complexity → covered by **tools**
(retrieve/experiment) and **honest "unsure"**. Bet: *don't build a bigger brain — build a driver who
owns one neighborhood so completely he beats the generalist there, and knows to ask directions and
run a test-drive when the fare leaves it.*

## 7. Data strategy

- **Warm-up = CVE/bridge, FILTERED for reasoning value.** Over-index on the reasoning-required subset
  (authz, logic, multi-step, cross-file); DOWN-WEIGHT the tool-catchable pattern vulns (SQLi/XSS a
  scanner already gets). Source: vulnrichment (167K CVEs) — mine the ~5-8K with a GitHub fix-commit
  directly (web-heavy), not just the C/PHP-heavy morefixes leftover. Fetch `commit/<sha>.patch`.
- **Destination = logic / un-toolable flaws, authored by a STRONG teacher** (the bet is distilling
  the *procedure* correctly; a weak model can't). User seeds the targets/classes he cares about.
- **Self-improving:** each EXPERIMENT trace (`input → observed outcome → conclusion`) is gold training
  data — teaches the empirical method + concrete input→behavior facts. The specialist gets deep by
  *running experiments and remembering*, not reading a map.
- **Hand-author safe sides** (user + me + teacher) for thin classes — the safe side is the scarce part.
- **NEVER train on raw v14 "trash reasoning."** Regenerate v14's reasoning LATER (good labels,
  rewrite reasoning); its current train_qwen_cot.py DOWN-WEIGHT wiring is rejected — DROP it before
  any train.

## 8. Training (OPTIMIZATION, not a requirement — the loop already works untrained)

Only when there's enough ALL-GOOD data to justify GPU days. Distill the procedure (SFT on strong-
teacher traces) + RLVR from the verifier/experiment. On the GOOD corpus only. Fine-tune Qwen3.5-9B
(multimodal loader already wired). Its job = make the model drive the loop NATIVELY (fewer
auto-retrieve/sink-window fallbacks) + sharpen per-step reliability. It is NOT the source of
generalization — the loop + procedure + experiment are.

## 9. Evaluation — the honest yardstick

A held-out set of vulns the model has NEVER seen, INCLUDING logic / no-oracle classes. Measure
whether it **CONSTRUCTS the assumption-violation (a concrete exploit)** — not whether it labels.
Validates reasoner vs recognizer. If it only produces the exploit on training-like classes, we built
a recognizer.

## 10. Priority order (BINDING)

1. **LOOP FIRST — as the reasoning substrate.** Harden reason/retrieve; add the ceiling-breaker.
   1a. Sharpen the loop prompt to force the **assumption → adversarial-construction** spine.
   1b. **Build the EXPERIMENT tool** + the Hyper-V/Firecracker executor sandbox.
   1c. Recall on hard multi-step chains (the DVNA deser type).
2. **DATA (bridge) — optimization.** Mine vulnrichment for reasoning-required web CVEs; hand-author
   safe sides for thin classes; keep experiment traces as training data.
3. **REGENERATE v14 reasoning — later.**
4. **TRAIN — only on all-good data;** distill procedure + RLVR.
5. **IaC (Docker/Terraform) — same architecture, swap the oracle to checkov.** Then host/network/AD.

## Open decisions (before data generation)
- **(a) Teacher:** strong reasoner (Claude/top model) as primary teacher for the hard/logic traces,
  with user seeding targets — vs DeepSeek for bulk + strong teacher only for the hardest.
- **(b) No-oracle trust gate:** how to trust a logic-flaw trace with no verifier — hand-review
  (user + me), a second strong model as checker, or both. The experiment tool partly solves this
  (a PoC that runs is self-verifying); for the un-runnable, review is the gate.

See memory: [[project_north_star]], [[project_roadmap]], [[project_reasoning_regen]],
[[reference_reasoning_papers]] (AEGIS = the loop, DAGVUL = distill + RLVR).
