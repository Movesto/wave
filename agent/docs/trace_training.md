# Teaching the local model to drive the harness (trace distillation)

*A plain-language guide. You have trained models before and hit a data-quality wall every time — this doc
explains the one thing that is different now, and exactly how to use it. No prior experience with this
approach assumed.*

---

## 1. The idea in one picture

A parent (a strong model — deepseek) teaches the kid (the local 27B) to drive a car (use the harness: run
commands, write a proof-of-concept, inject a marker, stand up a 2-identity harness, conclude with evidence).

The twist that makes this work where "watch the parent and copy" failed before: **the harness is a driving
instructor with a brake and a test.** After every drive it checks — objectively — whether the car actually
reached the destination (a marker file appeared, AddressSanitizer fired, an ownership boundary was crossed).
**Only the drives that provably reached the destination become lessons.** The ones where the parent *said* it
worked but nothing was witnessed are thrown away automatically.

That objective check — the **verifier** — is what your past training data never had.

## 2. Why your previous attempts stalled (and why this is different)

Your notes are consistent about the wall (STaR result, corpus audit):

- **STaR / self-generation reinforced the model's own bias** — the kid copied the parent, bad habits included,
  because nothing told it which of its own outputs were actually right.
- **The corpus had no contrastive pairs and 21% templated reasoning** — lots of text that *looked* like
  reasoning but wasn't grounded in anything real.

The common cause: **there was no way to know which training examples were correct.** You were teaching from a
book of driving stories, some of which ended in a crash that the story called a success.

What is different now: **wave itself is the verifier.** Every proof this pipeline produces ends in a *real
observed effect*:

| Class | The witnessed effect (the "reached the destination" signal) |
|---|---|
| command injection | the injected `; touch /work/wave_HIT` created the file |
| SQLi / NoSQLi | the marker reached the query in an unsafe position |
| C/C++ memory | AddressSanitizer printed `ERROR: ... buffer-overflow` |
| IDOR / access control | user A's call returned user B's data |

A trace that ends in one of those is *provably* a correct drive. A trace that ends in "I think it's
vulnerable" (`believed`) or "couldn't run it" (`blocked`) is not — and is **never saved**. The filter is the
tool result, not another model's opinion.

## 3. What the trace-logger captures

`agent/orchestrator/traces.py` records one JSONL line per **certified drive**. It saves ONLY:

- `confirmed`  → a **positive** example ("how to drive to a real proof")
- `refuted`    → a **negative / contrastive** example ("how to correctly clear a non-vuln")
- `anomalous_state` → a **review** example (IDOR/business-logic: a witnessed state delta)

It NEVER saves `believed` or `blocked` (nothing witnessed), and never saves a deterministic canary drive (the
model wasn't involved — nothing to imitate).

Each record holds the full drive — the **messages**: the system prompt, the task/brief, every tool call the
model made (run this command, write this PoC), every tool result it saw, and the final grounded conclusion —
plus metadata (`file`, `class`, `cwe`, `verdict`, `label`, `evidence`, `model`, `proof_mode`, `ran`).

```json
{"id":"repo:orders.py:20:authz","verdict":"anomalous_state","label":"review","verified":true,
 "cwe":"CWE-639","proof_mode":"differential","model":"deepseek/deepseek-v4-flash-0731",
 "evidence":"BASELINE ... ATTACK returned userB's data","messages":[ ...the whole drive... ]}
```

## 4. How to collect data (zero extra effort)

Turn it on with an environment variable, then just use wave normally with the strong model. Every certified
drive is banked automatically.

```powershell
# use deepseek as the driver (the parent)
$env:WAVE_API_BASE="https://openrouter.ai/api/v1"
$env:WAVE_MODEL="deepseek/deepseek-v4-flash-0731"
$env:WAVE_API_KEY="<your OPENROUTER_API_KEY>"

# turn on trace capture (-> <wave repo>/traces/wave_traces.jsonl), or point it anywhere:
$env:WAVE_TRACE="1"           # or:  $env:WAVE_TRACE_DIR="D:\wave-traces"

python -m agent.orchestrator.run all C:\path\to\some\repo --online --patch
```

Run it across many repos over days/weeks. Each confirmed/refuted/anomalous finding appends one verified trace.
You are building the dataset while doing the work you would do anyway — and every row is tool-certified, so
there is no templated or hallucinated reasoning to clean out later.

**Tip:** point it at a mix — apps (routes/sinks) and a few C repos (ASan) and an IDOR case — so the kid learns
every kind of drive, not just one.

## 5. How the collected data becomes training (the distillation step)

This is standard supervised fine-tuning (SFT) of the local model on the parent's certified drives. You do NOT
need RL or anything exotic — imitation of verified good drives is the whole method.

1. **Filter (already done for you):** every row in `wave_traces.jsonl` is already verified. Optionally
   down-weight or cap the easy positives so the set is not all command-injection.
2. **Format:** convert each record's `messages` into your model's chat/tool-calling training format
   (system + user + assistant-with-tool-calls + tool + ... + final assistant). The `messages` are already in
   OpenAI-style chat shape, so this is mostly a rename.
3. **Balance:** keep the `positive` (confirmed) and `negative` (refuted) examples in a healthy ratio — the
   negatives are what teach the kid to *stop* and clear a non-vuln instead of over-flagging (your STaR runs
   over-flagged precisely because they had no verified negatives).
4. **Train:** QLoRA / LoRA fine-tune the local 27B on these transcripts (`WAVE_ADAPTER` already loads a trained
   adapter in `model.py`). Small adapter, a few epochs. You are teaching *tool-use behavior on this harness*,
   not general reasoning — a narrow, achievable target.
5. **Evaluate the honest way:** point the fine-tuned local model back at the harness and re-run a held-out set
   (e.g. the GHSA lane, or fresh repos). The metric is the same one that mattered all along — did it
   confirm a real vuln, tool-witnessed? Compare to the base 27B (0/3 on the cmd timeouts) and to deepseek
   (2/3). Closing that gap is the goal.

## 6. Why this is a smaller, more achievable target than before

You are **not** trying to make the model a better reasoner from scratch (the months-long, might-fail path that
burned you). You are teaching it to **operate a tool that already does the hard part** — the harness holds the
structure, runs the sandbox, supplies the proof recipes, and verifies the result. The kid only has to learn
which pedals to press and in what order, from examples that are *guaranteed correct because a tool checked
them*. That is a much narrower skill than "understand security," and it is exactly the skill the base 27B
lacked when it thrashed to a timeout while deepseek drove straight to a proof.

## 7. Honest limits

- **The kid can only get as good as the parent's drives you collect.** If deepseek is wrong in a way the
  harness can't catch (it confirms a *mechanism* that isn't truly exploitable), that trace is still labeled
  verified. The gates (reachability, intrinsic-sink, the evidence audit) reduce this, but distillation inherits
  the parent's blind spots.
- **Coverage follows what you run.** Classes/languages you never point wave at produce no traces. Collect
  broadly.
- **This does not fix detection.** If the pipeline never *surfaces* a candidate (the library-XSS / detection
  gap), there is no drive to record. Trace training improves the *proving/driving*, not the *finding*.
- **It is still training.** Formatting, balancing, and the fine-tune itself are real work and can still
  under-deliver — but for the first time the *input data is verified*, which was the specific thing that failed
  before.

## 8. The one-line summary

Use the strong model to get results now; let the harness quietly certify its drives; fine-tune the local model
to imitate only the certified drives. It is a parent teaching the kid to drive — but with an instructor who
only lets the successful drives count as lessons.
