# Evidence-Grounded Investigation — the model reasons and decides; tools supply facts it can't fake

## The shift

Today wave is **tool-decides**: a deterministic oracle renders the verdict and the model is
forbidden from overriding it (sound-by-construction). That bought reliability but cost us two things
we can't live without:

1. **Generality.** The oracle proves by patching sinks in **Python**, so any non-Python project
   (ego-lite = JS/TS) gets **zero proven** — every hypothesis stays an unprovable opinion.
2. **Coverage.** The oracle only knows a fixed **~9 injection classes** (SQL/shell/path/HTTP/…). It is
   blind to business logic, IDOR, workflow bypass, and any class nobody enumerated — because those are
   not "a marker reached a sink," they're "the system reached a bad **state**."

This plan flips the roles:

> **The model reasons and has the final say. The tools' job is not to render the verdict — it is to
> manufacture ground-truth evidence the model reasons over. A verdict is the model's conclusion about
> *why* something happened, anchored to *what actually happened* on a real run.**

The tool is not smarter than the model and does not "know" vulnerabilities. It knows one narrow thing
with certainty — *what the system actually did when the model poked it* — and it cannot hallucinate
that, because it observed a real execution. The model supplies all the intelligence, including the
final call; the tool supplies reality so the model isn't reasoning in a vacuum (reasoning in a vacuum
is exactly what produced the fabricated CVE and the CWE-89-on-a-browser-call on ego-lite).

## The one rule that keeps the model honest

There is a single constraint, and it is the whole safety story:

> **A verdict of `confirmed` must cite an effect the model actually caused and a tool actually
> observed. Reasoning alone can PROPOSE (`believed`); only an observed effect can CONFIRM.**

- The model may reason however it likes and reach any conclusion it wants.
- But to *promote* a conclusion from "believed" to "confirmed," it must point at a concrete
  observation: "I sent `qty=-5`; the tool recorded the response balance going 100 → 105." No observed
  effect → it stays a reasoned lead, clearly labelled, never a confirmed finding.

Every hallucination we saw came from concluding **without acting**. This rule makes acting mandatory
for confirmation while leaving the model free to think, decide, and explain. It is not "the tool
overrules the model" — it is "the model may not declare victory on something that never happened."

## The core loop (language-agnostic, class-agnostic)

    hypothesize → act → observe → reason → conclude
        (model)   (model)  (tool)   (model)  (model)

1. **Hypothesize** — the model reads code and forms a theory: which file, which flow, what could go
   wrong, and *how it would test it*.
2. **Act** — the model writes and runs whatever it needs, **in the target's own language**, via a
   general executor: a script, an HTTP request, a replayed transaction, a crafted payload.
3. **Observe** — the tool runs it for real and returns **facts**: the response, the state change, a
   canary's location, a crash, a logged query. Facts, never verdicts.
4. **Reason** — the model interprets the observation: is this the bad thing? *why* did it happen? what
   is the mechanism and the impact?
5. **Conclude** — the model decides: confirmed (with the cited observation), believed (reasoned lead),
   refuted (observed the safe behaviour), or blocked (couldn't act). The model owns this step.

The tool never needs to understand the vuln class. It only faithfully reports what the system did.
That is why this loop covers the 9 injection classes, business logic, and classes we've never named —
the intelligence is entirely in the model, the reality entirely in the tool.

## Components to build

### 1. The general Executor — "run whatever the model asks"
A uniform interface, `run(code_or_request, runtime) -> Observation`, backed by per-language runners
dispatched by the target's language. This part is **general by nature** — running code is not
language-specific, only the interpreter is:

- `python` / `node` / `php` / `ruby` / `go run` / a shell — pick by the candidate's language.
- Runs inside the **target's own environment** (its container, or its dir with deps installed) so the
  code's real imports/deps resolve and the real sinks are present.
- TypeScript transpiles first (`tsx`/`esbuild`); handler shapes (Express/Nest `(req,res)`, Flask
  params) get a synthesized request carrying the marker — the same problem the Python side solved,
  redone per runtime.
- Isolation: the target's container / WSL2 sandbox, never the host (unchanged principle).

The model calls this like an LLM agent calls a code-interpreter helper: it asks, the tool runs, the
tool returns what happened.

### 2. The Observation layer — facts, not verdicts
A menu of **observers** the model can attach to a run. Each answers "what happened," none say
"vulnerable." This is the general replacement for the 9-class oracle — it's a spectrum of observable
effects, not a closed taxonomy:

| Observer | Reports (a fact) | Grounds which reasoning |
|---|---|---|
| **Canary-in-sink** | the marker landed inside the SQL/shell/path/URL unsafely | injection classes |
| **Reflection** | the marker came back in the HTTP response / DOM | XSS, disclosure |
| **Differential / state** | before→after state changed (balance, role, order status, another user's record) | business logic, IDOR, workflow, replay |
| **Crash / sanitizer** | the process crashed / ASan fired | memory safety |
| **Response / behaviour** | status, timing, body, side effects (file written, request egressed) | anything |

The canary and differential observers are **language-agnostic** — they're string/behaviour/state
comparisons, not runtime-patching. The sink-tripwire observer (strongest, near-zero-FP) is
per-language and optional: a bonus automatic witness where we've built it, not a requirement.

### 3. The Verdict + Evidence ledger
The model writes the verdict; the **Case File** (already exists — `recorder.py`) stores it *with its
cited observation*. Statuses:

- `believed` — reasoned; no confirming effect observed yet.
- `confirmed` — reasoned **and** cites an observed effect the model caused. (Enforced by the one rule.)
- `refuted` — the model acted and observed the safe behaviour.
- `blocked` — couldn't act (no runtime, missing deps) — honest, not a fake answer.

Every `confirmed` entry carries: the action taken, the observation returned, and the model's
reasoning for *why* it's a vuln. That triple is the deliverable — a human (or a second pass) can
re-run the action and see the same fact.

## How soundness degrades gracefully (the honest part)

Not all evidence is equally strong, and the plan does **not** pretend otherwise:

- **Injection / memory / reflection** — the observed effect (marker in the sink, ASan crash, canary
  reflected) is essentially self-proving. These stay near-zero-false-positive, model-narrated,
  automatically strong.
- **Business logic / IDOR / workflow** — the observation (state changed) is a fact, but "is this state
  *bad* or intended?" is a **judgment**. No tool can make that call — a senior human pentester can't
  either without judgment. So these are `confirmed`-by-the-model, **evidence-backed**, and flagged
  **human-reviewable**. The value is the concrete observed effect + the model's mechanism explanation,
  not a green light from an oracle.

This is the correct honesty: the strong classes get a strong witness; the open-ended classes get a
reasoned argument attached to a real observed effect — which is exactly how expert humans deliver
them.

## Migration (from the current system, without losing what works)

The current pieces map cleanly — this is a refactor + extension, not a rewrite:

1. **Refactor** `rung1.micro_exec` into `Executor` (run) + `Observer` (canary-in-sink). The existing
   Python path becomes `PythonExecutor` + the sink-tripwire observer — behaviour unchanged.
2. **Add `NodeExecutor`** (require/import + JS sink monkeypatch + call; `tsx` for TS) — unblocks JS/TS,
   the biggest gap; test on ego-lite so it finally gets a real oracle.
3. **Generalize the observers** — promote the differential/behavioural observer (already stubbed for
   business logic) to a first-class, language-agnostic evidence source, plus the reflection observer.
4. **Move the verdict to the model** under the one rule: the loop stops auto-labelling from the oracle
   and instead hands the model the observation, takes its conclusion, and enforces "confirmed ⇒ cites
   an observed effect." The sink oracles become the strongest *observer*, not the *decider*.
5. **Later executors** — PHP, Ruby, Go — each just implements `Executor`; the observation layer and the
   verdict logic are already general.

## What changes, what stays

- **Stays:** isolation (container/WSL2, never the host); the Case File; the marker/canary convention;
  the "cheapest sufficient evidence" instinct; the strong sink oracles (now as observers).
- **Changes:** the tool no longer renders the verdict — it renders *facts*; the model holds the final
  say under the grounding rule; the "9 classes" stop being the boundary and become the subset that
  *also* has a strong automatic witness; "run the code" becomes general across languages.

## One-line summary

The model reasons and decides everything; the tools run whatever it asks — in any language — and hand
back what actually happened, so the model's final verdict is anchored to reality instead of floating
free. Confirmation requires a real observed effect; everything else is an honest, reasoned lead.
