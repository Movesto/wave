# Two class-level fixes: unauthenticated-exec detection + adaptive sandbox provisioning

Driven by the opencode run (GHSA-vxw4-wv6m-9hhh / CVE-2026-22812). wave found the `/session/:id/shell` →
`spawn` chain but landed it as a **believed CWE-78 injection lead**, not the actual CVE, for two distinct
reasons. Each is an instance of a *class* of gap, so each fix is a general mechanism, not a one-off patch.

---

## 1. Why the CVE came out mislabeled — the three recall tiers

wave recognizes access-control classes (`authz/idor/access/bola`, severity 5) but has **no source pin** for
any of them. They can only enter detection through the weaker tiers:

| Tier | Mechanism | Classes | Needs a running target? |
|---|---|---|---|
| **1 — strong** | source regex pin → reachability → prove (+ `detector._codemap_pins` recall floor) | cmd, ssrf, path, deser, xss, eval, … (the pinnable classes) | no |
| **2 — behavioral** | live oracle (`idor.py` differential, `missing_controls.py` rate probe) | idor, access, bola, rate-limit | **yes — DAST** |
| **3 — static advisory** | coarse repo-level presence (`controls.py`) | CSRF-missing, rate-limit-missing, cookie flags | no, but no per-route reach |

This is **principled, not an oversight**: injection = the *presence* of a dangerous call (pinnable,
witnessable); access-control = the *absence* of a required check (no line to match; context-dependent, so
raising it blindly is noise). You can't regex a negative.

**But there is a seam.** When a remote route *reaches a tier-1 sink*, the reachable sink supplies the signal
the authz check normally has to guess: *this path must be guarded.* So the absence becomes safely raisable.

### `authzcov.py` — reach × guard, in the raising direction

A deterministic add-on (runs in `controls.scan` when the `all` pipeline has the call graph) that flags a
**remote route reaching a sev≥5 sink with no auth guard on it** as a **needs-review CWE-306/862 lead**.
It composes two things wave already computed — reachability (`reaches_untrusted_entry_bound`) and guard
detection — except guardmap only ever *cleared* false IDOR leads; this is the first use in the *raising*
direction.

Route handlers come in two shapes, so it anchors two ways:

- **(A) named handler** → walk the call graph back from the sink to a genuine **HTTP-route** entry (Flask
  decorator, App-Router method export, …). Catches cross-file sinks.
- **(B) inline route callback** → the opencode case: `app.post("/…/shell", async (c) => …)` is an anonymous
  arrow, so `server.ts:1434` has **no enclosing function** in the codemap and the call graph can't anchor it.
  Anchor instead on the sink being pinned in a **server-endpoint file** (declares routes, or reads a request
  object directly).

**Conservative by construction** (the dangerous direction is crying wolf): NEEDS-REVIEW only; remote +
sev≥5 only; ≤2 leads per file, ≤15 total; auth detection is generous (any auth-ish signal *suppresses*, the
safe direction); every finding carries the caveat "if auth is enforced by a framework layer this scan can't
see, disregard."

**Two real-target lessons that shaped it** (both found by running it on opencode, not in synthetic tests):
- `_is_web_route_entry` must be **narrower than `reachability._ROUTE_HINTS`** — the latter also tags
  event-bus/queue/socket handlers (`wave:event-handler`), which are not HTTP routes. Trusting them produced
  false positives on opencode's CLI/event handlers (`uninstall.ts`, `spawn.ts`).
- The auth-signal set must stay **strong**: a bare `session` token matched `SessionPrompt`/`sessionID` noise
  near the shell sink and wrongly suppressed the real CVE.

Result on opencode: **2 clean leads — `server.ts:1434` (the shell-route CVE) and `server.ts:226` (an
unauth SQL endpoint) — and zero CLI false positives.**

---

## 2. Why it couldn't be *witnessed* — runtime-rigid provisioning

The prove sandbox provisions `node:20-slim` + `tsx` and runs `npm install`. opencode is a **Bun** project, so
`npm install` failed and the repro died on `Bun.*` / top-level-await under Node. The model *correctly
diagnosed* this (it probed for `bun`) — it had no lever to fix it: `install` fetches importable *packages*,
not a *runtime*; runs are offline; and provisioning had no concept of Bun.

Fixing one runtime doesn't close the class — the next unknown stack (Deno, …) hits the same wall. So the fix
is **data, not a branch**.

### `runtimes.py` — a data-driven runtime registry

A table mapping project signals → a `Runtime` (trusted image, install recipe, run hint). Adding a stack is
**one row**. `detect(target)` prefers a strong manifest (a lockfile) and falls back to a source signal
(`Bun.`/`Deno.`) — which is how it identifies opencode as Bun even when the scan target is a sub-directory and
the lockfile sits at an un-scanned repo root.

**Policy: flexible in *what*, strict in *how*.** The registry **is** the trust boundary — `is_trusted_image`
only clears images named in the table, so a provisioning request can never pull an arbitrary image, and
egress stays confined to the single install step.

Wiring:
- `js_env.prepare` is now runtime-aware: a Bun/Deno project is provisioned with its **own image + installer**
  (`ensure_image` pulls a trusted image; `ensure_runtime_deps` runs e.g. `bun install`) instead of the
  node+tsx default. Graceful: a failed pull falls through to the node path, so a candidate stays a lead and
  nothing crashes.
- The model's `install` action gains a `runtime` nomination (`install({runtime: "bun"})`): the investigator
  can self-serve the interpreter when it hits "command not found: bun". **Verified** by a deterministic floor
  (registry membership) plus a reject-only cross-check (`_verify_runtime`: if the project auto-detects a
  *different* runtime, the nomination is blocked). Budget-bounded; user-visible `[deps]` line.

Result on opencode: `runtimes.detect` → `bun` / `oven/bun:1`, so a re-run provisions the Bun toolchain and
the witness can actually execute the chain instead of dying on `npm install`.

---

## Net effect for the opencode re-run

- The authz gap is now **raised statically** (`server.ts:1434` as unauth-exec CWE-306) regardless of whether
  the sandbox builds — so even a blocked witness yields the correct *framing*.
- The witness is now **provisionable** (Bun), so a confirm is reachable rather than structurally blocked.

The two gaps the first run exposed — *authz-framing* and *witness-build* — are both closed by general
mechanisms (a reach×guard composition and a runtime registry), not by special-casing this CVE.
