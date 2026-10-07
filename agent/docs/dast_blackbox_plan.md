# Black-box DAST plan — proving a vuln from a LIVE URL only

Status: **INJECTION + OAST + DIFFERENTIAL ALL INTEGRATED** (2026-10-06). Branch: `corpus-rebuild-and-dpo`.
Scope: **pure black-box** (URL only, never source), **full loop** in one pass. OAST is now WIRED (local
canary by default; `--oast-host` for a remote-reachable host/tunnel). Verified live on VAmPI: SQLi
(confirmed) + missing rate-limit (anomalous_state) in one run.

Fifth increment (2026-10-06, user: "improve the dast in areas it lacks"): closed the two real gaps --
RECALL and realism.
  - RECALL (recon now FEEDS the attack): `_expand_surface` ingests an OpenAPI/Swagger spec
    (dast_web.parse_openapi -> routes + params; swagger-2 + openapi-3, incl requestBody) so a JSON API
    needs NO manual --target-param; robots.txt Disallow + sitemap.xml <loc> become routes/targets;
    browser_recon now KEEPS link query strings and `query_targets` turns every `?p=` into a target
    (previously dropped -- the biggest hole). All targets deduped, fed to the injection battery + the
    route table (so IDOR/authz/rate-limit see more too).
  - REALISM (test as a logged-in user): `scan(auth_headers=)` + CLI `--header "N: v"` / `--cookie` and a
    shell prompt -- supply a REAL session instead of the synthesized dummy login. Provided session wins;
    synthesis is skipped.
  - All new logic pure + offline-tested (parse_openapi sw2/v3, robots, sitemap, query_targets, dedup,
    _expand_surface via mocked fetch, provided-session path). Suite 355.

Fourth increment (2026-10-06, user: "make dast complete -- more than web; think like a red teamer given
only a URL, any angle"): added an EXTERNAL RECON layer (dast_recon.py + dast_web.py) that runs before the
app stage and widens the surface:
  - NETWORK/INFRA: DNS (A/AAAA/CNAME/MX/NS/TXT; dnspython optional), email spoofing (SPF/DMARC ->
    spoofable?), subdomain takeover (dangling CNAME to a known provider), TLS cert (expiry/self-signed/
    hostname-mismatch + SANs as extra surface), port/service exposure scan (curated ~25 ports, flags
    externally-reachable DB/cache/admin, CWE-668).
  - HTTP POSTURE: stack fingerprint; missing security headers (HSTS/CSP/XFO/XCTO/Referrer); weak cookie
    flags (HttpOnly/Secure/SameSite); CORS misconfig (origin reflection +/- credentials, CWE-942);
    dangerous methods (TRACE/PUT/..); sensitive-path/content discovery with CONTENT-SIGNATURE gating
    (/.git, /.env, /actuator, swagger, phpinfo, backups, admin -- a 200 only counts if the body matches).
  - Tiers: recon FACTS -> entity; posture weaknesses -> anomalous_state; concrete exposures/leaks
    (.git/.env/takeover/dir-listing) -> confirmed. Flags `--no-recon`, `--no-ports`. All analyzers are
    PURE + unit-tested offline (24 tests); network fetchers guarded. Nothing run live (user's own site).

Second increment (2026-10-06, user: "add idor, authz; integrate ssrf, blind rce; make dast work like
sast"): the driver now runs ALL oracle classes in one pass with honest verdict tiers --
  - CONFIRMED (tool-witnessed): sqli / xss / path / redirect (response-diff/DOM) + ssrf / blind-RCE (OAST callback).
  - ANOMALOUS_STATE (differential, severity is a judgment): idor (idor.prove_idor), authz/broken-access
    (unauth-vs-auth body differential), missing rate-limit (missing_controls.prove_no_ratelimit),
    missing old-password check (prove_no_oldpassword). Reuses the existing black-box-ready oracles.
  - OAST: oast.Canary started per run; ssrf/cmd witnesses self-skip without it.
  - Multi-identity auth via auth.synthesize_multi (`--identities`, default 2, for IDOR).
  - ssrf/cmd/redirect are param-NAME gated (speed+precision); sqli/xss/path run on every param.

Third increment (2026-10-06, user: "close the gaps; don't test any live site; adhere to rules"):
  - NEW witnesses, all sound + client-only: SSTI (CWE-1336) + eval/expr-injection (CWE-94) via
    ARITHMETIC REFLECTION (send `{{A*B}}`/`${A*B}`/`<%=A*B%>` or bare `A*B`; the PRODUCT in the
    response -- never the literal -- proves evaluation); NoSQLi (CWE-943) via driver error signatures
    + an OPERATOR DIFFERENTIAL (`{$ne:X}` matches all vs `{$eq:X}` matches none, through a new
    `Sender.send_op` that places a structural JSON value -- assemble() would stringify it).
  - Only `deser` stays deferred, ON PURPOSE: a sound black-box witness needs a stack-specific gadget
    chain we can't synthesize blind; faking it would mint false confirms (forbidden).
  - Rate-limit precision tightened: `missing_controls.prove_no_ratelimit(require_success=)` -- DAST
    sets it True so an endpoint that merely 4xx-rejects the request shape isn't mislabeled "no rate
    limit". Default stays False (bench/SAST behavior unchanged).
  - SAFETY: `wave dast` now REFUSES to run without `--authorized` (operator asserts permission for the
    target). The gate is in cmd_dast, BEFORE any network call -- a scanner must never hit a site the
    operator isn't authorized to test. Per user: no live testing on unpermitted sites; all verification
    here is offline unit tests (311 pass). SSRF/blind-RCE/SSTI/eval/NoSQLi are unit-proven over canned
    responses / a fake canary -- live verification is the user's to do on their own authorized site.

## The problem, stated plainly

Everything built so far is **grey-box**: we have the source, we `provision` the app under Docker, and
we `instrument` its sinks so the oracle can read a harness-planted marker (`WAVE-SINK-*`, `wave_HIT`)
from inside the process. The new mode gets **only a URL**. There is no source, no boot, and — the part
that forces real change — **no way to instrument someone else's live site**, so the authoritative
in-process marker oracle (`oracle.py`) cannot fire. The proof has to come from OUTSIDE.

So black-box keeps wave's grounding rule (*translate, then prove with a tool*) but swaps the tool:

> A black-box `confirmed` rests on a witness observable **from the client only** — the payload EXECUTED
> in our own headless browser, a server-side effect called back to OUR canary, or a response
> differential no benign input could produce. Otherwise it is a review lead with its request attached.

## What already works black-box (reuse, do not rebuild)

The live-driving stages were written for grey-box DAST but touch the target through **only
`rt.base_url` + `exploit.fire`** — they never read source. Against a `Target(base_url=<the URL>)`
stand-in they work unchanged:

- `browser_recon.recon(rt)` — crawls the running app for forms/links/egress (the surface). This is
  the black-box replacement for eyes/codemap/detector.
- `auth.synthesize(rt, routes)` / `synthesize_multi` — registers + logs in 1..n identities over live
  HTTP; returns auth headers.
- `dom_oracle.prove_xss(url, headers, marker)` — renders in headless Chromium and witnesses XSS
  **execution** (TIER-2, fires in OUR browser — black-box by nature).
- `oast.Canary` — out-of-band witness (Mode 2 public canary). **Deferred** this increment.
- `bizlogic` / `idor` / `missing_controls` / `behavioral` — differential logic oracles, already
  HTTP-only. Produce `anomalous_state` / `blocked`, never a tool-witnessed `confirmed` (correct: a
  logic violation is a judgment).
- `recorder.CaseFile` — the output substrate. A black-box finding is a `confirmation`/`confirmed`
  entry whose `provenance` is the **replayable request**, not a `file:line`.
- `exploit.assemble(decision, marker)` — mechanical route+vector+param→request. Reused as-is.

## What is NET-NEW

1. **`dast.Target`** — a tiny stand-in with `.base_url` (+ captured auth/cookies) so every consumer
   above runs without a provision handle. Plus a reachability health-check (the "boot" replacement).
2. **A fuller HTTP primitive** — `exploit.fire` truncates bodies and drops headers/timing. The
   differential oracle needs `(status, body_full, headers, elapsed_ms)`. New `dast_oracle._send`.
3. **`dast_oracle` — the response/timing differential oracle (the real new work).** Deterministic
   client-only witnesses, one per class:
   - **XSS (CWE-79)** — reflect probe un-encoded in an HTML context → hand to `dom_oracle` for the
     EXECUTION witness. Reflection alone ≠ proof.
   - **SQLi boolean (CWE-89)** — `' AND '1'='1` vs `' AND '1'='2`: a stable content/row differential
     that the pair `true`/`false` produces and benign input does not.
   - **SQLi error** — payload elicits a DB-error signature (`SQL syntax`, `ORA-`, `SQLSTATE`, …).
   - **SQLi / cmd blind TIMING** — a `SLEEP(n)` / `pg_sleep(n)` payload delays the response by ~n vs
     baseline, confirmed over repeats to beat jitter. (cmd blind reuses the timing channel.)
   - **Open redirect (CWE-601)** — payload in a redirect param → `Location` points off-origin.
   - **Path traversal (CWE-22)** — `../../../etc/passwd` → a `root:x:0:0` / `[extensions]` signature.
   - **SSRF / blind (CWE-918, blind RCE)** — needs OAST. **Deferred → review lead.**
   Each witness returns a structured PoC: the exact request, the differential observed, the class.
4. **`dast_scan` — the driver/loop.** health-check → recon surface (+ `--seed`/OpenAPI) → auth →
   enumerate (route, param) targets → the MODEL proposes vector/param/class from the SURFACE (not
   source; a black-box variant of `craft_requests`) → run the matching oracle → record PoC → then the
   already-black-box logic oracles → `CaseFile.report()`.
5. **CLI** — `wave dast <url> [--seed path] [--auth ...] [--max-pages N]`. URL-first; no repo path;
   skips SAST entirely.

## Honest limits (the "does the fix create new problems?" test)

- **Recall is response-shaped.** No source means no sink inventory; we only probe what the crawl +
  model surface. A route the crawler never reaches is never tested. Stated, not hidden.
- **Differentials have a false-positive floor** (a page that varies run-to-run). Mitigation: require a
  STABLE differential (benign baseline repeated; the true/false pair must separate cleanly), and
  timing confirmed over repeats. When it won't stabilize → review lead, never a confirm.
- **SSRF/blind are under-covered** until OAST infra lands — by explicit decision, not oversight.
- **No patch stage.** We don't have the code, so the deliverable is a reproducible HTTP PoC, not a
  patch+reverify. `dast` writes findings; `patch` is N/A in this mode.

## Build order

1. `dast.Target` + health-check + `dast_oracle._send`.  *(testable offline)*
2. `dast_oracle` witnesses + unit tests over canned responses (fake `_send`).  *(the core)*
3. `dast_scan` driver + `cmd_dast` CLI.
4. Live end-to-end on a known-vulnerable app pointed at by URL only (treat as opaque).
5. Regression: the existing suite stays green; add DAST cases to it.
