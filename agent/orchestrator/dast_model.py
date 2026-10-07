"""Model-driven payloads -- the MODEL crafts, deterministic effect-detectors PROVE.

The deterministic battery (dast_oracle) fires fixed payloads; this layer lets the model craft payloads
TAILORED to the observed response -- the right quote/comment style for the DB that errored, a breakout
for the exact reflection context, the template syntax it fingerprinted, a filter-evading encoding. It is
an opt-in ESCALATION run only where the battery found nothing.

Grounding rule is unchanged: the model only PROPOSES. A proposed payload becomes a finding ONLY when a
tool-observable effect fires -- a DB-error signature, an OAST callback to our canary, execution in our
headless browser, a system-file signature, or a distinctive COMPUTED value the server returned (present
now, absent from the baseline, and NOT a literal in the payload). So a wrong/hallucinated payload yields
"not proven", never a false confirm.

Pure core: build_prompt / parse_probes / prove_response (unit-tested on canned data). run() is the thin
orchestration around a Model + a dast_oracle.Sender + the OAST canary + the headless browser.
"""
from __future__ import annotations

import json
import re
import secrets

from . import dast_oracle as do
from . import dom_oracle

_NOSQL_ERRORS = ("mongoerror", "bsonerror", "failed to parse", "e11000", "mongoservererror")


def _factors():
    """Two factors + their product; the product is the distinctive value an SSTI/eval payload must
    COMPUTE (not contain literally). Randomized so it can't collide with a value already on the page."""
    a, b = 7919, secrets.randbelow(9000) + 1000
    return a, b, str(a * b)


def build_prompt(route, vector, param, baseline, probe, canary_url, marker, a, b, expect):
    """(system, user) for the payload-crafting call. Pure. The harness PROVES the effect; the model only
    proposes payloads, each tagged with its class."""
    system = (
        "You are a web-application penetration tester crafting BLACK-BOX injection payloads for a single "
        "parameter. You do NOT decide success -- the harness proves the effect with a tool. Craft payloads "
        "TAILORED to the observed responses (quote/comment style for the DB that errored, a breakout for "
        "the exact reflection context, the template syntax you fingerprint, filter-evading encodings).\n"
        "Rules that make a payload PROVABLE:\n"
        f"- XSS: the payload must EXECUTE script and surface the marker {marker} (e.g. alert('{marker}')), "
        "placed to break out of the reflection context you see.\n"
        f"- SSRF or blind command/code execution: make the SERVER fetch {canary_url} (a URL we control) -- "
        "a callback proves it.\n"
        f"- SSTI / eval: craft an expression in the template/language syntax you believe the server uses "
        f"that EVALUATES {a}*{b}; it must COMPUTE the value, it must NOT contain the number {expect} "
        "literally.\n"
        "- SQLi / NoSQLi: aim to trigger a database error or a clear boolean/union difference.\n"
        "- path traversal: escape the directory to read a known system file.\n"
        'Output ONLY a JSON array, 3-8 items, most-likely first, each: {"class":"sqli|nosqli|xss|ssti|'
        'eval|ssrf|cmd|path","payload":"..."}. No prose.')
    user = (f"Target: {route}  vector={vector}  param={param}\n"
            f"Baseline (benign '1'): HTTP {getattr(baseline, 'status', None)}, {getattr(baseline, 'length', 0)} bytes\n"
            f"  {(getattr(baseline, 'body', '') or '')[:300]!r}\n"
            f"Probe (a single quote): HTTP {getattr(probe, 'status', None)}, {getattr(probe, 'length', 0)} bytes\n"
            f"  {(getattr(probe, 'body', '') or '')[:300]!r}")
    return system, user


def parse_probes(text):
    """The model's JSON array of {class, payload} (tolerates ```json fences and a <think> preamble). Pure."""
    after = (text or "").split("</think>")[-1]
    m = (re.search(r"```(?:json)?\s*(\[.*?\])\s*```", after, re.S)
         or re.search(r"(\[\s*\{.*\}\s*\])", after, re.S)
         or re.search(r"(\[\s*\{.*\}\s*\])", text or "", re.S))
    if not m:
        return []
    try:
        arr = json.loads(m.group(1))
    except Exception:
        return []
    out = []
    for d in arr:
        if isinstance(d, dict) and d.get("payload") is not None:
            out.append({"class": str(d.get("class") or "").lower(), "payload": str(d.get("payload"))})
    return out


def prove_response(probe, resp, baseline, expect=None):
    """Deterministic, payload-agnostic effect checks on a single response (pure). Returns a PoC or None.
    Proves: DB error (sqli/nosqli), system-file signature (path), and a distinctive COMPUTED value the
    server returned (ssti/eval/union) -- present now, absent from the baseline, and not a payload literal."""
    cls = (probe.get("class") or "").lower()
    payload = probe.get("payload", "")
    body = getattr(resp, "body", "") or ""
    low = body.lower()
    base_low = ((getattr(baseline, "body", "") or "") if baseline else "").lower()
    for sig in do._SQL_ERRORS:
        if sig in low and sig not in base_low:
            return do._poc("sqli", "CWE-89", payload,
                           f"DB error signature {sig!r} elicited (status {getattr(resp, 'status', None)})",
                           extra={"oracle": "model-driven"})
    for sig in _NOSQL_ERRORS:
        if sig in low and sig not in base_low:
            return do._poc("nosqli", "CWE-943", payload,
                           f"NoSQL driver error {sig!r} elicited", extra={"oracle": "model-driven"})
    for sig in do._PATH_SIG:
        if sig.search(body):
            return do._poc("path", "CWE-22", payload,
                           f"system-file signature ({sig.pattern!r}) in response", extra={"oracle": "model-driven"})
    if expect and expect in body and expect not in base_low and expect not in payload:
        cwe = {"ssti": "CWE-1336", "eval": "CWE-94"}.get(cls, "CWE-89")
        return do._poc(cls or "ssti", cwe, payload,
                       f"server returned the computed value {expect} (evaluated, not a literal in the payload)",
                       extra={"oracle": "model-driven"})
    return None


def _dom_check(sender, payload, marker, resp, headers):
    """Render the model's XSS payload and confirm EXECUTION of the marker (Tier-2, same as dast_oracle)."""
    try:
        url = sender.url_for(payload)
    except Exception:
        url = None
    if url:
        execs, _ = dom_oracle.capture_execs(url, headers or {})
    else:
        execs, _ = dom_oracle.capture_execs("about:blank", headers or {}, html=getattr(resp, "body", "") or "")
    if execs and any(marker in str(e) for e in execs):
        return do._poc("xss", "CWE-79", payload, "model-crafted payload executed in the rendered DOM",
                       extra={"oracle": "model-driven"})
    return None


def run(model, sender, baseline, probe, canary=None, headers=None, budget=6):
    """Ask the model for payloads tailored to (baseline, probe), fire each through the Sender, and prove
    with the deterministic effect-detectors + the OAST canary. Returns a PoC dict or None. Raises only
    ModelAuthError (the caller disables the model once); every other failure degrades to None."""
    from .oast import CONTAINER_TO_HOST
    from .model import ModelAuthError
    marker = "wavem" + secrets.token_hex(3)
    a, b, expect = _factors()
    token = canary.new_token() if canary else None
    cb = canary.url(token, getattr(canary, "host", None) or CONTAINER_TO_HOST) if canary else "http://oast.invalid/"
    system, user = build_prompt(sender.route, sender.vector, sender.param, baseline, probe, cb, marker, a, b, expect)
    try:
        text = model.generate(system, user, max_new_tokens=1200, temperature=0.3)
    except ModelAuthError:
        raise
    except Exception:
        return None
    for p in parse_probes(text)[:budget]:
        try:
            resp = sender.send(p["payload"])
        except Exception:
            continue
        poc = prove_response(p, resp, baseline, expect)
        if poc:
            return poc
        if p["class"] == "xss" and marker in p["payload"]:
            got = _dom_check(sender, p["payload"], marker, resp, headers)
            if got:
                return got
    if canary and token and canary.hit(token, wait=1.0):
        return do._poc("ssrf", "CWE-918", "<model-crafted>",
                       f"server dialed our OAST canary (token {token}) from a model-crafted payload",
                       extra={"oracle": "model-driven+oast"})
    return None
