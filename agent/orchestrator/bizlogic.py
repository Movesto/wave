"""Business-logic oracle -- the FIRST Tier-2 class: web parameter tampering (CWE-472, external control
of an assumed-immutable web parameter). Unlike an injection sink, 'the server should not trust this
field' is a JUDGMENT; but the VIOLATION is proven deterministically by a server-confirmed, attacker-
favorable state delta -- a differential, exactly like IDOR (idor.py) and the missing-controls oracle.

Design lesson (baked in): field NAMES are app-specific FACTS, not judgments -- so the oracle PERCEIVES
them by probing rather than trusting a blind model guess. value_routes() flags the value-bearing
surface deterministically; the model optionally supplies structural body fields (a hint); then the
oracle EMPIRICALLY discovers the trusted field: set candidate money-fields to a baseline, lower each
one, and watch which response value tracks it proportionally. A server that recomputes shows NO delta
on any field -> DEFER. This is the general business-logic pattern: MODEL frames the surface/invariant,
a deterministic differential PROVES the break.

Soundness (Tier-2): the delta is deterministic, but 'this field is security-relevant' rests on the
money-field judgment/context -> findings carry 'logic-judgment: needs confirm', are NOT auto-fixed,
and are surfaced with the demonstrated before/after evidence for human review.
"""
import json
import re

from . import exploit
from .models import Candidate

_VALUE_ROUTE = re.compile(
    r"checkout|purchase|\border\b|payment|\bpay\b|\bcart\b|\bbuy\b|transfer|withdraw|topup|top-up|"
    r"refund|charge|billing|invoice|subscri|donate|deposit", re.I)
# candidate fields a server should own/compute -- probed empirically (money/authority fields)
_MONEY = ["price", "amount", "total", "cost", "unit_price", "subtotal", "fee", "value", "balance", "discount"]
_HONEST, _LOW = 100.0, 10.0                              # a 10x drop -> the tracked value must fall to ~0.1


def value_routes(routes):
    """POST/PUT routes whose path suggests a value-bearing state change (a tampering surface)."""
    seen, out = set(), []
    for r in routes:
        if r.method in ("POST", "PUT") and _VALUE_ROUTE.search(r.path) and r.path not in seen:
            seen.add(r.path)
            out.append(r)
    return out


_SYS = (
    "You are testing web routes for BUSINESS-LOGIC PARAMETER TAMPERING (CWE-472): a request field a "
    "server should COMPUTE or own (price, amount, total, cost, discount, balance) but instead trusts "
    "from the client, letting an attacker pay less / gain more. For each value-bearing route, give a "
    "plausible request BODY so the endpoint accepts the request (ids, quantities, currency, etc.), and "
    "list any field names you suspect are client-trusted money fields. Output ONLY a JSON array (empty "
    '[] if none), each: {"method":"POST","path":"/exact/path","body":{structural fields with plausible '
    'values},"fields":["suspected money field names"]}. No prose, JSON only.')


def propose_hints(model, routes):
    """Model supplies a structural body + suspected money-field names per value-route (a HINT only --
    the oracle still empirically discovers/proves the trusted field). Returns {path: hint}."""
    vr = value_routes(routes)
    if not vr:
        return {}
    listing = "\n".join(f"{r.method} {r.path}" for r in vr)
    txt = model.generate(_SYS, "Value-bearing routes:\n" + listing, max_new_tokens=700, temperature=0.2)
    m = re.search(r"(\[.*\])", (txt or "").split("</think>")[-1], re.S)
    valid, hints = {r.path for r in vr}, {}
    if m:
        try:
            for d in json.loads(m.group(1)):
                if isinstance(d, dict) and d.get("path") in valid:
                    hints[d["path"]] = {"body": d.get("body") or {}, "fields": d.get("fields") or []}
        except Exception:
            pass
    return hints


def _nums(resp):
    """Every top-level numeric value in a response body, keyed by name (JSON first, regex fallback)."""
    out = {}
    try:
        obj = json.loads(resp or "")
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    out[k] = float(v)
    except Exception:
        pass
    if not out:
        for k, v in re.findall(r'["\']?(\w+)["\']?\s*[:=]\s*"?(-?\d+(?:\.\d+)?)', resp or ""):
            out.setdefault(k, float(v))
    return out


def prove_tamper(rt, route, auth=None, hint=None):
    """Empirical differential: set candidate money-fields to a baseline, then lower each one; if a
    response value TRACKS a field proportionally (falls to ~0.1x, attacker-favorable), the server
    trusts that client field. A server that recomputes shows no tracked delta -> DEFER."""
    base = dict((hint or {}).get("body") or {})
    cand = list(dict.fromkeys(list((hint or {}).get("fields") or []) + _MONEY))
    baseline = {**base, **{f: _HONEST for f in cand}}
    st0, resp0 = exploit.fire(rt.base_url, route.method, route.path, baseline, headers=dict(auth or {}))
    r0 = _nums(resp0)
    if not r0:
        return {"status": "not-proven", "cwe": "CWE-472",
                "notes": f"no numeric result in the response (status {st0}) -- no delta to judge"}
    for f in cand:
        st, resp = exploit.fire(rt.base_url, route.method, route.path, {**baseline, f: _LOW}, headers=dict(auth or {}))
        r = _nums(resp)
        for k, v0 in r0.items():
            v = r.get(k)
            if v0 > 0 and v is not None and v < v0 and abs((v / v0) - (_LOW / _HONEST)) <= 0.05:
                return {"status": "proven", "cwe": "CWE-472", "oracle": "differential",
                        "payload": f"{f}: {_HONEST} -> {_LOW}", "request": f"{route.method} {route.path}",
                        "evidence": (f"response '{k}' tracked the client-supplied '{f}': {v0} -> {v} when "
                                     f"'{f}' went {_HONEST} -> {_LOW} (attacker underpays; server does not "
                                     f"recompute -- assumed-immutable web parameter is client-controlled)")}
    return {"status": "not-proven", "cwe": "CWE-472",
            "notes": f"no response value tracked any client money-field ({sorted(r0)}) -- server recomputes -> safe"}


def candidate_for(route):
    return Candidate(file=route.file, unit=route.function or "<handler>", line=0, cwe="CWE-472",
                     family="business logic: web parameter tampering", detector="differential",
                     sink=f"{route.method} {route.path}", provable=True, rank=45,
                     route_hint=f"{route.method} {route.path}")
