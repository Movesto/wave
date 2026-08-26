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
# LEGITIMATE multipliers -- a secure server SHOULD honor these, so lowering them lowers the total by
# design (you get fewer goods, not underpay). Treating them as tamper candidates is a false positive,
# so they are excluded from the money-field set (incl. any the model suggests).
_LEGIT = re.compile(r"quant|qty|count|\bnum\b|items?|seats?|units?|guests?|nights?|days?|weeks?|months?|"
                    r"people|pax|tickets?|rooms?|passengers?", re.I)
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
    cand = [f for f in cand if not _LEGIT.search(f)]        # never tamper a legitimate quantity/count multiplier
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


# ---- Privilege-via-parameter / mass assignment (CWE-915) -------------------------------------------
# An account create/update endpoint that binds ALL client fields lets the client set a privilege
# attribute the server should own (role=admin, is_admin=true). Proven differentially: an attacker who
# injects the field ends up with it PERSISTED, while a control account that never sent it stays default.
# (Surface avoids register/signup on purpose -- those collide with the rate-limit oracle's sensitive
# set; profile/account/user-update routes are the clean, non-overlapping mass-assignment surface.)
_PRIV_ROUTE = re.compile(r"profile|account|\buser(s|_update|-update)?\b|member|settings|\bme\b|onboard", re.I)
_PRIV_FIELDS = {
    "role": "admin", "user_type": "admin", "account_type": "admin", "usertype": "admin",
    "privilege": "admin", "scope": "admin", "permissions": "admin", "grant": "admin", "group": "admin",
    "is_admin": True, "isadmin": True, "admin": True, "is_staff": True, "isstaff": True,
    "is_superuser": True, "superuser": True, "verified": True, "is_verified": True,
    "access_level": 99, "level": 99,
}
_PRIV_KEYS = set(_PRIV_FIELDS)


def privilege_routes(routes):
    """POST/PUT routes that create or update an account/profile (mass-assignment surface), excluding
    the auth endpoints the rate-limit oracle already owns (register/signup/login/reset)."""
    seen, out = set(), []
    for r in routes:
        if (r.method in ("POST", "PUT", "PATCH") and _PRIV_ROUTE.search(r.path)
                and not re.search(r"login|signin|register|signup|reset|forgot|logout", r.path, re.I)
                and r.path not in seen):
            seen.add(r.path)
            out.append(r)
    return out


def _collect_priv(resp):
    """Walk a response body (nested dicts/lists) and collect every privilege-ish field -> {lower: value}."""
    out = {}

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(k, str) and k.lower() in _PRIV_KEYS and not isinstance(v, (dict, list)):
                    out.setdefault(k.lower(), v)
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    try:
        walk(json.loads(resp or ""))
    except Exception:
        pass
    return out


def _matches(readback, sentinel):
    """Did the readback take the injected privileged value?"""
    if readback is None:
        return False
    if isinstance(sentinel, bool):
        return readback is True or str(readback).strip().lower() in ("true", "1", "yes")
    if isinstance(sentinel, (int, float)):
        try:
            return float(readback) >= float(sentinel)
        except (TypeError, ValueError):
            return False
    return str(readback).strip().lower() == str(sentinel).strip().lower()


def prove_mass_assignment(rt, route, auth=None):
    """Differential: create a CONTROL account (no privilege fields) and an ATTACK account that injects
    them. If the attacker's readback shows an injected privilege PERSISTED while the control stays
    default, the server trusts a client-controlled privilege attribute (mass assignment). Server that
    strips/ignores privilege fields -> attack readback == control -> DEFER."""
    from secrets import token_hex
    tag = token_hex(3)
    common = {"password": "Wave_123!"}
    ctrl = {**common, "username": f"wctl{tag}", "email": f"c{tag}@wave.test", "display_name": "ctl"}
    atk = {**common, "username": f"watk{tag}", "email": f"a{tag}@wave.test", "display_name": "atk", **_PRIV_FIELDS}
    _, rc = exploit.fire(rt.base_url, route.method, route.path, ctrl, headers=dict(auth or {}))
    _, ra = exploit.fire(rt.base_url, route.method, route.path, atk, headers=dict(auth or {}))
    pc, pa = _collect_priv(rc), _collect_priv(ra)
    if not pa:
        return {"status": "not-proven", "cwe": "CWE-915",
                "notes": "no privilege field reflected in the account response -- nothing to compare"}
    for field, sentinel in _PRIV_FIELDS.items():
        av, cv = pa.get(field), pc.get(field)
        if _matches(av, sentinel) and not _matches(cv, sentinel):
            return {"status": "proven", "cwe": "CWE-915", "oracle": "differential",
                    "payload": f"{field}={sentinel}", "request": f"{route.method} {route.path}",
                    "evidence": (f"attacker-injected '{field}={sentinel}' PERSISTED (readback '{field}'={av!r}) "
                                 f"while a control account that never sent it stays default ('{field}'={cv!r}) "
                                 f"-- server binds a client-controlled privilege attribute (mass assignment)")}
    return {"status": "not-proven", "cwe": "CWE-915",
            "notes": f"no injected privilege persisted (attack readback {pa} == control-default) -- server owns it"}


def candidate_for_privilege(route):
    return Candidate(file=route.file, unit=route.function or "<handler>", line=0, cwe="CWE-915",
                     family="business logic: privilege-via-parameter (mass assignment)", detector="differential",
                     sink=f"{route.method} {route.path}", provable=True, rank=48,
                     route_hint=f"{route.method} {route.path}")


# ---- Replay / idempotency abuse (CWE-837) ---------------------------------------------------------
# A once-only operation (claim a bonus, redeem a coupon, cash a referral) with no idempotency guard can
# be REPLAYED, each time accumulating value in the attacker's favor. Proven by firing the SAME request N
# times and watching a BALANCE-like field STACK monotonically. A secure server applies it once and
# plateaus -> no accumulation -> DEFER. Only value/balance fields are tracked (a transaction/receipt id
# legitimately increments and must not count).
_REPLAY_ROUTE = re.compile(r"claim|redeem|coupon|voucher|promo|\bgift\b|bonus|reward|referral|cashback", re.I)
_CUMULATIVE = {"balance", "wallet", "credit", "credits", "points", "funds", "reward", "rewards",
               "cashback", "bonus", "coins", "tokens", "store_credit"}


def replay_routes(routes):
    """POST/PUT routes for a once-only value operation (claim/redeem/coupon/bonus) -- replay candidates."""
    seen, out = set(), []
    for r in routes:
        if r.method in ("POST", "PUT") and _REPLAY_ROUTE.search(r.path) and r.path not in seen:
            seen.add(r.path)
            out.append(r)
    return out


def prove_replay(rt, route, auth=None, n=4):
    """Fire the SAME operation n times as one identity; if a balance-like field STACKS strictly across
    replays, the once-only/idempotency control is missing. Plateau (applied once) -> DEFER."""
    from secrets import token_hex
    u = "wrep" + token_hex(3)
    body = {"username": u, "user": u, "code": "WAVE", "coupon": "WAVE"}   # extras harmless; app uses what it needs
    seqs = {}
    for _ in range(n):
        st, resp = exploit.fire(rt.base_url, route.method, route.path, body, headers=dict(auth or {}))
        for k, v in _nums(resp).items():
            if k.lower() in _CUMULATIVE:
                seqs.setdefault(k, []).append(v)
    for k, vals in seqs.items():
        if len(vals) == n and all(vals[i] < vals[i + 1] for i in range(n - 1)):
            return {"status": "proven", "cwe": "CWE-837", "oracle": "differential",
                    "payload": f"{n}x replay of {route.method} {route.path}", "request": f"{route.method} {route.path}",
                    "evidence": (f"the same operation replayed {n}x kept stacking '{k}': {vals} -- no once-only/"
                                 f"idempotency guard, each replay credits the attacker again")}
    return {"status": "not-proven", "cwe": "CWE-837",
            "notes": f"no value field accumulated across {n} replays (tracked {seqs or 'none'}) -- once-only guard present"}


def candidate_for_replay(route):
    return Candidate(file=route.file, unit=route.function or "<handler>", line=0, cwe="CWE-837",
                     family="business logic: replay / missing idempotency", detector="differential",
                     sink=f"{route.method} {route.path}", provable=True, rank=44,
                     route_hint=f"{route.method} {route.path}")
