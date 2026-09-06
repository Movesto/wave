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
    """POST/PUT routes whose path suggests a value-bearing PURCHASE (a tampering / negative-qty
    surface). Money-OUT routes (withdraw/transfer/payout) are EXCLUDED -- they are stateful mutations
    (each call changes a persistent balance), which breaks the tampering oracle's idempotent-probe
    assumption: ~10 sequential probes on a monotonically-draining balance eventually hit the expected
    ratio by coincidence -> a false positive. Those routes are the fund-flow-reversal oracle's domain."""
    seen, out = set(), []
    for r in routes:
        if (r.method in ("POST", "PUT") and _VALUE_ROUTE.search(r.path)
                and not _FLOW_ROUTE.search(r.path) and r.path not in seen):
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


_NUM = r"([-$]*\s*[\d,]*\.?\d+)"                          # leading -/$ in any order, thousands separators; stripped on parse


def _nums(resp):
    """Every keyed numeric value in a response, keyed by (lowercased) name. JSON parses win, so JSON
    apps are unchanged; otherwise HTML/text is scanned -- form inputs (`name=total value="123"`),
    id/class/data spans (`<span id="total">123`), table label/value cells (`<td>Total</td><td>123`),
    and plain `Total: $1,234` text -- so the differential oracles work on apps that render HTML."""
    out = {}
    try:
        obj = json.loads(resp or "")
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    out[k] = float(v)
        if out:
            return out
    except Exception:
        pass
    t = resp or ""

    def add(k, v):
        try:
            out.setdefault(k.lower(), float(v.replace(",", "").replace("$", "").replace(" ", "")))
        except ValueError:
            pass

    for pat in (r'name=["\'](\w+)["\'][^>]*?value=["\']\s*' + _NUM,          # <input name=total value="123">
                r'(?:id|class|data-[\w-]+)=["\'](\w+)["\'][^>]*>\s*' + _NUM,  # <span id="total">123</span>
                r'>\s*([A-Za-z]\w*)\s*:?\s*</t[dh]>\s*<t[dh][^>]*>\s*' + _NUM,  # <td>Total</td><td>$123</td>
                r'["\']?([A-Za-z]\w*)["\']?\s*[:=]\s*["\']?\s*' + _NUM):      # Total: $123  /  total="123
        for k, v in re.findall(pat, t, re.I):
            add(k, v)
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
    if not out:                                         # HTML/text fallback: a rendered privilege field
        t = resp or ""
        for key in _PRIV_KEYS:
            for pat in (rf'name=["\']{key}["\'][^>]*?value=["\']([^"\'>]+)',        # <input name=role value="admin">
                        rf'(?:id|class|data-[\w-]+)=["\']{key}["\'][^>]*>\s*([^<\s][^<]*)',  # <span id=role>admin</span>
                        rf'>\s*{key}\s*:?\s*</t[dh]>\s*<t[dh][^>]*>\s*([^<]+)',      # <td>role</td><td>admin</td>
                        rf'\b{key}\b["\']?\s*[:=]\s*["\']?\s*(\w+)'):               # Role: admin  /  role="admin
                m = re.search(pat, t, re.I)
                if m:
                    out.setdefault(key, m.group(1).strip())
                    break
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


# ---- Workflow / step bypass (CWE-840) -------------------------------------------------------------
# The first class needing SEQUENCE reasoning: a protected step (confirm/ship/finalize) must succeed
# only AFTER its prerequisite (pay/verify/authorize). The bug is a missing state-machine guard. Proven
# by a differential over the SEQUENCE: complete the honest flow (prereq -> protected) to see the
# protected step's success, then hit the protected step with a FRESH identity that skipped the
# prerequisite. If the bypass succeeds the same way, the order is not enforced. A secure app blocks the
# bypass (402/redirect/"payment required") -> the prerequisite matters -> DEFER.
_PREREQ = re.compile(r"\bpay\b|payment|checkout|\bverify\b|\botp\b|authoriz|validate|add[-_]?to[-_]?cart|\bcart\b", re.I)
_PROTECTED = re.compile(r"confirm|complete|finaliz|\bship\b|fulfil|deliver|\bplace\b|place[-_]?order|activate|"
                        r"\bissue\b|approve|grant|checkout[-_]?complete", re.I)
_STEP_KEYS = ["order", "order_id", "orderId", "id", "token", "cart", "cart_id", "reference", "ref",
              "txn", "transaction", "booking", "invoice", "session"]
_ERR = re.compile(r"\berror\b|denied|forbidden|unauthor|not allowed|not permitted|unpaid|not paid|"
                  r"payment.{0,15}(require|need|first|pending|missing)|(require|need).{0,15}payment|"
                  r"incomplete|invalid|\bmissing\b|please (pay|verify|complete|log)|must (pay|verify|complete)|"
                  r"no (active|pending)|\brequired\b", re.I)


def workflow_pairs(routes):
    """Return (protected_route, [candidate prerequisite routes]) -- a later value step and the earlier
    steps that should gate it. The heuristic infers the intended order from route names (model-composed
    multi-step flows are the extension)."""
    prereq = [r for r in routes if r.method in ("POST", "PUT") and _PREREQ.search(r.path)]
    protected = [r for r in routes if r.method in ("POST", "PUT") and _PROTECTED.search(r.path)]
    out = []
    for p in protected:
        qs = [q for q in prereq if q.path != p.path]
        if qs:
            out.append((p, qs))
    return out


def _success(st, body):
    return st is not None and 200 <= st < 300 and not _ERR.search(body or "")


def prove_stepbypass(rt, prereq, protected, auth=None):
    """Differential over the sequence. For a shared resource key: run the honest flow (prereq then
    protected) to confirm the protected step yields a success; then hit the protected step with a FRESH
    resource that never did the prerequisite. Both succeed -> order not enforced (bypass). Fresh blocked
    -> prerequisite gates the step -> DEFER."""
    from secrets import token_hex
    hdr = dict(auth or {})
    for key in _STEP_KEYS:
        r1, r2 = "wf" + token_hex(3), "wf" + token_hex(3)
        pre_body = {"amount": 100, "quantity": 1, "price": 100, "email": f"{r1}@wave.test",
                    "password": "Wave_123!", key: r1}
        exploit.fire(rt.base_url, prereq.method, prereq.path, pre_body, headers=hdr)   # honest prerequisite
        s_h, b_h = exploit.fire(rt.base_url, protected.method, protected.path, {key: r1}, headers=hdr)
        # the key is only valid if the protected route actually USES it -- it must echo THIS resource id.
        # Otherwise the route ignored the key and fell back to a default resource, and the "success" is
        # meaningless (this is exactly how a polluted empty-default order produced a false bypass).
        if not (_success(s_h, b_h) and r1 in (b_h or "")):
            continue
        s_b, b_b = exploit.fire(rt.base_url, protected.method, protected.path, {key: r2}, headers=hdr)  # skip prereq
        if _success(s_b, b_b) and r2 in (b_b or ""):    # bypass recognized ITS distinct id and still succeeded
            return {"status": "proven", "cwe": "CWE-840", "oracle": "differential",
                    "payload": f"{protected.method} {protected.path} without {prereq.path}",
                    "request": f"{protected.method} {protected.path}",
                    "evidence": (f"'{protected.path}' succeeded (status {s_b}) for a fresh '{key}' that never "
                                 f"completed the prerequisite '{prereq.path}' -- same success as the honest flow "
                                 f"(status {s_h}); the step-order/state-machine guard is missing (step bypass)")}
        return {"status": "not-proven", "cwe": "CWE-840",
                "notes": f"'{protected.path}' blocked without '{prereq.path}' (status {s_b}) -- workflow enforced"}
    return {"status": "not-proven", "cwe": "CWE-840",
            "notes": f"could not establish an honest {prereq.path}->{protected.path} flow (no shared key succeeded)"}


def candidate_for_workflow(route):
    return Candidate(file=route.file, unit=route.function or "<handler>", line=0, cwe="CWE-840",
                     family="business logic: workflow / step-order bypass", detector="differential",
                     sink=f"{route.method} {route.path}", provable=True, rank=46,
                     route_hint=f"{route.method} {route.path}")


# ---- Negative quantity / numeric-invariant break (CWE-1284) ----------------------------------------
# The mirror of tampering: here the QUANTITY is the attack vector. A quantity/amount field that should
# be positive but accepts a NEGATIVE value can drive a monetary result NEGATIVE -- the buyer is CREDITED
# instead of charged. Proven by a sign differential: a positive quantity yields a positive total, a
# negative quantity flips it negative. A server that validates/clamps keeps the result >= 0 -> DEFER.
_QTY = ["quantity", "qty", "count", "amount", "num", "units", "items", "number", "seats", "nights"]
_NEG_RESULT = {"total", "amount", "charge", "charged", "subtotal", "grand_total", "cost", "balance",
               "credit", "due", "payable", "sum", "price", "owed", "net"}


def prove_negative(rt, route, auth=None, hint=None):
    """Sign differential: for each quantity-like field, fire quantity=+2 then quantity=-2 (with a price
    present so the total is nonzero). If a monetary result goes from positive to NEGATIVE, the non-
    negativity invariant is unenforced (buyer credited). Validated/clamped result (>=0) -> DEFER."""
    base = dict((hint or {}).get("body") or {})
    base.setdefault("product_id", 1)
    hdr = dict(auth or {})
    for f in _QTY:
        pos = {**base, "price": 100, "unit_price": 100, f: 2}
        neg = {**base, "price": 100, "unit_price": 100, f: -2}
        _, rp = exploit.fire(rt.base_url, route.method, route.path, pos, headers=hdr)
        _, rn = exploit.fire(rt.base_url, route.method, route.path, neg, headers=hdr)
        np_, nn = _nums(rp), _nums(rn)
        for k, vp in np_.items():
            if k.lower() in _NEG_RESULT and vp > 0:
                vn = nn.get(k)
                if vn is not None and vn < 0:
                    return {"status": "proven", "cwe": "CWE-1284", "oracle": "differential",
                            "payload": f"{f}: 2 -> -2", "request": f"{route.method} {route.path}",
                            "evidence": (f"a negative '{f}' drove '{k}' NEGATIVE: {vp} -> {vn} -- no non-"
                                         f"negativity validation, the buyer is CREDITED instead of charged "
                                         f"(numeric-invariant break)")}
    return {"status": "not-proven", "cwe": "CWE-1284",
            "notes": "no monetary result went negative for a negative quantity -- validated/clamped"}


def candidate_for_negative(route):
    return Candidate(file=route.file, unit=route.function or "<handler>", line=0, cwe="CWE-1284",
                     family="business logic: unvalidated quantity (negative -> credit)", detector="differential",
                     sink=f"{route.method} {route.path}", provable=True, rank=45,
                     route_hint=f"{route.method} {route.path}")


# ---- Fund-flow reversal: negative amount on a money-OUT route (CWE-682) ----------------------------
# A withdraw/transfer/payout that doesn't require a POSITIVE amount can be REVERSED: a negative amount
# runs the arithmetic backwards, CREDITING the attacker instead of debiting. Proven by a direction
# differential: a positive amount leaves the account LOWER, a negative amount leaves it HIGHER. A
# server that rejects non-positive amounts blocks the negative case -> no reversal -> DEFER.
_FLOW_ROUTE = re.compile(r"withdraw|transfer|\bsend\b|payout|cashout|remit|\bwire\b|disburse|redeem[-_]?cash", re.I)
_BAL = {"balance", "wallet", "funds", "account_balance", "new_balance", "available", "credit"}


def flow_routes(routes):
    """POST/PUT money-OUT routes (withdraw/transfer/payout) -- fund-flow-reversal candidates."""
    seen, out = set(), []
    for r in routes:
        if r.method in ("POST", "PUT") and _FLOW_ROUTE.search(r.path) and r.path not in seen:
            seen.add(r.path)
            out.append(r)
    return out


def prove_reversal(rt, route, auth=None, amount=50.0):
    """Direction differential on two fresh accounts: one withdraws a POSITIVE amount (balance should
    drop), one a NEGATIVE amount (balance should be REJECTED). If the negative case ends up at least
    `amount` HIGHER than the positive case, the negative amount was credited -- the flow reversed."""
    from secrets import token_hex
    hdr = dict(auth or {})
    un, up = "wneg" + token_hex(3), "wpos" + token_hex(3)
    _, rn = exploit.fire(rt.base_url, route.method, route.path,
                         {"username": un, "user": un, "to": un, "amount": -amount}, headers=hdr)
    _, rp = exploit.fire(rt.base_url, route.method, route.path,
                         {"username": up, "user": up, "to": up, "amount": amount}, headers=hdr)
    nn, np_ = _nums(rn), _nums(rp)
    for k in _BAL:
        bn, bp = nn.get(k), np_.get(k)
        if bn is not None and bp is not None and bn > bp + amount:
            return {"status": "proven", "cwe": "CWE-682", "oracle": "differential",
                    "payload": f"amount = -{amount}", "request": f"{route.method} {route.path}",
                    "evidence": (f"a NEGATIVE amount on '{route.path}' left the attacker with MORE '{k}' "
                                 f"({bn}) than a positive amount did ({bp}) -- a negative withdrawal/transfer "
                                 f"is CREDITED, not debited (fund-flow reversal; no amount>0 validation)")}
    return {"status": "not-proven", "cwe": "CWE-682",
            "notes": "negative amount did not reverse the fund flow (rejected / validated as positive)"}


def candidate_for_reversal(route):
    return Candidate(file=route.file, unit=route.function or "<handler>", line=0, cwe="CWE-682",
                     family="business logic: fund-flow reversal (negative amount)", detector="differential",
                     sink=f"{route.method} {route.path}", provable=True, rank=47,
                     route_hint=f"{route.method} {route.path}")
