"""Black-box DAST oracle regression (dast_oracle.py).

Every witness is exercised over CANNED responses via a fake `send` -- no network, no browser, no model.
Positive AND negative cases: a witness must fire on a real client-observable effect and stay silent when
the param is ignored or the response is benign (the false-positive floor the plan commits to).

Run: pytest tests/test_dast_oracle.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.orchestrator import dast_oracle as do
from agent.orchestrator.dast_oracle import Resp


class Fake:
    """A `send(value)` stub: returns the Resp mapped to the exact value, else `default`."""
    def __init__(self, mapping, default):
        self.mapping, self.default = mapping, default
        self.calls = []

    def __call__(self, value):
        self.calls.append(value)
        return self.mapping.get(value, self.default)


# ---- _similar ----

def test_similar_same_status_and_length():
    assert do._similar(Resp(200, "a" * 100), Resp(200, "a" * 100))
    assert do._similar(Resp(200, "a" * 100), Resp(200, "a" * 98))      # within ratio


def test_similar_rejects_status_or_length_gap():
    assert not do._similar(Resp(200, "x" * 100), Resp(500, "x" * 100))
    assert not do._similar(Resp(200, "x" * 100), Resp(200, "x" * 10))


# ---- boolean SQLi ----

def test_sqli_boolean_fires_on_stable_separation():
    normal = Resp(200, "row: alice " * 20)          # baseline + TRUE look like this
    empty = Resp(200, "no results")                 # FALSE diverges
    send = Fake({"1": normal, "1' AND '1'='1": normal, "1' AND '1'='2": empty}, normal)
    got = do.witness_sqli_boolean(send)
    assert got and got["cwe"] == "CWE-89"


def test_sqli_boolean_silent_when_param_ignored():
    same = Resp(200, "static page " * 20)           # every variant identical -> param ignored
    send = Fake({}, same)
    assert do.witness_sqli_boolean(send) is None


def test_sqli_boolean_silent_on_one_off_noise():
    normal = Resp(200, "row " * 20)
    empty = Resp(200, "none")
    # first pair separates but the stability repeat does NOT -> rejected
    seq = {"1": normal, "1' AND '1'='1": normal, "1' AND '1'='2": empty}
    calls = {"n": 0}

    def send(value):
        if value == "1' AND '1'='2":
            calls["n"] += 1
            return empty if calls["n"] == 1 else normal     # second FALSE looks normal (noise)
        return seq.get(value, normal)
    assert do.witness_sqli_boolean(send) is None


# ---- error-based SQLi ----

def test_sqli_error_signature():
    send = Fake({"1'": Resp(500, "You have an error in your SQL syntax near ''")}, Resp(200, "ok"))
    got = do.witness_sqli_error(send)
    assert got and got["class"] == "sqli"


def test_sqli_error_silent_without_signature():
    send = Fake({"1'": Resp(200, "welcome back")}, Resp(200, "ok"))
    assert do.witness_sqli_error(send) is None


# ---- blind timing ----

def test_timing_fires_when_sleep_delays():
    base = Resp(200, "ok", elapsed_s=0.1)
    slow = Resp(200, "ok", elapsed_s=6.0)
    send = Fake({"1": base}, slow)                  # every sleep payload is slow (and its repeat)
    got = do.witness_timing(send)
    assert got and got["cwe"] == "CWE-89"


def test_timing_silent_when_baseline_slow():
    slow_base = Resp(200, "ok", elapsed_s=5.0)      # unreliable baseline -> refuse to judge
    send = Fake({"1": slow_base}, Resp(200, "ok", elapsed_s=6.0))
    assert do.witness_timing(send) is None


def test_timing_silent_when_no_delay():
    send = Fake({"1": Resp(200, "ok", elapsed_s=0.1)}, Resp(200, "ok", elapsed_s=0.2))
    assert do.witness_timing(send) is None


def test_timing_cmd_variant_labels_cwe78():
    base = Resp(200, "ok", elapsed_s=0.1)
    send = Fake({"1": base}, Resp(200, "ok", elapsed_s=6.0))
    got = do.witness_timing(send, cls="cmd", cwe="CWE-78")
    assert got and got["cwe"] == "CWE-78"


# ---- open redirect ----

def test_open_redirect_fires_on_offsite_location():
    send = Fake({"https://wave.invalid/": Resp(302, "", {"Location": "https://wave.invalid/"})},
                Resp(200, "home"))
    got = do.witness_open_redirect(send)
    assert got and got["cwe"] == "CWE-601"


def test_open_redirect_silent_on_200():
    send = Fake({"https://wave.invalid/": Resp(200, "ignored the param")}, Resp(200, "home"))
    assert do.witness_open_redirect(send) is None


def test_open_redirect_silent_on_same_origin():
    send = Fake({"https://wave.invalid/": Resp(302, "", {"Location": "/dashboard"})}, Resp(200, "h"))
    assert do.witness_open_redirect(send) is None


# ---- path traversal ----

def test_path_traversal_unix_passwd():
    send = Fake({"../../../../../../etc/passwd": Resp(200, "root:x:0:0:root:/root:/bin/bash\n")},
                Resp(404, "not found"))
    got = do.witness_path_traversal(send)
    assert got and got["cwe"] == "CWE-22"


def test_path_traversal_silent_without_signature():
    send = Fake({}, Resp(404, "not found"))
    assert do.witness_path_traversal(send) is None


# ---- XSS reflection gate (no browser needed for the negative path) ----

def test_xss_silent_when_not_reflected():
    send = Fake({}, Resp(200, "your input was sanitized &lt;img&gt;"))   # encoded -> not reflected raw
    assert do.witness_xss(send, url_for=lambda v: "http://t/x") is None


# ---- dispatch ----

def test_witness_dispatch_sqli_prefers_error_then_boolean():
    send = Fake({"1'": Resp(500, "SQLSTATE[42000]: syntax error")}, Resp(200, "ok"))
    got = do.witness("sqli", send)
    assert got and got["class"] == "sqli"


def test_witness_deferred_class_returns_none():
    send = Fake({}, Resp(200, "ok"))
    assert do.witness("deser", send) is None
    assert "deser" in do.DEFERRED


def test_witness_unknown_class_returns_none():
    send = Fake({}, Resp(200, "ok"))
    assert do.witness("totally-made-up", send) is None


# ---- OUT-OF-BAND (OAST) witnesses: ssrf + blind rce ----

import re as _re


class FakeCanary:
    """Stands in for oast.Canary: a `send` that forwards the canary URL marks that token as called back
    (a vulnerable server), so hit() reports it. vulnerable=False never calls back."""
    def __init__(self, vulnerable=True, host="host.docker.internal"):
        self.vulnerable, self.host, self._hits, self._n = vulnerable, host, {}, 0

    def new_token(self):
        self._n += 1
        return f"wz{self._n}"

    def url(self, token, host=None):
        return f"http://{host or self.host}:9999/{token}"

    def hit(self, token, wait=4.0):
        return self._hits.get(token)

    def make_send(self):
        def send(value):
            if self.vulnerable:
                m = _re.search(r"wz\d+", str(value))
                if m and f"http://" in str(value):
                    self._hits[m.group(0)] = [{"path": "/" + m.group(0)}]
            return Resp(200, "ok")
        return send


def test_ssrf_fires_on_callback():
    c = FakeCanary(vulnerable=True)
    got = do.witness_ssrf(c.make_send(), canary=c)
    assert got and got["cwe"] == "CWE-918" and got["oracle"] == "oast"


def test_ssrf_silent_without_callback():
    c = FakeCanary(vulnerable=False)
    assert do.witness_ssrf(c.make_send(), canary=c) is None


def test_ssrf_silent_without_canary():
    assert do.witness_ssrf(lambda v: Resp(200, "ok"), canary=None) is None


def test_blind_rce_fires_on_callback():
    c = FakeCanary(vulnerable=True)
    got = do.witness_blind_rce(c.make_send(), canary=c)
    assert got and got["cwe"] == "CWE-78" and got["oracle"] == "oast"


def test_blind_rce_silent_without_canary():
    assert do.witness_blind_rce(lambda v: Resp(200, "ok"), canary=None) is None


def test_dispatch_ssrf_uses_canary():
    c = FakeCanary(vulnerable=True)
    assert do.witness("ssrf", c.make_send(), canary=c) is not None
    assert do.witness("ssrf", lambda v: Resp(200, "x"), canary=None) is None
    assert "ssrf" not in do.DEFERRED                     # ssrf is now an active (OAST) class


def test_dispatch_cmd_blind_rce_before_timing():
    c = FakeCanary(vulnerable=True)
    # with a canary, the OAST blind-rce witness fires without needing the slow timing probe
    assert do.witness("cmd", c.make_send(), canary=c, timing=False)["oracle"] == "oast"


# ---- SSTI / eval (arithmetic reflection) ----

_PRODUCT = str(73819 * 91193)                    # 6731776067 -- the evaluated result the oracle looks for


def test_ssti_fires_when_expression_evaluated():
    # baseline shows no product; any template payload comes back with the PRODUCT -> engine evaluated it
    send = Fake({"wv73819": Resp(200, "home page")}, Resp(200, f"result is {_PRODUCT} ok"))
    got = do.witness_ssti(send)
    assert got and got["cwe"] == "CWE-1336"


def test_ssti_silent_when_expression_only_reflected():
    # the raw expression is echoed but never evaluated -> product absent -> not SSTI
    send = Fake({}, Resp(200, "you searched for {{73819*91193}}"))
    assert do.witness_ssti(send) is None


def test_eval_fires_on_product():
    send = Fake({"wv73819": Resp(200, "ok")}, Resp(200, f"={_PRODUCT}"))
    got = do.witness_eval(send)
    assert got and got["cwe"] == "CWE-94"


def test_arith_silent_when_product_already_present():
    # if the baseline already contains the product, we can't attribute it -> no witness (no false positive)
    send = Fake({}, Resp(200, f"lucky number {_PRODUCT}"))
    assert do.witness_ssti(send) is None


# ---- NoSQLi (error-based + operator differential) ----

class FakeOp:
    """A `op_send(obj)` stub keyed on the JSON of the operator object."""
    def __init__(self, mapping, default):
        import json
        self._json = json
        self.mapping, self.default = mapping, default

    def __call__(self, obj):
        return self.mapping.get(self._json.dumps(obj, sort_keys=True), self.default)


def test_nosqli_error_based():
    send = Fake({'\'"\\{': Resp(500, "MongoError: unexpected token")}, Resp(200, "ok"))
    got = do.witness_nosqli(send)
    assert got and got["cwe"] == "CWE-943"


def test_nosqli_operator_differential_fires():
    import json
    miss = "waveNoSuchValue_x8z"
    broad = Resp(200, "user records " * 60)
    empty = Resp(200, "none")
    op = FakeOp({json.dumps({"$ne": miss}, sort_keys=True): broad,
                 json.dumps({"$eq": miss}, sort_keys=True): empty,
                 json.dumps(miss): empty}, empty)
    send = Fake({}, Resp(200, "ok"))                 # no error signature -> falls through to op differential
    got = do.witness_nosqli(send, op_send=op)
    assert got and got["cwe"] == "CWE-943"


def test_nosqli_silent_when_param_not_in_query():
    # a non-injectable param: the operator object is coerced to a string -> every response identical
    same = Resp(200, "static " * 30)
    op = FakeOp({}, same)
    send = Fake({}, Resp(200, "ok"))
    assert do.witness_nosqli(send, op_send=op) is None


def test_nosqli_silent_without_op_send_and_no_error():
    send = Fake({}, Resp(200, "ok"))
    assert do.witness_nosqli(send, op_send=None) is None


def test_new_classes_not_deferred():
    for c in ("ssti", "eval", "nosqli"):
        assert c not in do.DEFERRED
    assert do.DEFERRED == {"deser"}                  # the one class with no sound black-box witness
