"""Model-driven-payload regression (dast_model.py). The MODEL is stubbed; the proof detectors are pure.
No network, no real model, no browser.

Run: pytest tests/test_dast_model.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.orchestrator import dast_model as dm
from agent.orchestrator.dast_oracle import Resp


# ---------- parse_probes ----------

def test_parse_probes_plain_and_fenced():
    assert dm.parse_probes('[{"class":"sqli","payload":"1\' OR 1=1"}]')[0]["class"] == "sqli"
    fenced = "thinking...\n```json\n[{\"class\":\"xss\",\"payload\":\"<x>\"}]\n```"
    out = dm.parse_probes(fenced)
    assert out and out[0]["payload"] == "<x>"


def test_parse_probes_after_think_and_junk():
    assert dm.parse_probes("<think>noise [not json]</think> [{\"class\":\"ssti\",\"payload\":\"${7*7}\"}]")
    assert dm.parse_probes("no json here") == []
    assert dm.parse_probes("[not, valid, json") == []


# ---------- prove_response ----------

def _r(body, status=200):
    return Resp(status, body)


def test_prove_sqli_error_new_signature():
    base = _r("welcome")
    poc = dm.prove_response({"class": "sqli", "payload": "x'"}, _r("You have an error in your SQL syntax", 500), base)
    assert poc and poc["cwe"] == "CWE-89" and poc["oracle"] == "model-driven"


def test_prove_sqli_error_ignored_if_in_baseline():
    base = _r("sql syntax help page")                 # the signature is already on the normal page
    assert dm.prove_response({"class": "sqli", "payload": "x'"}, _r("sql syntax help page"), base) is None


def test_prove_path_signature():
    poc = dm.prove_response({"class": "path", "payload": "../etc/passwd"}, _r("root:x:0:0:root:/root"), _r("nope"))
    assert poc and poc["cwe"] == "CWE-22"


def test_prove_computed_value_reflection():
    # expect appears in the response, not in the baseline, and NOT a literal in the payload -> evaluated
    poc = dm.prove_response({"class": "ssti", "payload": "${7919*1234}"}, _r("result 9772046"), _r("home"),
                            expect="9772046")
    assert poc and poc["cwe"] == "CWE-1336"


def test_prove_computed_value_rejects_literal_in_payload():
    # the number is just echoed from the payload (reflection, not evaluation) -> not proven
    assert dm.prove_response({"class": "ssti", "payload": "9772046"}, _r("you said 9772046"), _r("home"),
                             expect="9772046") is None


def test_prove_nothing():
    assert dm.prove_response({"class": "sqli", "payload": "x"}, _r("normal page"), _r("normal page")) is None


# ---------- build_prompt ----------

def test_build_prompt_carries_context():
    system, user = dm.build_prompt("/u/:id", "path", "id", _r("hi", 200), _r("err", 500),
                                   "http://c/wz1", "wavemARK", 7919, 1234, "9772046")
    assert "wavemARK" in system and "http://c/wz1" in system and "9772046" in system
    assert "/u/:id" in user and "param=id" in user


# ---------- run() with a stubbed model + sender ----------

class _FakeModel:
    def __init__(self, reply):
        self.reply = reply
        self.model_id = "fake"

    def generate(self, system, user, **k):
        return self.reply


class _FakeSender:
    """Returns a canned Resp for each payload (via a function); records what was sent."""
    route, vector, param = "/x", "query", "q"

    def __init__(self, fn):
        self.fn = fn
        self.sent = []

    def send(self, value):
        self.sent.append(value)
        return self.fn(value)

    def url_for(self, value):
        return None


def test_run_confirms_via_error_detector(monkeypatch):
    reply = '[{"class":"sqli","payload":"1\\" OR \\"1\\"=\\"1"}]'
    model = _FakeModel(reply)

    def resp(value):
        return Resp(500, "ORA-00933: SQL command not properly ended") if '"' in value else Resp(200, "ok")
    sender = _FakeSender(resp)
    base, probe = Resp(200, "ok"), Resp(200, "ok")
    poc = dm.run(model, sender, base, probe, canary=None, headers={})
    assert poc and poc["cwe"] == "CWE-89" and poc["oracle"] == "model-driven"


def test_run_returns_none_when_nothing_fires():
    model = _FakeModel('[{"class":"sqli","payload":"1 or 1"}]')
    sender = _FakeSender(lambda v: Resp(200, "same boring page"))
    poc = dm.run(model, sender, Resp(200, "same boring page"), Resp(200, "same boring page"))
    assert poc is None


def test_run_survives_model_error():
    class Boom:
        model_id = "x"
        def generate(self, *a, **k): raise RuntimeError("endpoint down")
    assert dm.run(Boom(), _FakeSender(lambda v: Resp(200, "x")), Resp(200, "x"), Resp(200, "x")) is None
