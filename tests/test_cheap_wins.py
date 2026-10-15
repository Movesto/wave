"""Cheap recall/noise wins (remaining-work 5):
  (a) model.py flags a truncated/empty reply (finish_reason 'length' / empty body) and RETRIES with a
      bigger budget, instead of silently returning nothing (the notebook whiff + silent detector refute).
  (b) _audit_confirm skips the near-coin-flip second-model judge on TIER-3 'judgment' classes and routes
      them straight to human review.
"""
import types

import pytest

from agent.orchestrator import model as model_mod
from agent.orchestrator import prove


# --- (a) incomplete-reply detection + retry ----------------------------------------------------------
def test_has_usable_and_call_incomplete():
    assert model_mod._has_usable({"content": "hi"}) is True
    assert model_mod._has_usable({"reasoning": "thinking..."}) is True
    assert model_mod._has_usable({"tool_calls": [{"id": "x"}]}) is True
    assert model_mod._has_usable({"content": "   "}) is False
    assert model_mod._has_usable({}) is False
    # a 'length' truncation with nothing usable must be flagged for retry
    assert model_mod._call_incomplete({"content": ""}, "length") is True
    assert model_mod._call_incomplete({}, "stop") is True                 # empty body, however it stopped
    # a truncation that still carries partial content is salvageable -> NOT flagged
    assert model_mod._call_incomplete({"content": "partial..."}, "length") is False
    # a tool-call reply with empty content is complete, not a whiff
    assert model_mod._call_incomplete({"tool_calls": [{"id": "x"}]}, "tool_calls") is False
    # a normal complete reply
    assert model_mod._call_incomplete({"content": "done"}, "stop") is False
    # a DELIBERATE tiny-budget probe (e.g. a 1-token connectivity/credits check) is NOT a whiff -> never
    # retried (retrying 2x a tiny number can't help -- it wasted probe calls before the budget guard)
    assert model_mod._call_incomplete({"content": ""}, "length", budget=1) is False
    assert model_mod._call_incomplete({}, "length", budget=1) is False
    # a real content budget still flags an empty/length whiff for retry
    assert model_mod._call_incomplete({"content": ""}, "length", budget=2000) is True


class _FakeResp:
    def __init__(self, payload):
        self._p = payload
        self.status_code = 200
        self.reason = "OK"

    def raise_for_status(self):
        pass

    def json(self):
        return self._p


def test_api_chat_retries_truncated_then_returns_complete(monkeypatch):
    m = model_mod.Model(model_id="x", api_base="https://api.test/v1", api_key="k")
    posts = []
    replies = [
        {"choices": [{"message": {"content": ""}, "finish_reason": "length"}]},   # whiff -> must retry
        {"choices": [{"message": {"content": "the real answer"}, "finish_reason": "stop"}]},
    ]

    def fake_post(url, **kw):
        posts.append(dict(kw.get("json") or {}))            # snapshot (the body dict is mutated in place)
        return _FakeResp(replies[len(posts) - 1])

    import requests
    monkeypatch.setattr(requests, "post", fake_post)
    msg = m._api_chat([{"role": "user", "content": "hi"}], max_tokens=2000)
    assert msg["content"] == "the real answer"
    assert len(posts) == 2                                   # it retried once
    assert posts[0]["max_tokens"] == 2000 and posts[1]["max_tokens"] == 4000   # budget bumped on retry
    assert m.last_finish_reason == "stop"


def test_api_chat_does_not_retry_a_tiny_budget_probe(monkeypatch):
    # a 1-token connectivity/credits probe ALWAYS comes back finish='length' with ~nothing; the old retry
    # logic burned two extra probe calls on it (caught on the nv run). The budget floor stops that.
    m = model_mod.Model(model_id="x", api_base="https://api.test/v1", api_key="k")
    posts = []

    def fake_post(url, **kw):
        posts.append(dict(kw.get("json") or {}))
        return _FakeResp({"choices": [{"message": {"content": ""}, "finish_reason": "length"}]})

    import requests
    monkeypatch.setattr(requests, "post", fake_post)
    m._api_chat([{"role": "user", "content": "ping"}], max_tokens=1)
    assert len(posts) == 1                                   # consumed as-is, no wasted retries


# --- (b) skip the judge on weak (TIER-3 judgment) classes --------------------------------------------
def _c():
    return types.SimpleNamespace(cwe="CWE-639", file="app.py", loc=lambda: "app.py:1", family="idor")


def test_audit_skips_judge_on_judgment_class_routes_to_human_review(monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr("agent.orchestrator.audit.audit",
                        lambda *a, **k: (called.__setitem__("n", called["n"] + 1), ("confirmed", "x"))[1])
    rec = {"verdict": "confirmed", "oracle_tier": "judgment", "harness_witnessed": False, "why": "base"}
    prove._audit_confirm(rec, _c(), auditor=None)
    assert rec["verdict"] == "anomalous_state"               # no tripwire -> human review, not a coin-flip confirm
    assert "weak-judge" in rec["audit"]
    assert called["n"] == 0                                   # the second model was NOT called


def test_audit_still_runs_second_model_on_gradable_no_marker_class(monkeypatch):
    seen = {"n": 0}

    def fake_audit(auditor, c, rec):
        seen["n"] += 1
        return ("anomalous_state", "2nd model downgraded")
    monkeypatch.setattr("agent.orchestrator.audit.audit", fake_audit)
    rec = {"verdict": "confirmed", "oracle_tier": "marker", "harness_witnessed": False, "why": "base"}
    prove._audit_confirm(rec, _c(), auditor=object())
    assert seen["n"] == 1                                     # gradable class still gets the 2nd-model audit
    assert rec["verdict"] == "anomalous_state"


def test_audit_harness_witnessed_needs_no_model(monkeypatch):
    monkeypatch.setattr("agent.orchestrator.audit.audit",
                        lambda *a, **k: pytest.fail("must not audit a tape-witnessed confirm"))
    rec = {"verdict": "confirmed", "harness_witnessed": True, "harness_marker": "WAVE-SINK-SQL",
           "oracle_tier": "marker", "why": "base"}
    prove._audit_confirm(rec, _c(), auditor=object())
    assert rec["verdict"] == "confirmed" and "[harness]" in rec["audit"]
