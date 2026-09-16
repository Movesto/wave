"""Tests for the distillation data-prep (agent/train/prepare_traces) -- deterministic, no model/GPU."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.train import prepare_traces as pt


def _drive(system=True, assistant=True, extra=0):
    msgs = []
    if system:
        msgs.append({"role": "system", "content": "you are an investigator"})
    msgs.append({"role": "user", "content": "brief"})
    if assistant:
        msgs.append({"role": "assistant", "content": "", "tool_calls": [{"id": "1", "function": {"name": "run_command", "arguments": {"command": "python3 x.py"}}}]})
        msgs.append({"role": "tool", "tool_call_id": "1", "name": "run_command", "content": "uid=0"})
    for _ in range(extra):
        msgs.append({"role": "assistant", "content": "thinking"})
    return msgs


def _rec(rid, label, verdict, file="a.py", cwe="CWE-78", cls="cmd", messages=None):
    return {"id": rid, "label": label, "verdict": verdict, "file": file, "cwe": cwe, "class": cls,
            "proof_mode": "call", "model": "deepseek", "messages": messages if messages is not None else _drive()}


def test_clean_messages_keeps_valid_drive():
    out = pt._clean_messages(_drive())
    assert out and out[0]["role"] == "system" and any("tool_calls" in m for m in out)


def test_clean_messages_rejects_no_system_or_too_short():
    assert pt._clean_messages(_drive(system=False)) is None
    assert pt._clean_messages([{"role": "user", "content": "hi"}]) is None
    assert pt._clean_messages("not a list") is None


def test_prepare_dedups_splits_and_reports(tmp_path):
    recs = [_rec("t:a.py:1:cmd", "positive", "confirmed"),
            _rec("t:a.py:1:cmd", "positive", "confirmed"),          # dup id -> collapsed
            _rec("t:b.py:2:path", "negative", "refuted", file="b.py", cwe="CWE-22", cls="path"),
            _rec("t:c.rs:3:cmd", "negative", "refuted", file="c.rs"),
            _rec("t:d.py:4:authz", "review", "anomalous_state", file="d.py", cwe="CWE-639", cls="authz")]
    src = tmp_path / "wave_traces.jsonl"
    src.write_text("\n".join(json.dumps(r) for r in recs), encoding="utf-8")
    out = tmp_path / "sft"
    rep = pt.prepare(str(src), str(out), eval_frac=0.5, seed=0)
    assert rep["raw"] == 5 and rep["deduped"] == 4 and rep["usable"] == 4     # one dup removed
    assert rep["overall"]["by_label"] == {"positive": 1, "negative": 2, "review": 1}
    assert rep["overall"]["by_lang"].get("rust") == 1
    assert (out / "train.jsonl").exists() and (out / "eval.jsonl").exists()
    # every emitted record is a valid chat example
    for name in ("train.jsonl", "eval.jsonl"):
        for line in (out / name).read_text(encoding="utf-8").splitlines():
            e = json.loads(line)
            assert e["messages"][0]["role"] == "system" and "label" in e["meta"]


def test_prepare_drops_unusable(tmp_path):
    recs = [_rec("t:a:1:cmd", "positive", "confirmed"),
            _rec("t:b:2:cmd", "negative", "refuted", messages=[{"role": "user", "content": "no system"}])]
    src = tmp_path / "wave_traces.jsonl"
    src.write_text("\n".join(json.dumps(r) for r in recs), encoding="utf-8")
    rep = pt.prepare(str(src), str(tmp_path / "sft"), eval_frac=0.0, seed=0)
    assert rep["usable"] == 1 and rep["dropped_unusable"] == 1


from agent.train import validate_dataset as vd


def _ex(messages, rid="t:a:1"):
    return {"messages": messages, "meta": {"id": rid}}


def test_validate_clean_example():
    e = _ex([{"role": "system", "content": "s"}, {"role": "user", "content": "u"},
             {"role": "assistant", "content": "", "tool_calls": [{"id": "1", "function": {"name": "run_command", "arguments": {}}}]},
             {"role": "tool", "tool_call_id": "1", "name": "run_command", "content": "uid=0"},
             {"role": "assistant", "content": "confirmed"}])
    assert vd.check_example(e) == []


def test_validate_catches_empty_assistant_and_orphan_tool():
    e = _ex([{"role": "system", "content": "s"}, {"role": "user", "content": "u"},
             {"role": "assistant", "content": ""},                                  # empty turn
             {"role": "tool", "tool_call_id": "99", "content": "x"}])                # orphan tool (no name, no call)
    probs = vd.check_example(e)
    assert any("empty assistant" in p for p in probs) and any("not linked" in p for p in probs)


def test_validate_flags_overlong():
    big = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"},
           {"role": "assistant", "content": "x" * 80000}]
    assert any("truncate" in p for p in vd.check_example(_ex(big), max_tokens=8000))


def test_validate_run_on_prepared(tmp_path):
    p = tmp_path / "train.jsonl"
    p.write_text(json.dumps(_ex([{"role": "system", "content": "s"}, {"role": "user", "content": "u"},
                                 {"role": "assistant", "content": "done"}])) + "\n", encoding="utf-8")
    r = vd.validate(str(p))
    assert r["total"] == 1 and r["bad"] == 0 and r["pass_rate"] == 1.0
