"""Diagnostic transcript log: on by default, records EVERY verdict with the runtime image the sandbox
launched + the command/result trail -- so a believed/blocked lead is explainable without the live stdout
(the Bun-witness diagnostic blind spot). Distinct from traces.py (opt-in, verified-only training data)."""
import json

from agent.orchestrator import transcript_log


def _read(d):
    return [json.loads(l) for l in (d / "wave_transcripts.jsonl").read_text(encoding="utf-8").splitlines()]


def test_enabled_by_default_and_toggle(monkeypatch):
    monkeypatch.delenv("WAVE_NO_TRANSCRIPT", raising=False)
    assert transcript_log.enabled() is True
    monkeypatch.setenv("WAVE_NO_TRANSCRIPT", "1")
    assert transcript_log.enabled() is False


def test_saves_image_and_trail_for_a_believed_lead(tmp_path, monkeypatch):
    monkeypatch.delenv("WAVE_NO_TRANSCRIPT", raising=False)
    trail = [("cd /work && grep -n shell server.ts", "exit 0\n1434: shell(...)"),
             ("bun /work/.wave_repro.mjs '; id'", "WAVE_RESULT: ...")]
    transcript_log.save(tmp_path, file="server.ts", line=1434, cls="cmd", cwe="CWE-78",
                        verdict="believed", image="oven/bun:1", oracle="investigate (9 run(s), call)",
                        ran=9, mode="call", trail=trail)
    (rec,) = _read(tmp_path)
    assert rec["image"] == "oven/bun:1" and rec["verdict"] == "believed" and rec["ran"] == 9
    assert [s["cmd"] for s in rec["steps"]] == [c for c, _ in trail]   # the exact command trail is captured
    assert "bun /work/.wave_repro.mjs" in rec["steps"][1]["cmd"]       # answers "did bun run?"


def test_blocked_verdict_is_recorded_too(tmp_path, monkeypatch):
    monkeypatch.delenv("WAVE_NO_TRANSCRIPT", raising=False)
    transcript_log.save(tmp_path, file="x.ts", line=1, cls="cmd", cwe="CWE-78", verdict="blocked",
                        image=None, oracle="runtime unavailable", ran=0, mode="call", trail=[])
    (rec,) = _read(tmp_path)
    assert rec["verdict"] == "blocked" and rec["image"] is None and rec["steps"] == []


def test_disabled_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("WAVE_NO_TRANSCRIPT", "1")
    transcript_log.save(tmp_path, file="x.ts", line=1, cls="cmd", cwe="CWE-78", verdict="believed",
                        image="oven/bun:1", oracle="", ran=1, mode="call", trail=[("ls", "ok")])
    assert not (tmp_path / "wave_transcripts.jsonl").exists()


def test_result_output_is_truncated(tmp_path, monkeypatch):
    monkeypatch.delenv("WAVE_NO_TRANSCRIPT", raising=False)
    transcript_log.save(tmp_path, file="x.ts", line=1, cls="cmd", cwe="CWE-78", verdict="believed",
                        image="oven/bun:1", oracle="", ran=1, mode="call",
                        trail=[("cat big", "A" * 5000)])
    (rec,) = _read(tmp_path)
    assert len(rec["steps"][0]["result"]) == transcript_log._MAX_RESULT


def test_append_across_candidates(tmp_path, monkeypatch):
    monkeypatch.delenv("WAVE_NO_TRANSCRIPT", raising=False)
    for ln in (10, 20):
        transcript_log.save(tmp_path, file="x.ts", line=ln, cls="cmd", cwe="CWE-78", verdict="believed",
                            image="oven/bun:1", oracle="", ran=1, mode="call", trail=[("ls", "ok")])
    assert [r["line"] for r in _read(tmp_path)] == [10, 20]
