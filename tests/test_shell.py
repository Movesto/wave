"""Interactive shell regression (shell.py) -- the PURE/dispatch parts. No real input, config, or network:
the interactive primitives (_ask/_confirm) and the CLI bridge (_run_cli) are monkeypatched, so a test
never writes ~/.wave/config or sends traffic.

Run: pytest tests/test_shell.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.orchestrator import shell


def _capture(monkeypatch):
    calls = []
    monkeypatch.setattr(shell, "_run_cli", lambda argv: calls.append(argv))
    return calls


def test_dispatch_has_core_commands():
    for c in ("/help", "/setup", "/env", "/config", "/status", "/sast", "/dast", "/both", "/exit"):
        assert c in shell._DISPATCH


def test_help_topics_render():
    assert "commands" in shell._HELP_MAIN
    assert "black-box" in shell._HELP_DAST and "--authorized" in shell._HELP_DAST
    assert "eyes -> detect -> prove" in shell._HELP_SAST
    assert ".env" in shell._HELP_SETUP and "WAVE_AUDIT_MODEL" in shell._HELP_SETUP


def test_exit_returns_sentinel():
    assert shell._cmd_exit("") == "EXIT"


def test_dast_refuses_without_authorization(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(shell, "_confirm", lambda prompt: False)      # user declines the authorization prompt
    shell._cmd_dast("http://localhost:8080")
    assert calls == []                                               # nothing runs


def test_dast_builds_authorized_argv(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(shell, "_confirm", lambda prompt: True)       # authorize + auth-synth + timing
    monkeypatch.setattr(shell, "_ask", lambda *a, **k: "")            # no seed
    shell._cmd_dast("http://localhost:8080")
    assert len(calls) == 1
    argv = calls[0]
    assert argv[:3] == ["dast", "http://localhost:8080", "--authorized"]
    assert "--timing" in argv and "--no-auth" not in argv            # confirm=True => synth auth kept


def test_dast_adds_no_auth_when_declined(monkeypatch):
    calls = _capture(monkeypatch)
    answers = iter([True, False, False, False, False])   # authorize, synth-auth no, timing no, stored no, model no
    monkeypatch.setattr(shell, "_confirm", lambda prompt: next(answers))
    monkeypatch.setattr(shell, "_ask", lambda *a, **k: "")
    shell._cmd_dast("http://t")
    assert "--no-auth" in calls[0] and "--timing" not in calls[0] and "--stored" not in calls[0]
    assert "--model" not in calls[0]


def test_sast_discover_argv(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(shell, "_ask", lambda prompt, default="": "1" if "1/2/3" in prompt else "./repo")
    shell._cmd_sast("")
    assert calls == [["discover", "./repo"]]


def test_sast_all_files_no_patch(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(shell, "_ask", lambda prompt, default="": "3" if "choose" in prompt else "./repo")
    monkeypatch.setattr(shell, "_confirm", lambda prompt: True)       # yes to online + run-now
    shell._cmd_sast("")
    assert calls == [["all", "./repo", "--all-files", "--online"]]    # depth 3 = full all-files, NO patch
    assert "--patch" not in calls[0]


def test_sast_full_with_patch(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(shell, "_ask", lambda prompt, default="": "4" if "choose" in prompt else "./repo")
    monkeypatch.setattr(shell, "_confirm", lambda prompt: True)       # yes to online + run-now
    shell._cmd_sast("")
    assert calls == [["all", "./repo", "--patch", "--online"]]        # depth 4 = patch


def test_sast_quick_runs_eyes_detect_deps_no_docker(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(shell, "_ask", lambda prompt, default="": "5" if "choose" in prompt else "./repo")
    shell._cmd_sast("")
    assert calls == [["eyes", "./repo", "--notes"], ["detect", "./repo"], ["deps", "./repo"]]


def test_sast_full_without_online(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(shell, "_ask", lambda prompt, default="": "2" if "1/2/3" in prompt else "./repo")
    answers = iter([False, True])                                    # no to online, yes to run-now
    monkeypatch.setattr(shell, "_confirm", lambda prompt: next(answers))
    shell._cmd_sast("")
    assert calls == [["all", "./repo"]]


def test_setup_writes_env_with_both_models(monkeypatch):
    captured = {}
    monkeypatch.setattr(shell, "_write_env", lambda updates: captured.update(updates) or "/tmp/.env")

    def ask(prompt, default=""):
        if "base URL" in prompt:
            return "http://api"
        if prompt.startswith("FIRST"):
            return "primary-model"
        if prompt.startswith("SECOND"):
            return "auditor-model"
        return default
    monkeypatch.setattr(shell, "_ask", ask)
    monkeypatch.setattr("getpass.getpass", lambda *a, **k: "secretkey")
    monkeypatch.setattr(shell.os, "environ", {})                     # isolate from the real env
    shell._cmd_setup("")
    assert captured["WAVE_API_BASE"] == "http://api"
    assert captured["WAVE_MODEL"] == "primary-model"
    assert captured["WAVE_AUDIT_MODEL"] == "auditor-model"           # the SECOND model is now captured
    assert captured["WAVE_API_KEY"] == "secretkey"


def test_ready_reflects_env(monkeypatch):
    monkeypatch.setattr(shell, "_config_view", lambda: {})
    monkeypatch.setenv("WAVE_API_BASE", "http://api")
    monkeypatch.setenv("WAVE_MODEL", "m1")
    ready, info = shell._ready()
    assert ready and info == "m1"
