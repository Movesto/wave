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
    assert "~/.wave/config" in shell._HELP_SETUP


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
    answers = iter([True, False, False, False])          # authorize yes, synth-auth no, timing no, stored no
    monkeypatch.setattr(shell, "_confirm", lambda prompt: next(answers))
    monkeypatch.setattr(shell, "_ask", lambda *a, **k: "")
    shell._cmd_dast("http://t")
    assert "--no-auth" in calls[0] and "--timing" not in calls[0] and "--stored" not in calls[0]


def test_sast_discover_argv(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(shell, "_ask", lambda prompt, default="": "1" if "1/2/3" in prompt else "./repo")
    shell._cmd_sast("")
    assert calls == [["discover", "./repo"]]


def test_sast_full_with_patch(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(shell, "_ask", lambda prompt, default="": "3" if "1/2/3" in prompt else "./repo")
    monkeypatch.setattr(shell, "_confirm", lambda prompt: True)       # confirm the model run
    shell._cmd_sast("")
    assert calls == [["all", "./repo", "--patch"]]


def test_setup_writes_each_field(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(shell, "_ask", lambda prompt, default="": "http://api" if "base" in prompt else "m1")
    monkeypatch.setattr("getpass.getpass", lambda *a, **k: "secretkey")
    monkeypatch.setattr(shell, "_load_config_noop", None, raising=False)
    # _cmd_setup also calls run._load_config(); stub it so no real file is read
    import agent.orchestrator.run as runmod
    monkeypatch.setattr(runmod, "_load_config", lambda: None)
    shell._cmd_setup("")
    kinds = [argv[2] for argv in calls]                              # config set <kind> <value>
    assert "base" in kinds and "model" in kinds and "key" in kinds


def test_ready_reflects_env(monkeypatch):
    monkeypatch.setattr(shell, "_config_view", lambda: {})
    monkeypatch.setenv("WAVE_API_BASE", "http://api")
    monkeypatch.setenv("WAVE_MODEL", "m1")
    ready, info = shell._ready()
    assert ready and info == "m1"
