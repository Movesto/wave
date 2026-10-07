"""The interactive `wave` shell -- a Claude-Code-style REPL.

Typing `wave` with no subcommand drops the user into this shell: a banner, a readiness line, and a
slash-command prompt. From here they configure the model/endpoint (/setup), pick a mode (/sast, /dast,
/both), and read feature help (/help <topic>) -- the same guided flow a real CLI offers, on top of the
one-shot `wave <cmd> ...` interface which still works unchanged for scripting.

Everything routes back through run.main([...]) so there is ONE source of truth for arguments, defaults,
and handlers -- the shell just assembles argv from an interactive flow. Live/active actions (SAST loads
a model; DAST sends attack traffic) are confirmed here before they run; DAST additionally passes
--authorized only after the operator affirms permission for the target.
"""
from __future__ import annotations

import os
import sys

# -------- styling (ANSI, auto-disabled when not a TTY or NO_COLOR is set) --------------------------
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code):
    return (lambda s: f"\033[{code}m{s}\033[0m") if _USE_COLOR else (lambda s: s)


BOLD, DIM, CYAN, GREEN, RED, YEL, MAG = (_c("1"), _c("2"), _c("36"), _c("32"), _c("31"), _c("33"), _c("35"))

_BANNER = r"""
  ___       ___   __   ___
 | | |  /\  \  / |_   |__   wave
 |_|_| /--\  \/  |__  |___  local autonomous vuln-discovery & repair
"""

_ALIAS = {"model": "WAVE_MODEL", "base": "WAVE_API_BASE", "key": "WAVE_API_KEY"}


# -------- small interactive primitives (patchable in tests) ----------------------------------------

def _ask(prompt, default=""):
    try:
        v = input(f"  {prompt}" + (f" [{default}]" if default else "") + ": ").strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return v or default


def _confirm(prompt):
    try:
        return input(f"  {prompt} (yes/no): ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def _run_cli(argv):
    """Dispatch back through the real CLI, catching SystemExit so an argparse/handler exit (or the DAST
    authorization gate) never kills the REPL."""
    from .run import main as run_main
    try:
        run_main(argv)
    except SystemExit as e:
        if e.code not in (0, None):
            print(RED(f"  (command exited: {e.code})"))
    except Exception as e:                           # a pipeline error is reported, the shell survives
        print(RED(f"  error: {e}"))


# -------- config / readiness -----------------------------------------------------------------------

def _config_view():
    from .run import _config_path
    cfg, out = _config_path(), {}
    if cfg.is_file():
        for line in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def _ready():
    """(ready, reason) -- a model + endpoint configured (env or ~/.wave/config)? DAST needs neither."""
    have = {**_config_view(), **{k: os.environ[k] for k in os.environ if k.startswith("WAVE_")}}
    if have.get("WAVE_API_BASE") and have.get("WAVE_MODEL"):
        return True, have.get("WAVE_MODEL", "")
    return False, "model/endpoint not set -- run /setup (DAST works without a model)"


def _status_line():
    ready, info = _ready()
    dot = GREEN("●") if ready else YEL("●")
    msg = GREEN(f"model {info}") if ready else YEL(info)
    print(f"  {dot} {msg}")


# -------- command handlers (return 'EXIT' to leave the REPL) ---------------------------------------

def _cmd_help(arg):
    topic = (arg or "").strip().lower().lstrip("/")
    if topic in ("dast",):
        print(_HELP_DAST)
    elif topic in ("sast",):
        print(_HELP_SAST)
    elif topic in ("setup", "env", "config"):
        print(_HELP_SETUP)
    else:
        print(_HELP_MAIN)


def _cmd_setup(arg):
    print(BOLD("\n  Setup -- model + API endpoint (written to ~/.wave/config)\n"))
    cur = _config_view()
    base = _ask("API base URL (OpenAI-compatible)", cur.get("WAVE_API_BASE", "https://openrouter.ai/api/v1"))
    model = _ask("model id", cur.get("WAVE_MODEL", "deepseek/deepseek-r1"))
    import getpass
    try:
        key = getpass.getpass("  API key (hidden, blank keeps current): ").strip()
    except (EOFError, KeyboardInterrupt):
        key = ""
    if base:
        _run_cli(["config", "set", "base", base])
    if model:
        _run_cli(["config", "set", "model", model])
    if key:
        _run_cli(["config", "set", "key", key])
    from .run import _load_config
    _load_config()                                   # reload so /status reflects it immediately
    print(GREEN("  saved.\n"))
    _status_line()


def _cmd_config(arg):
    cfg = _config_view()
    if not cfg:
        print(DIM("  (no config yet -- run /setup)"))
        return
    for k, v in cfg.items():
        print(f"  {k}={'***' if 'KEY' in k else v}")


def _cmd_status(arg):
    _status_line()


def _cmd_sast(arg):
    target = (arg or "").strip() or _ask("target repo path", ".")
    if not target:
        return
    print(BOLD("\n  SAST depth:"))
    print("    1) discover  -- fast static candidates, no model")
    print("    2) all       -- full pipeline (eyes -> detect -> prove), loads the model")
    print("    3) all --patch -- full pipeline + patch & reverify confirmed findings")
    choice = _ask("choose 1/2/3", "1")
    if choice == "1":
        argv = ["discover", target]
    elif choice == "3":
        argv = ["all", target, "--patch"]
    else:
        argv = ["all", target]
    if choice in ("2", "3") and _confirm("this loads the model and may take a while -- run now?") is False:
        print(DIM("  cancelled."))
        return
    print(CYAN(f"\n  > wave {' '.join(argv)}\n"))
    _run_cli(argv)


def _cmd_dast(arg):
    url = (arg or "").strip() or _ask("target base URL", "http://localhost:8080")
    if not url:
        return
    print(YEL("\n  DAST sends live attack traffic (injection payloads, OAST callbacks, brute-force bursts)."))
    if not _confirm(f"Do you OWN or have WRITTEN authorization to actively test {url}?"):
        print(RED("  refused -- only scan systems you are authorized to test."))
        return
    argv = ["dast", url, "--authorized"]
    if not _confirm("synthesize an authenticated session (auth)?"):
        argv.append("--no-auth")
    if _confirm("enable blind time-based probes (slow, more intrusive)?"):
        argv.append("--timing")
    seed = _ask("seed endpoint as 'METHOD route vector param' (blank to skip)")
    if seed:
        argv += ["--target-param", seed]
    print(CYAN(f"\n  > wave {' '.join(argv[:2])} --authorized ...\n"))
    _run_cli(argv)


def _cmd_both(arg):
    print(BOLD("  Running SAST then DAST.\n"))
    _cmd_sast("")
    _cmd_dast("")


def _cmd_clear(arg):
    os.system("cls" if os.name == "nt" else "clear")
    _print_banner()


def _cmd_exit(arg):
    print(DIM("  bye."))
    return "EXIT"


_DISPATCH = {
    "/help": _cmd_help, "/?": _cmd_help,
    "/setup": _cmd_setup, "/env": _cmd_setup,
    "/config": _cmd_config, "/status": _cmd_status,
    "/sast": _cmd_sast, "/dast": _cmd_dast, "/both": _cmd_both,
    "/clear": _cmd_clear, "/exit": _cmd_exit, "/quit": _cmd_exit, "/q": _cmd_exit,
}


def _print_banner():
    print(CYAN(_BANNER))


def run():
    """The REPL. Returns an exit code."""
    _print_banner()
    _status_line()
    print(DIM("  type /help for commands, /setup to configure, /dast or /sast to begin, /exit to leave.\n"))
    while True:
        try:
            line = input(f"{CYAN('wave')}> ").strip()
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print(DIM("\n  (/exit to leave)"))
            continue
        if not line:
            continue
        if not line.startswith("/"):
            print(DIM("  commands start with '/'. Try /help, /dast, /sast."))
            continue
        parts = line.split(maxsplit=1)
        cmd, arg = parts[0].lower(), (parts[1] if len(parts) > 1 else "")
        handler = _DISPATCH.get(cmd)
        if handler is None:
            print(DIM(f"  unknown command {cmd!r} -- /help for the list."))
            continue
        if handler(arg) == "EXIT":
            break
    return 0


# -------- help text --------------------------------------------------------------------------------

_HELP_MAIN = """
  wave -- commands
    /setup, /env     configure model + API endpoint + key (saved to ~/.wave/config)
    /config          show the current configuration
    /status          show readiness (model/endpoint configured?)
    /sast [path]     static analysis of a code repo (discover / full / full+patch)
    /dast [url]      black-box dynamic testing of a LIVE URL (authorization required)
    /both            run SAST then DAST
    /help [topic]    this help, or details: /help sast | /help dast | /help setup
    /clear           clear the screen
    /exit, /quit     leave the shell

  Everything also works one-shot for scripting:  wave <command> ...  (e.g. wave all ./repo)
"""

_HELP_SAST = """
  /sast [path] -- static analysis (needs the source; loads the model for the full pipeline)
    discover       fast, deterministic static candidates (no model)        -> wave discover <path>
    all            eyes -> detect -> prove (clean-room, model-driven)       -> wave all <path>
    all --patch    the above, plus patch & dual-gate reverify confirmations -> wave all <path> --patch
  Findings are written under the repo (wave_results / casefile). SAST owns cross-file taint & repair.
"""

_HELP_DAST = """
  /dast [url] -- black-box dynamic testing of a LIVE URL (red-team view: any angle, no source)
    RECON (network/infra):   DNS + email-spoofing (SPF/DMARC) + subdomain-takeover, TLS cert
                             (expiry/self-signed/mismatch + SANs), port/service exposure scan.
    POSTURE (http):          stack fingerprint, missing security headers, weak cookie flags,
                             CORS misconfig, dangerous methods, sensitive-path discovery
                             (/.git, /.env, /actuator, swagger, admin, backups, ...).
    APP (injection):         sqli, xss (DOM-execution), path, open redirect, SSTI, eval, NoSQLi,
                             SSRF & blind RCE (OAST callback).
    JUDGMENT (differential): IDOR, broken access control, missing rate-limit / old-password
                             (reported as anomalous_state -- observed effect, severity is a judgment).
    SAFETY: active traffic (scans ports, sends payloads) -- only run against systems you own or are
    authorized to test. The command refuses without an authorization affirmation.
    One-shot:  wave dast <url> --authorized [--no-auth] [--timing] [--no-recon] [--no-ports]
                              [--target-param "METHOD route vector param"] [--identities N] [--out f]
"""

_HELP_SETUP = """
  /setup (alias /env) -- configure the model + API endpoint
    Prompts for the API base URL (OpenAI-compatible), the model id, and the API key (hidden).
    Saved to ~/.wave/config so future runs need no env vars. View with /config; one-shot:
      wave config set base <url> | wave config set model <id> | wave config set key <key>
    DAST needs no model; SAST's full pipeline does.
"""
