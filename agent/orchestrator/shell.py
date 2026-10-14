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


def _model_jobs(n=4):
    """How many files the model stages (notebook/detect/prove) should read CONCURRENTLY from the shell.
    A CLOUD model is safe to call in parallel -> n (the interactive serial notebook was ~2 min/file, so a
    40-file read took ~80 min); a LOCAL single-GPU model must stay serial -> 1 (the stages enforce this too,
    so passing n is harmless either way -- this just avoids the "reading serially" notice for local users).
    n=4 is the documented sweet spot for a ~32GB/6-core box. Falls back to 1 on any config hiccup."""
    try:
        from .model import Model
        from .parallel import is_cloud_model
        return n if is_cloud_model(Model()) else 1
    except Exception:
        return 1


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
    import getpass
    print(BOLD("\n  Setup -- your provider + two models. Saved to the repo's .env (see .env.example).\n"))
    base = _ask("API base URL (OpenAI-compatible; OpenRouter default, or http://localhost:11434/v1 for local ollama)",
                os.environ.get("WAVE_API_BASE", "https://openrouter.ai/api/v1"))
    try:
        key = getpass.getpass("  API key for that provider (hidden; blank = keep current / none for local ollama): ").strip()
    except (EOFError, KeyboardInterrupt):
        key = ""
    first = _ask("FIRST model -- the primary reasoner that finds, proves & patches",
                 os.environ.get("WAVE_MODEL", "deepseek/deepseek-v4-flash-0731"))
    second = _ask("SECOND model -- a DIFFERENT model that audits judgment-call findings (blank = reuse the first)",
                  os.environ.get("WAVE_AUDIT_MODEL", ""))
    updates = {}
    if base:
        updates["WAVE_API_BASE"] = base
    if key:
        updates["WAVE_API_KEY"] = key
    if first:
        updates["WAVE_MODEL"] = first
    if second:
        updates["WAVE_AUDIT_MODEL"] = second
    path = _write_env(updates)
    for k, v in updates.items():                     # reflect immediately so /status is right now
        os.environ[k] = v
    print(GREEN(f"  saved -> {path}\n"))
    _status_line()


def _write_env(updates):
    """Merge `updates` into the repo's .env (preserving other keys), create it if absent. Returns the path."""
    from .run import _repo_root
    env = _repo_root() / ".env"
    order, existing = [], {}
    if env.is_file():
        for line in env.read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if s and not s.startswith("#") and "=" in s:
                k, v = s.split("=", 1)
                k = k.strip()
                if k not in existing:
                    order.append(k)
                existing[k] = v.strip()
    for k, v in updates.items():
        if k not in existing:
            order.append(k)
        existing[k] = v
    body = "# wave config (see .env.example). KEY=value, WAVE_ prefix.\n" + \
           "\n".join(f"{k}={existing[k]}" for k in order) + "\n"
    try:
        env.write_text(body, encoding="utf-8")
    except OSError as e:
        print(RED(f"  could not write {env}: {e}"))
    return env


def _cmd_config(arg):
    vals = {k: v for k, v in os.environ.items() if k.startswith("WAVE_")}
    if not vals:
        print(DIM("  (nothing configured yet -- run /setup)"))
        return
    for k in sorted(vals):                           # the EFFECTIVE config wave will use (any source)
        print(f"  {k}={'***' if 'KEY' in k else vals[k]}")


def _cmd_status(arg):
    _status_line()


def _cmd_sast(arg):
    target = (arg or "").strip().strip('"').strip("'") or _ask("target repo path", ".")
    if not target:
        return
    print(BOLD("\n  SAST depth:"))
    print("    1) discover        -- fast static candidates, no model (a quick look)")
    print("    2) all             -- full scan of the security-surface files, NO patch")
    print("    3) all --all-files -- FULL scan of EVERY source file, NO patch (thorough; slow on big repos)")
    print("    4) all --patch     -- security-surface scan, plus auto-patch & reverify confirmations")
    print("    5) quick           -- eyes + detect + deps, NO prove/Docker (fast; good for a first look)")
    choice = _ask("choose 1/2/3/4/5", "2")
    # Parallelism: the model stages read one file per call, so on a CLOUD model reading serially is the whole
    # reason a 40-file notebook took ~80 min. Fan out on a cloud model (no-op/serial on a local one).
    jobs = _model_jobs()
    jflag = ["--jobs", str(jobs)] if jobs > 1 else []
    if jobs > 1:
        print(DIM(f"  (cloud model -> reading {jobs} files in parallel)"))
    if choice == "5":
        # Fast, no-Docker pass: notebook + falsifier (the detect verdicts) + the deterministic dep scan.
        # Skips the slow prove/patch stage entirely -- a quick first look / verification path.
        print(CYAN(f"\n  > wave eyes {target} --notes  ;  wave detect {target}  ;  wave deps {target}\n"))
        _run_cli(["eyes", target, "--notes"] + jflag)
        _run_cli(["detect", target] + jflag)
        _run_cli(["deps", target])
        print(DIM(f"  detect verdicts -> {target}/wave_detect.jsonl   deps -> {target}/wave_deps.md"))
        return
    if choice == "1":
        argv = ["discover", target]
    else:
        # 2/3/4 are the one-and-done SAST run -- pipeline + deterministic scans + report. 3 reads every
        # file (best recall, costly); 4 also patches. Only 4 writes fixes.
        argv = ["all", target] + jflag
        if choice == "3":
            argv.append("--all-files")
        elif choice == "4":
            argv.append("--patch")
        if _confirm("include the dependency-CVE scan (sends your package names to OSV.dev over the network)?"):
            argv.append("--online")
        if _confirm("this loads the model and may take a while -- run now?") is False:
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
    cookie = _ask("paste a session Cookie to test as a logged-in user (blank = synthesize)")
    if cookie:
        argv += ["--cookie", cookie]
    elif not _confirm("synthesize an authenticated session (auth)?"):
        argv.append("--no-auth")
    if _confirm("enable blind time-based probes (slow, more intrusive)?"):
        argv.append("--timing")
    if _confirm("hunt stored/second-order XSS (writes payloads into the app, re-renders pages)?"):
        argv.append("--stored")
    delay = _ask("politeness delay between requests in seconds (blank = none)")
    if delay:
        argv += ["--delay", delay]
    plugins = _ask("external tools to run (nuclei,ffuf,zap,mitmproxy or all; blank = none)")
    if plugins:
        argv += ["--plugins", plugins]
    har = _ask("import a captured HAR for surface/recall (path, blank = none)")
    if har:
        argv += ["--har", har]
    if _confirm("use the model to craft payloads on a battery miss (needs a configured endpoint)?"):
        argv.append("--model")
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
    1 discover         fast, deterministic static candidates (no model)        -> wave discover <path>
    2 all              eyes -> detect -> prove on the security-surface files   -> wave all <path>
    3 all --all-files  the full pipeline over EVERY source file (best recall,  -> wave all <path> --all-files
                       costly; no patch)
    4 all --patch      surface scan + patch & dual-gate reverify confirmations -> wave all <path> --patch
    5 quick            eyes + detect + deps, NO prove/Docker (fast first look / verify; detect verdicts
                       land in wave_detect.jsonl, dep CVEs ranked by reachability in wave_deps.md)
  Only option 4 writes fixes. Findings are written under the repo (wave_results / casefile / WAVE_REPORT.md).
  SAST owns cross-file taint & repair. (On a big repo, --all-files is slow -- scope to a subdir instead.)
"""

_HELP_DAST = """
  /dast [url] -- black-box dynamic testing of a LIVE URL (red-team view: any angle, no source)
    RECON (network/infra):   DNS + email-spoofing (SPF/DMARC) + subdomain-takeover, TLS cert
                             (expiry/self-signed/mismatch + SANs), port/service exposure scan.
    POSTURE (http):          stack fingerprint, missing security headers, weak cookie flags,
                             CORS misconfig, dangerous methods, sensitive-path discovery
                             (/.git, /.env, /actuator, swagger, admin, backups, ...).
    APP (injection):         sqli, xss (reflected DOM-execution), STORED/second-order xss (--stored),
                             path, open redirect, SSTI, eval, NoSQLi, SSRF & blind RCE (OAST callback).
    MODEL (opt-in):          --model -- on a battery miss, the model CRAFTS payloads tailored to the
                             response (context breakout, DB-specific, filter evasion); our oracles still
                             prove every confirm. Needs a configured endpoint (/setup).
    JUDGMENT (differential): IDOR, broken access control, missing rate-limit / old-password
                             (reported as anomalous_state -- observed effect, severity is a judgment).
    SAFETY: active traffic (scans ports, sends payloads) -- only run against systems you own or are
    authorized to test. The command refuses without an authorization affirmation.
    RECALL: ingests an OpenAPI/Swagger spec + robots/sitemap + crawled query params automatically, so
            an API needs no manual seeding. AUTH: pass a real session with --cookie / --header to test
            logged-in areas (otherwise a dummy login is synthesized).
    One-shot:  wave dast <url> --authorized [--cookie "sid=.."] [--header "Authorization: Bearer .."]
                              [--no-auth] [--timing] [--stored] [--delay SECONDS]
                              [--plugins nuclei,ffuf,zap,mitmproxy] [--har capture.har] [--model]
                              [--no-recon] [--no-ports] [--target-param "METHOD route vector param"] [--out f]
    POLITENESS: --delay SECONDS throttles ALL outbound requests (recon, battery, writes, renders) to
                avoid hammering / tripping rate limits on a live target.
    TOOLS:      --plugins nuclei,ffuf,zap,mitmproxy (or all) runs free external tools as PERCEPTION --
                output is ingested as leads/surface (wave's oracle still owns every `confirmed`). ZAP
                spiders + passive-scans (WAVE_ZAP_ACTIVE=1 for its slow active scan). --har <file> imports
                captured traffic (mitmproxy/browser/proxy HAR) -> routes+params for recall.
"""

_HELP_SETUP = """
  /setup (alias /env) -- configure your provider + two models, written to the repo .env
    Prompts for: the API base URL (OpenAI-compatible -- OpenRouter, or a local ollama), the API key
    (hidden), the FIRST model (primary reasoner), and the SECOND model (a different model that audits
    judgment-call findings; optional). Saved to the repo's .env (copy of .env.example) so future runs
    need no env vars. View the effective config with /config.
    Manual: `cp .env.example .env` and edit it. One-shot equivalents:
      wave config set base <url> | set key <key> | set model <id> | set audit <id>
    The env var names are WAVE_API_BASE / WAVE_API_KEY / WAVE_MODEL / WAVE_AUDIT_MODEL.
    DAST needs no model; SAST's full pipeline does.
"""
