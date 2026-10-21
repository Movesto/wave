"""Boot-and-drive witness EXECUTOR -- the one thing the in-process scaffold can't do: actually START the app
and hit it over HTTP.

For an unauthenticated HTTP command-exec on an INLINE route (a Hono/Express arrow callback with no importable
function), the only real witness is to boot the server and drive a live request to the route. This module does
exactly that, deterministically and within a hard budget:

  1. launch the server package's start command in ONE Docker container (the resolved runtime image, e.g.
     oven/bun:1), mounted read-write at the boot root so the app's node_modules resolve;
  2. wait for it to print/bind a port;
  3. drive ONE request at the vulnerable route -- the MODEL crafts the request (method, path with params
     filled, body) that injects a per-run MARKER command (`touch /work/<marker>`) into the field that reaches
     the shell; the harness sends it with the runtime's own fetch (no curl dependency);
  4. OBSERVE: the marker FILE appearing in the mount is the witness (the injected command executed through the
     live route), graded by the harness -- not the model's say-so.

Strictly bounded + safe: `--network none` (the client reaches the server over the container's OWN loopback,
but nothing egresses), `--memory`/`--cpus` caps, a wall-clock timeout, `--rm`, and the whole thing is OPT-IN
(gated by the caller on a flag + the preflight feasibility). Everything degrades gracefully: any failure to
boot/bind/drive returns a `blocked`/None result and the caller falls back to the normal lead -- it NEVER
raises and never turns a non-result into a false `confirmed`.

Scope of this first executor: JS/TS command-exec routes (CWE-78 / unauth-exec). Other classes return None so the
caller keeps its existing path.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_MEMORY = "2g"
DEFAULT_CPUS = "2"
DEFAULT_TIMEOUT = 180        # total wall-clock for boot + wait + drive (seconds)
_BOOT_WAIT = 40              # seconds to wait for the server to bind a port, inside the container

# classes this executor can drive (a command-exec route is the first-class target)
_EXEC_CWES = {"CWE-78", "CWE-77", "CWE-94"}
_EXEC_FAMILIES = ("cmd", "exec", "unauth-exec", "rce")


def available() -> bool:
    return shutil.which("docker") is not None


def enabled() -> bool:
    """Opt-in: the caller also gates on the preflight feasibility, but this is the hard env switch."""
    return os.environ.get("WAVE_BOOT_WITNESS", "").strip().lower() in ("1", "true", "yes", "on")


def _docker_mount(host_path: str) -> str:
    p = os.path.abspath(host_path)
    if len(p) >= 2 and p[1] == ":":                           # Windows C:\x -> //c/x
        return f"//{p[0].lower()}{p[2:].replace(chr(92), '/')}"
    return p


def _boot_root(target: str):
    """The dir to MOUNT: the nearest ancestor with node_modules (deps resolve there -- often hoisted to the
    monorepo root), else the nearest package.json / .git, else the target. Returns (root, pkg_subdir)."""
    p = Path(target).resolve()
    root = None
    for d in (p, *p.parents):
        if (d / "node_modules").is_dir():
            root = d
            break
        if (d / ".git").is_dir():
            root = root or d
            break
    if root is None:
        from . import js_env
        pj = js_env._pkg_root(target)
        root = pj or p
    # the package dir that actually holds the start script (nearest package.json at/above target)
    from . import js_env
    pkg = js_env._pkg_root(target) or root
    try:
        sub = str(pkg.resolve().relative_to(root.resolve())).replace("\\", "/")
    except Exception:
        sub = "."
    return root, (sub or ".")


def is_applicable(candidate, plan) -> bool:
    """True only for a JS command-exec route whose preflight plan says a boot is actually feasible."""
    if plan is None or not getattr(plan, "needed", False):
        return False
    cwe = (getattr(candidate, "cwe", "") or "").upper()
    fam = (getattr(candidate, "family", "") or "").lower()
    if cwe not in _EXEC_CWES and not any(f in fam for f in _EXEC_FAMILIES):
        return False
    if getattr(plan, "runtime", "") not in ("bun", "node", "deno"):
        return False
    return bool(getattr(plan, "entrypoint", ""))


_REQ_SYS = (
    "You craft ONE HTTP request that drives a web route to a command-execution sink, to WITNESS the bug on a "
    "live server. Return ONLY a JSON object, no prose: "
    '{"method":"POST","path":"/full/path/with/params/filled","headers":{"Content-Type":"application/json"},'
    '"body":"<raw request body string, or empty>"}. '
    "Fill any :param / {param} path segments with a plausible dummy value. Put the INJECTION in whichever "
    "field reaches the shell (often a JSON body field like command/cmd/input/script): inject a value that runs "
    "the marker command so we can observe it. Do NOT add auth headers -- the whole point is to test the route "
    "WITHOUT credentials."
)


def _model_request(model, *, route, code_window, marker):
    """Ask the model for a concrete request spec (one shot, no tools). Returns a dict or None."""
    if model is None:
        return None
    method, path = route[0], route[1]
    inject = f"; touch /work/{marker}"                        # the marker side-effect (file appears => executed)
    user = (f"Route: {method} {path}\nMarker command to inject (creates the witness file): `{inject}` "
            f"(you may also use `$(touch /work/{marker})` or a newline form if the field is not a shell "
            f"string).\nHandler/code around the sink:\n{code_window}\n\nReturn the JSON request now.")
    try:
        msg = model.chat([{"role": "system", "content": _REQ_SYS},
                          {"role": "user", "content": user}], temperature=0.1)
        content = (msg or {}).get("content") if isinstance(msg, dict) else getattr(msg, "content", "")
        m = re.search(r"\{.*\}", content or "", re.S)
        if not m:
            return None
        spec = json.loads(m.group(0))
        if not isinstance(spec, dict) or not spec.get("path"):
            return None
        return spec
    except Exception:
        return None


def _default_request(route, marker):
    """Heuristic fallback when there's no model / the model reply didn't parse: fill path params with '1' and
    try the common command fields with the marker injection."""
    method, path = (route[0] or "POST").upper(), route[1] or "/"
    path = re.sub(r"[:{][A-Za-z0-9_]+\}?", "1", path)         # :id / {id} -> 1
    inject = f"; touch /work/{marker}"
    if method in ("GET", "HEAD"):                             # a body on GET/HEAD makes fetch throw
        return {"method": method, "path": path, "headers": {}, "body": ""}
    body = json.dumps({k: inject for k in ("command", "cmd", "input", "script")})
    return {"method": method, "path": path, "headers": {"Content-Type": "application/json"}, "body": body}


# The in-container driver: start the server, wait for a port, send ONE request with the runtime's fetch, then
# report whether the marker file appeared. Placeholders are @@TOKENS@@ (not str.format) so the shell/regex
# braces (`{2,5}`, `${...}`) survive untouched.
_DRIVER = r'''
cd "/work/@@SUB@@" || cd /work
rm -f "/work/@@MARKER@@"
( @@EP@@ ) > /tmp/wave_srv.log 2>&1 &
SRV=$!
PORT=""
for i in $(seq 1 @@WAIT@@); do
  PORT=$(grep -oiE ':[0-9]{2,5}' /tmp/wave_srv.log | grep -oE '[0-9]{2,5}' | head -1)
  if [ -z "$PORT" ]; then PORT=$(grep -oiE 'port[^0-9]{0,4}[0-9]{2,5}' /tmp/wave_srv.log | grep -oE '[0-9]{2,5}' | tail -1); fi
  [ -n "$PORT" ] && break
  kill -0 $SRV 2>/dev/null || { echo "WAVE_BOOT: SERVER_EXITED"; break; }
  sleep 1
done
if [ -z "$PORT" ]; then echo "WAVE_BOOT: NO_PORT"; echo "---LOG---"; tail -40 /tmp/wave_srv.log; exit 0; fi
echo "WAVE_BOOT: PORT=$PORT"
cat > /tmp/wave_req.mjs <<'EOFREQ'
const spec = @@SPEC@@;
const base = "http://127.0.0.1:" + process.env.WAVE_PORT;
(async () => {
  try {
    const m = (spec.method || "POST").toUpperCase();
    const noBody = (m === "GET" || m === "HEAD" || spec.body === "" || spec.body == null);
    const r = await fetch(base + spec.path, { method: m,
      headers: spec.headers || {}, body: (noBody ? undefined : spec.body) });
    const t = await r.text();
    console.log("WAVE_RESP_STATUS:", r.status);
    console.log("WAVE_RESP_BODY:", t.slice(0, 400));
  } catch (e) { console.log("WAVE_REQ_ERROR:", e && e.message); }
})();
EOFREQ
WAVE_PORT=$PORT @@RUNNER@@ /tmp/wave_req.mjs 2>&1 | head -20
sleep 1
if [ -f "/work/@@MARKER@@" ]; then echo "WAVE_BOOT: MARKER_PRESENT"; else echo "WAVE_BOOT: MARKER_ABSENT"; fi
kill $SRV 2>/dev/null
echo "---LOG---"; tail -40 /tmp/wave_srv.log
'''


def _render_driver(*, sub, marker, ep, wait, spec, runner):
    s = _DRIVER
    for tok, val in (("@@SUB@@", sub), ("@@MARKER@@", marker), ("@@EP@@", ep),
                     ("@@WAIT@@", str(wait)), ("@@SPEC@@", spec), ("@@RUNNER@@", runner)):
        s = s.replace(tok, val)
    return s


@dataclass
class BootResult:
    verdict: str                # confirmed | anomalous_state | refuted | blocked
    evidence: str = ""
    why: str = ""
    log: str = ""
    status: int = 0             # HTTP status observed (0 if none)
    marker: str = ""            # the witness marker (set on a confirm) -> harness_marker in the record


def _runner_cmd(runtime):
    return {"bun": "bun", "deno": "deno run -A", "node": "node"}.get(runtime, "node")


def _classify(out: str, marker: str) -> BootResult:
    """Grade the container's stdout. The MARKER FILE appearing is the witness (deterministic, harness-read)."""
    log_tail = out.split("---LOG---", 1)[1].strip()[:800] if "---LOG---" in out else ""
    m = re.search(r"WAVE_RESP_STATUS:\s*(\d+)", out)
    status = int(m.group(1)) if m else 0
    body = ""
    mb = re.search(r"WAVE_RESP_BODY:\s*(.*)", out)
    if mb:
        body = mb.group(1).strip()[:200]
    if "WAVE_BOOT: MARKER_PRESENT" in out:
        return BootResult("confirmed", evidence=f"the injected command executed through the live route: the "
                          f"marker file /work/{marker} was created (HTTP {status or '?'}).",
                          why="boot-and-drive witness: live request to the route created the marker side-effect",
                          log=log_tail, status=status, marker=f"boot:/work/{marker}")
    if "WAVE_BOOT: NO_PORT" in out or "WAVE_BOOT: SERVER_EXITED" in out:
        return BootResult("blocked", why="the server did not boot/bind a port within the budget "
                          "(entrypoint may need config/services, or a longer boot)", log=log_tail)
    if status and status not in (401, 403):
        return BootResult("anomalous_state", evidence=f"the route answered WITHOUT credentials (HTTP {status}"
                          + (f": {body}" if body else "") + f") but the exec marker did not appear.",
                          why="route reached unauthenticated; command execution not observed (handler may "
                              "validate the dummy params before the sink)", log=log_tail, status=status)
    if status in (401, 403):
        return BootResult("refuted", why=f"the route required authentication (HTTP {status}) -- an auth guard "
                          "is present on this path", log=log_tail, status=status)
    return BootResult("blocked", why="booted and sent the request but observed neither the marker nor a usable "
                      "response", log=log_tail, status=status)


def drive(target, candidate, plan, *, image, runtime, route, model=None, code_window="",
          memory=None, cpus=None, timeout=None):
    """Boot the app and drive the route to witness a command-exec bug. Returns a BootResult, or None when not
    applicable / Docker absent. Never raises."""
    if not available() or not is_applicable(candidate, plan):
        return None
    marker = "wave_BOOT_" + secrets.token_hex(5)
    spec = _model_request(model, route=route, code_window=code_window, marker=marker) \
        or _default_request(route, marker)
    root, sub = _boot_root(target)
    ep = plan.entrypoint
    script = _render_driver(sub=sub, marker=marker, ep=ep, wait=_BOOT_WAIT,
                            spec=json.dumps(spec), runner=_runner_cmd(runtime))
    cmd = ["docker", "run", "--rm", "--network", "none",
           "--memory", str(memory or DEFAULT_MEMORY), "--cpus", str(cpus or DEFAULT_CPUS),
           "-v", _docker_mount(str(root)) + ":/work", "-w", "/work",
           image, "sh", "-c", script]
    env = dict(os.environ)
    env["MSYS_NO_PATHCONV"] = "1"                              # Git-Bash: don't mangle /work
    print(f"🔌 [boot-witness] booting {plan.package} ({runtime}) to drive {route[0]} {route[1]} ...", flush=True)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=int(timeout or DEFAULT_TIMEOUT), env=env)
    except subprocess.TimeoutExpired:
        return BootResult("blocked", why=f"boot-and-drive exceeded the {int(timeout or DEFAULT_TIMEOUT)}s budget "
                          "(server too heavy to boot here, or it hung)")
    except Exception as e:
        return BootResult("blocked", why=f"boot-and-drive could not run ({type(e).__name__})")
    out = (r.stdout or "") + ("\n" + r.stderr if r.stderr else "")
    res = _classify(out, marker)
    tick = {"confirmed": "✓ WITNESSED", "anomalous_state": "• reached (unauth)", "refuted": "• guarded",
            "blocked": "✗ could not boot/drive"}.get(res.verdict, res.verdict)
    print(f"🔌 [boot-witness] {tick}: {res.why[:90]}", flush=True)
    return res
