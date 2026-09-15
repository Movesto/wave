"""The EXECUTE tool -- the model's hands.

Run whatever the model asks -- any language, a shell command, an auth login, an HTTP request, a compile
-and-run -- inside a sandbox, and hand back the result (stdout / stderr / exit code / duration). The
tool knows NO languages: the model writes the specifics (`python x.py`, `node x.js`, `./a.out`,
`curl -X POST /login ...`, `psql -c ...`) and this just executes them in a throwaway container and
returns what came back. It is universal because it executes commands in an ENVIRONMENT, not because it
understands them.

The model reasons over the result (evidence-grounded plan: the model has the final say; the tool only
supplies what actually happened). Nothing here decides "vulnerable" -- it decides nothing.

SAFETY: never runs on the host. Every call is a fresh container with no network by default (opt in when
the model needs to reach a target), a memory/cpu/pids cap, and a hard timeout. `container=` instead runs
the command inside an already-running target container (the app's own environment -- deps, runtime,
auth all present) via `docker exec`.
"""
from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass

# Where a per-investigation dependency store is bind-mounted inside the sandbox. Packages the model asks
# for are downloaded here ONCE (with network); every later run mounts this read-back so `network=none`
# execution can still import them. Keeps "fetch a dep" (egress) separate from "run the exploit" (no egress).
_DEPS_MOUNT = "/wave_deps"

# A conservative package-name allow-list: PEP 508-ish name + optional extras + optional version pin, and
# npm's @scope/name. No spaces, quotes, shell metacharacters, flags, or VCS/url installs -- so a model
# request can never smuggle `-e git+...`, `--find-links`, or `; rm -rf` into the install shell command.
_PKG_RE = re.compile(
    r"^(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9][A-Za-z0-9._-]*"     # name (optionally @scope/ for npm)
    r"(?:\[[A-Za-z0-9,_.-]+\])?"                              # extras, e.g. [cryptography]
    r"(?:(?:==|>=|<=|~=|!=|>|<|@)[A-Za-z0-9._*+-]+)?$")       # version pin / npm @version


def _safe_pkg(name: str) -> bool:
    return bool(name) and len(name) <= 100 and _PKG_RE.match(name) is not None


@dataclass
class ExecResult:
    command: str
    stdout: str
    stderr: str
    exit_code: int
    duration: float
    timed_out: bool = False

    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def summary(self, limit: int = 4000) -> str:
        """A compact, model-facing digest of the run."""
        head = (f"$ {self.command}\n[exit {self.exit_code}"
                + (" TIMED OUT" if self.timed_out else "") + f", {self.duration:.1f}s]")
        out = (self.stdout or "").strip()
        err = (self.stderr or "").strip()
        parts = [head]
        if out:
            parts.append("--- stdout ---\n" + out[:limit])
        if err:
            parts.append("--- stderr ---\n" + err[:limit])
        return "\n".join(parts)


def _docker_mount(host_path: str) -> str:
    """Host path in a form Docker Desktop accepts as a bind-mount source. On Windows/git-bash, turn
    C:\\Users\\x into //c/Users/x; POSIX paths pass through."""
    p = os.path.abspath(host_path)
    if len(p) >= 2 and p[1] == ":":                      # Windows drive path
        drive, rest = p[0].lower(), p[2:].replace("\\", "/")
        return f"//{drive}{rest}"
    return p


def execute(command: str, *, stdin: str | None = None, image: str = "python:3.12-slim",
            mount: str | None = None, workdir: str = "/work", timeout: int = 60,
            network: str = "none", env: dict | None = None, memory: str = "512m",
            cpus: str = "1", container: str | None = None, deps: str | None = None) -> ExecResult:
    """Run `command` in a sandbox and return the result.

    - `image`: the runtime to run in (python/node/gcc/... -- the model picks what its command needs).
    - `mount`: a host dir to bind at `workdir` (so the target's own code/files are present).
    - `network`: "none" (default, no egress) or e.g. "host"/a compose network when the model must reach
      a target (auth, HTTP). `container`: run inside this already-running container via `docker exec`
      instead of a fresh `docker run` (the app's own environment).
    - `deps`: a host dir holding packages the model asked to install (see install_packages). It is
      bind-mounted read-back and put on PYTHONPATH/NODE_PATH, so an offline (network=none) run can still
      import them -- downloads happen only in install_packages, never here.
    """
    if shutil.which("docker") is None:
        return ExecResult(command, "", "execute: docker is not available on this host", 127, 0.0)

    if container:
        cmd = ["docker", "exec", "-i"]
        for k, v in (env or {}).items():
            cmd += ["-e", f"{k}={v}"]
        if workdir:
            cmd += ["-w", workdir]
        cmd += [container, "sh", "-c", command]
    else:
        name = "wave-exec-" + secrets.token_hex(4)
        cmd = ["docker", "run", "--rm", "-i", "--name", name, "--network", network,
               "--memory", memory, "--cpus", cpus, "--pids-limit", "256", "-w", workdir]
        if mount:
            cmd += ["-v", _docker_mount(mount) + ":" + workdir]
        eff_env = dict(env or {})
        if deps:                                             # installed packages -> importable, no egress
            cmd += ["-v", _docker_mount(deps) + ":" + _DEPS_MOUNT]
            eff_env.setdefault("PYTHONPATH", _DEPS_MOUNT)
            eff_env.setdefault("NODE_PATH", _DEPS_MOUNT + "/node_modules")
        for k, v in eff_env.items():
            cmd += ["-e", f"{k}={v}"]
        cmd += [image, "sh", "-c", command]

    t0 = time.time()
    try:
        r = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        return ExecResult(command, r.stdout or "", r.stderr or "", r.returncode, time.time() - t0)
    except subprocess.TimeoutExpired as e:
        if not container:                                # kill the runaway container we named
            subprocess.run(["docker", "kill", name], capture_output=True)
        out = e.stdout if isinstance(e.stdout, str) else (e.stdout.decode("utf-8", "replace") if e.stdout else "")
        return ExecResult(command, out or "", f"execute: timed out after {timeout}s", 124,
                          time.time() - t0, timed_out=True)
    except Exception as e:
        return ExecResult(command, "", f"execute: failed to run ({type(e).__name__}: {e})", 1,
                          time.time() - t0)


def install_packages(packages, *, deps: str, image: str = "python:3.12-slim", kind: str = "py",
                     network: str = "host", timeout: int = 300) -> ExecResult:
    """Download `packages` into the `deps` dir so later network=none runs can import them. This is the
    ONE place egress happens for dependency provisioning: it runs a throwaway networked container that
    installs into the shared deps dir; the exploit runs stay offline and just read it back.

    - `kind`: "py" -> `pip install --target <deps>`; "js" -> `npm install --prefix <deps>`.
    Package names are validated (_safe_pkg) so the model cannot smuggle flags/urls/shell into the command.
    """
    if shutil.which("docker") is None:
        return ExecResult("install", "", "install: docker is not available on this host", 127, 0.0)
    pkgs = [p for p in (packages or []) if _safe_pkg(str(p).strip())]
    rejected = [p for p in (packages or []) if not _safe_pkg(str(p).strip())]
    if not pkgs:
        return ExecResult("install", "", "install: no valid package names"
                          + (f" (rejected: {rejected})" if rejected else ""), 1, 0.0)
    if kind == "js":
        img = image if "node" in (image or "") else "node:20-slim"
        inner = (f"npm install --no-audit --no-fund --ignore-scripts --prefix {_DEPS_MOUNT} "
                 + " ".join(pkgs))
    else:
        img = image if "python" in (image or "") else "python:3.12-slim"
        inner = f"pip install --no-input --disable-pip-version-check --target {_DEPS_MOUNT} " + " ".join(pkgs)
    name = "wave-deps-" + secrets.token_hex(4)
    cmd = ["docker", "run", "--rm", "--name", name, "--network", network, "--memory", "2g", "--cpus", "2",
           "-v", _docker_mount(deps) + ":" + _DEPS_MOUNT, img, "sh", "-c", inner]
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        return ExecResult("install: " + " ".join(pkgs), r.stdout or "", r.stderr or "",
                          r.returncode, time.time() - t0)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "kill", name], capture_output=True)
        return ExecResult("install: " + " ".join(pkgs), "", f"install: timed out after {timeout}s", 124,
                          time.time() - t0, timed_out=True)
    except Exception as e:
        return ExecResult("install: " + " ".join(pkgs), "", f"install: failed ({type(e).__name__}: {e})",
                          1, time.time() - t0)
