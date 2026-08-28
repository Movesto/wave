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
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass


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
            cpus: str = "1", container: str | None = None) -> ExecResult:
    """Run `command` in a sandbox and return the result.

    - `image`: the runtime to run in (python/node/gcc/... -- the model picks what its command needs).
    - `mount`: a host dir to bind at `workdir` (so the target's own code/files are present).
    - `network`: "none" (default, no egress) or e.g. "host"/a compose network when the model must reach
      a target (auth, HTTP). `container`: run inside this already-running container via `docker exec`
      instead of a fresh `docker run` (the app's own environment).
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
        for k, v in (env or {}).items():
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
