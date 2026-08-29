"""JS/TS provisioning for the investigate sandbox.

The investigator can only PROVE a JS/TS vuln if the suspect code actually RUNS -- but real repos need
TypeScript transpilation and their node_modules, which a bare `node:20-slim` lacks. This module gives
the sandbox the two missing pieces, once and cached:

  1. a runner image (`wave-js-runner`) with `tsx` installed -> `.ts` files execute (via `tsx`).
  2. the repo's node_modules -> `require`/`import` of its dependencies resolves.

With both in place the model's exploit (`require('/work/app').f('; id')` / `tsx -e "..."`) actually
fires and produces the observable effect the grounding rule needs. Everything degrades gracefully: if
Docker or the network is unavailable, the caller falls back to the plain image and the candidate just
stays a lead -- never a crash.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

RUNNER_IMAGE = "wave-js-runner:latest"
_DOCKERFILE = "FROM node:20-slim\nRUN npm install -g tsx@4 >/dev/null 2>&1 || npm install -g tsx\n"

# Browser sandbox for XSS/DOM classes: Microsoft's Playwright image (chromium + all deps preinstalled)
# + tsx + a global playwright, with NODE_PATH so a script anywhere can `require('playwright')`. Lets the
# model RENDER a payload in a real headless browser and observe whether it executed as script.
BROWSER_IMAGE = "wave-js-browser:latest"
_BROWSER_PW = "v1.48.0"
_BROWSER_DOCKERFILE = (
    f"FROM mcr.microsoft.com/playwright:{_BROWSER_PW}-jammy\n"
    # local install in a fixed dir -> reliable require() resolution (global + NODE_PATH is flaky here)
    "RUN mkdir -p /opt/wave && cd /opt/wave && npm init -y >/dev/null 2>&1 && "
    "npm install tsx playwright@1.48.0\n"
    "ENV NODE_PATH=/opt/wave/node_modules\n"
    "ENV PATH=/opt/wave/node_modules/.bin:$PATH\n"
)


def _docker_mount(host_path: str) -> str:
    """Host path in Docker-bind-mount form (Windows C:\\x -> //c/x)."""
    p = os.path.abspath(host_path)
    if len(p) >= 2 and p[1] == ":":
        return f"//{p[0].lower()}{p[2:].replace(chr(92), '/')}"
    return p


def ensure_runner(timeout: int = 600) -> str | None:
    """Build the tsx-equipped runner image once (cached); return its tag, or None if it can't be built."""
    import shutil
    if shutil.which("docker") is None:
        return None
    inspect = subprocess.run(["docker", "image", "inspect", RUNNER_IMAGE], capture_output=True)
    if inspect.returncode == 0:
        return RUNNER_IMAGE
    print(f"[js_env] building {RUNNER_IMAGE} (node + tsx) -- one time ...", flush=True)
    try:
        r = subprocess.run(["docker", "build", "-t", RUNNER_IMAGE, "-"], input=_DOCKERFILE, text=True,
                           capture_output=True, timeout=timeout)
    except Exception as e:
        print(f"[js_env] runner build failed ({type(e).__name__}) -- falling back to node:20-slim", flush=True)
        return None
    if r.returncode != 0:
        print(f"[js_env] runner build failed -- falling back to node:20-slim", flush=True)
        return None
    return RUNNER_IMAGE


def ensure_browser_runner(timeout: int = 1800) -> str | None:
    """Build the Playwright/chromium browser image once (cached); return its tag, or None if unavailable.
    Large (~2GB) and slow the first time -- worth it: it's the only way to PROVE XSS (render + observe)."""
    import shutil
    if shutil.which("docker") is None:
        return None
    if subprocess.run(["docker", "image", "inspect", BROWSER_IMAGE], capture_output=True).returncode == 0:
        return BROWSER_IMAGE
    print(f"[js_env] building {BROWSER_IMAGE} (playwright + chromium) -- one time, large download ...", flush=True)
    try:
        r = subprocess.run(["docker", "build", "-t", BROWSER_IMAGE, "-"], input=_BROWSER_DOCKERFILE,
                           text=True, capture_output=True, timeout=timeout)
    except Exception as e:
        print(f"[js_env] browser image build failed ({type(e).__name__})", flush=True)
        return None
    if r.returncode != 0:
        print(f"[js_env] browser image build failed: {(r.stderr or '')[-200:]}", flush=True)
        return None
    return BROWSER_IMAGE


def _pkg_root(target: str) -> Path | None:
    """The nearest directory at/above the target that has a package.json (where node_modules belongs)."""
    p = Path(target).resolve()
    for d in (p, *p.parents):
        if (d / "package.json").is_file():
            return d
        if (d / ".git").is_dir():
            break
    return None


def ensure_deps(target: str, timeout: int = 600) -> bool:
    """Install the repo's node_modules once (in a linux container, so native deps match the sandbox), if
    it's an npm project that doesn't already have them. Returns True if deps are present afterwards.
    Uses --ignore-scripts: never run an untrusted package's postinstall while just trying to read code."""
    import shutil
    if shutil.which("docker") is None:
        return False
    root = _pkg_root(target)
    if root is None:
        return False
    if (root / "node_modules").is_dir():
        return True                                         # already installed (host or prior run)
    print(f"[js_env] installing node_modules for {root.name} (once) ...", flush=True)
    try:
        r = subprocess.run(
            ["docker", "run", "--rm", "-v", _docker_mount(str(root)) + ":/app", "-w", "/app",
             "node:20-slim", "npm", "install", "--no-audit", "--no-fund", "--ignore-scripts"],
            capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        print(f"[js_env] npm install failed ({type(e).__name__}) -- deps unavailable", flush=True)
        return False
    ok = (root / "node_modules").is_dir()
    if not ok:
        print(f"[js_env] npm install did not produce node_modules (exit {r.returncode})", flush=True)
    return ok


def prepare(target: str) -> str | None:
    """Ensure the runner image + the repo's deps for the investigate sandbox. Returns the runner image
    tag to use (or None to fall back to the default node image)."""
    image = ensure_runner()
    ensure_deps(target)                                     # best-effort; the model can still read code without it
    return image
