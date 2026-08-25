"""Environment Provisioner — turn a target repo into a live, instrumented app.

Runtime step 1 of the loop: profile the stack, inject the matching sink hook(s) from the Registry
(the "modified driver"), boot, health-gate. Two paths:
  - PY standalone (e.g. VAmPI): generate a Dockerfile + compose that build the app with a wave entry
    shim (loads hooks, disables the reloader -- Phase-0 F2).
  - JS / multi-service (e.g. NodeGoat: web + mongo): COMPOSE-MERGE -- reuse the app's own compose
    (its build, DB service, wait-for-db + seed command) and inject the hook via NODE_OPTIONS=--require
    through an override file. This is the generic multi-service approach.
Returns a RunningTarget the exploit/oracle stages drive. Deterministic; no model.
"""
import re
import subprocess
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import registry


@dataclass
class TargetProfile:
    root: str
    lang: str
    framework: str
    deps_text: str
    entry: str
    internal_port: int
    compose_file: str = ""
    drivers: list = field(default_factory=list)


def _find(root, names):
    for n in names:
        p = Path(root) / n
        if p.exists():
            return str(p)
    for n in names:
        hits = list(Path(root).rglob(n))
        if hits:
            return str(hits[0])
    return ""


def _detect_entry_py(root):
    for c in ("app.py", "main.py", "wsgi.py", "server.py", "run.py"):
        p = Path(root) / c
        if p.exists() and re.search(r"__main__|\.run\(|uvicorn", p.read_text(encoding="utf-8", errors="replace")):
            return c
    return "app.py"


def _detect_port(root, entry, default):
    try:
        m = re.search(r"port\s*=\s*(\d{2,5})", (Path(root) / entry).read_text(encoding="utf-8", errors="replace"))
        return int(m.group(1)) if m else default
    except OSError:
        return default


def _pick_compose(root):
    """Choose a compose file, PREFERRING one that builds the app from source (so the sink hook can be
    injected) over one that pulls a prebuilt image (e.g. brokencrystals compose.yml vs compose.local.yml)."""
    candidates = [str(p) for name in ("compose.local.yml", "docker-compose.local.yml", "compose.local.yaml",
                                      "docker-compose.yaml", "docker-compose.yml", "compose.yml", "compose.yaml")
                  for p in [Path(root) / name] if p.exists()]
    with_build = [c for c in candidates if _parse_compose(c)[0]]   # has a build service
    return (with_build or candidates or [""])[0]


def profile(target) -> TargetProfile:
    root = str(target)
    req = _find(root, ["requirements.txt"])
    pkg = _find(root, ["package.json"])
    compose = _pick_compose(root)
    if req and not pkg:
        deps = Path(req).read_text(encoding="utf-8", errors="replace")
        fw = ("connexion" if "connexion" in deps.lower() else "fastapi" if "fastapi" in deps.lower()
              else "flask" if "flask" in deps.lower() else "python")
        entry = _detect_entry_py(root)
        return TargetProfile(root, "py", fw, deps, entry, _detect_port(root, entry, 5000), compose,
                             [h.name for h in registry.select(deps, "py")])
    if pkg:
        deps = Path(pkg).read_text(encoding="utf-8", errors="replace")
        fw = "nestjs" if "@nestjs" in deps else "express" if "express" in deps else "node"
        entry = "server.js" if (Path(root) / "server.js").exists() else "index.js"
        return TargetProfile(root, "js", fw, deps, entry, _detect_port(root, entry, 3000), compose,
                             [h.name for h in registry.select(deps, "js")])
    raise SystemExit(f"profile: unrecognized stack at {target}")


# ---- compose / Dockerfile parsing (JS multi-service path) --------------------------------------
def _parse_compose(path):
    d = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    services = d.get("services", {})
    build_svc = next((n for n, s in services.items() if isinstance(s, dict) and "build" in s), None)
    host, internal = None, None
    for p in (services.get(build_svc, {}) or {}).get("ports", []) or []:
        parts = str(p).split(":")
        internal = int(parts[-1].split("/")[0])
        host = int(parts[0]) if len(parts) > 1 else internal
        break
    return build_svc, host, internal


def _dockerfile_workdir(root):
    df = Path(root) / "Dockerfile"
    if not df.exists():
        return "/app"
    env, wd = {}, "/app"
    for line in df.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"\s*ENV\s+(\w+)\s+(.+)", line)
        if m:
            env[m.group(1)] = m.group(2).strip()
        m = re.match(r"\s*WORKDIR\s+(.+)", line)
        if m:
            wd = m.group(1).strip()
    for k, v in env.items():                                   # resolve $VAR / ${VAR}
        wd = wd.replace(f"${{{k}}}", v).replace(f"${k}", v)
    return wd.rstrip("/") or "/app"


# ---- PY standalone build artifacts ------------------------------------------------------------
_ENTRY_PY = '''"""wave entry shim: load sink hooks + disable reloaders, then run the app as __main__."""
import sys, runpy
{imports}
try:
    import flask
    _o = flask.Flask.run
    flask.Flask.run = lambda self, *a, **k: _o(self, *a, **{{**k, "use_reloader": False}})
except Exception:
    pass
runpy.run_path(sys.argv[1] if len(sys.argv) > 1 else "{entry}", run_name="__main__")
'''
_DOCKERFILE_PY = '''FROM python:3.11-alpine
RUN apk add --no-cache bash g++
WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY . /app
ENV vulnerable=1
ENTRYPOINT ["python", "_wave_entry.py", "{entry}"]
'''
_COMPOSE_PY = '''services:
  wave-app:
    build:
      context: .
      dockerfile: Dockerfile.wave
    container_name: {name}
    ports:
      - "{host}:{internal}"
    environment:
      - vulnerable=1
      - tokentimetolive=3600
'''


class RunningTarget:
    def __init__(self, prof, compose_files, service, host_port):
        self.profile = prof
        self.compose_files = list(compose_files)
        self.service = service
        self.base_url = f"http://localhost:{host_port}"
        self.healthy = False

    def _compose(self, *args):
        cmd = ["docker", "compose"]
        for f in self.compose_files:
            cmd += ["-f", f]
        cmd += list(args)
        return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")

    def logs(self):
        r = self._compose("logs", "--no-color", self.service)
        return (r.stdout or "") + (r.stderr or "")

    def sink_lines(self, marker=""):
        want = marker or "WAVE-SINK"
        return [l for l in self.logs().replace("\r", "").splitlines() if want in l]

    def down(self):
        self._compose("down", "-v")


def _write_py(prof, hooks):
    root = Path(prof.root)
    imports = []
    for h in hooks:
        (root / h.filename).write_text(h.code, encoding="utf-8")
        imports.append(f"import {h.filename[:-3]}")
    (root / "_wave_entry.py").write_text(_ENTRY_PY.format(imports="\n".join(imports), entry=prof.entry),
                                         encoding="utf-8")
    (root / "Dockerfile.wave").write_text(_DOCKERFILE_PY.format(entry=prof.entry), encoding="utf-8")


def _provision_py(prof, hooks, host_port):
    host_port = host_port or prof.internal_port
    name = "wave-" + Path(prof.root).name.lower()
    _write_py(prof, hooks)
    compose = str(Path(prof.root) / "wave.compose.yml")
    Path(compose).write_text(_COMPOSE_PY.format(name=name, host=host_port, internal=prof.internal_port),
                             encoding="utf-8")
    return RunningTarget(prof, [compose], "wave-app", host_port), [compose]


def _provision_js(prof, hooks, host_port):
    if not prof.compose_file:
        raise SystemExit("provision(js): no app compose (standalone JS not implemented)")
    d = yaml.safe_load(Path(prof.compose_file).read_text(encoding="utf-8")) or {}
    services = d.get("services", {})
    build_svc, _, internal = _parse_compose(prof.compose_file)
    if not build_svc:
        raise SystemExit("provision(js): no build service in the app compose (prebuilt image?)")
    internal = internal or prof.internal_port
    host = host_port or internal
    workdir = _dockerfile_workdir(prof.root)
    mounts = []
    for h in hooks:
        (Path(prof.root) / h.filename).write_text(h.code, encoding="utf-8")
        host_path = str((Path(prof.root) / h.filename).resolve()).replace("\\", "/")
        mounts.append(f"{host_path}:{workdir}/{h.filename}:ro")   # BIND-MOUNT: survives multi-stage/prebuilt
    node_opts = " ".join(f"--require {workdir}/{h.filename}" for h in hooks)

    # Generate a full modified compose (not an override -- override APPENDS ports, which can't clear a
    # conflicting host mapping). Inject the hook via a bind-MOUNT + NODE_OPTIONS on the build service
    # (a multi-stage/prebuilt image won't COPY our source file); drop host-port publishing on all OTHER
    # services so their host ports can't clash (the app reaches them over the internal network).
    for n, s in services.items():
        if not isinstance(s, dict):
            continue
        if n == build_svc:
            env = s.get("environment")
            if isinstance(env, list):
                s["environment"] = env + [f"NODE_OPTIONS={node_opts}"]
            else:
                env = dict(env or {})
                env["NODE_OPTIONS"] = node_opts
                s["environment"] = env
            s["ports"] = [f"{host}:{internal}"]
            s["volumes"] = (s.get("volumes") or []) + mounts
        else:
            s.pop("ports", None)
    out = str(Path(prof.root) / "wave.compose.full.yml")
    Path(out).write_text(yaml.safe_dump(d), encoding="utf-8")
    return RunningTarget(prof, [out], build_svc, host), [out]


def provision(target, host_port=None, timeout=300) -> RunningTarget:
    prof = profile(target)
    hooks = registry.select(prof.deps_text, prof.lang)
    if not hooks:
        raise SystemExit(f"provision: no Registry sink hook for {prof.framework}/{prof.lang}")

    if prof.lang == "py":
        rt, files = _provision_py(prof, hooks, host_port)
    else:
        rt, files = _provision_js(prof, hooks, host_port)

    print(f"[provision] building+booting {prof.framework}/{prof.lang} via {len(files)} compose file(s); "
          f"hooks={[h.name for h in hooks]}", flush=True)
    cmd = ["docker", "compose"]
    for f in files:
        cmd += ["-f", f]
    cmd += ["up", "-d", "--build"]
    subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)

    for _ in range(90):                        # heavy multi-service apps (keycloak realm import, etc.)
        try:
            with urllib.request.urlopen(rt.base_url + "/", timeout=4) as r:
                if r.status < 500:
                    rt.healthy = True
                    break
        except Exception:
            pass
        time.sleep(3)
    print(f"[provision] {'up' if rt.healthy else 'NOT healthy'} at {rt.base_url} "
          f"(instrumented: {[h.name for h in hooks]})", flush=True)
    return rt
