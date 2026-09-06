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
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import registry

_SKIP = {"node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build", "site-packages"}


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


_COMPOSE_NAMES = ("compose.local.yml", "docker-compose.local.yml", "compose.local.yaml",
                  "docker-compose.yaml", "docker-compose.yml", "compose.yml", "compose.yaml")


def _pick_compose(root):
    """Choose a compose file, PREFERRING one that builds the app from source (so the sink hook can be
    injected). Searches the root first, then SUBDIRS (monorepos keep it in infrastructure/ / deploy/ /
    docker/), so pointing at the repo root reuses the app's own multi-service stack."""
    candidates = [str(Path(root) / n) for n in _COMPOSE_NAMES if (Path(root) / n).exists()]
    if not candidates:
        for n in _COMPOSE_NAMES:
            for p in sorted(Path(root).rglob(n)):
                if not any(s in p.parts for s in _SKIP):
                    candidates.append(str(p))
    with_build = [c for c in candidates if _parse_compose(c)[0]]   # has a build service
    return (with_build or candidates or [""])[0]


def _build_context(compose, build_svc):
    """Absolute dir of the build service's context (where the app's manifest/code live)."""
    try:
        d = yaml.safe_load(Path(compose).read_text(encoding="utf-8")) or {}
        b = (d.get("services", {}).get(build_svc, {}) or {}).get("build")
        ctx = b if isinstance(b, str) else (b or {}).get("context", ".")
        return str((Path(compose).parent / ctx).resolve())
    except Exception:
        return str(Path(compose).parent)


def profile(target) -> TargetProfile:
    root = str(target)                                     # ANALYSIS scope (whole repo); app may be a subdir
    compose = _pick_compose(root)
    app_root = root
    if compose:                                            # monorepo: profile the app from its BUILD CONTEXT,
        bs, _, _ = _parse_compose(compose)                 # not from an unrelated manifest elsewhere in the repo
        if bs:
            app_root = _build_context(compose, bs)
    req = _find(app_root, ["requirements.txt"])
    pkg = _find(app_root, ["package.json"])
    if req and not pkg:
        deps = Path(req).read_text(encoding="utf-8", errors="replace")
        fw = ("connexion" if "connexion" in deps.lower() else "fastapi" if "fastapi" in deps.lower()
              else "flask" if "flask" in deps.lower() else "python")
        entry = _detect_entry_py(app_root)
        return TargetProfile(root, "py", fw, deps, entry, _detect_port(app_root, entry, 5000), compose,
                             [h.name for h in registry.select(deps, "py")])
    if pkg:
        deps = Path(pkg).read_text(encoding="utf-8", errors="replace")
        fw = "nestjs" if "@nestjs" in deps else "express" if "express" in deps else "node"
        entry = "server.js" if (Path(app_root) / "server.js").exists() else "index.js"
        return TargetProfile(root, "js", fw, deps, entry, _detect_port(app_root, entry, 3000), compose,
                             [h.name for h in registry.select(deps, "js")])
    raise SystemExit(f"profile: unrecognized stack at {target}")


# ---- compose / Dockerfile parsing (JS multi-service path) --------------------------------------
def _parse_compose(path):
    d = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    services = d.get("services", {})
    build_svc = next((n for n, s in services.items() if isinstance(s, dict) and "build" in s), None)
    host, internal = None, None
    svc = services.get(build_svc, {}) or {}
    for p in svc.get("ports", []) or []:
        parts = str(p).split(":")
        internal = int(parts[-1].split("/")[0])
        host = int(parts[0]) if len(parts) > 1 else internal
        break
    if internal is None:                                       # apps often only `expose:` the port
        for e in svc.get("expose", []) or []:
            internal = int(str(e).split("/")[0])
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
_ENTRY_PY = '''"""wave entry shim: load sink hooks, then START THE APP the way its framework expects
(ASGI apps -> uvicorn; Flask/WSGI -> run the module as __main__). Framework-agnostic so the same
provisioner boots Flask, FastAPI/Starlette, etc. -- not just a Flask-style app.py."""
import sys, runpy, os
{imports}
try:
    import flask
    _o = flask.Flask.run
    flask.Flask.run = lambda self, *a, **k: _o(self, *a, **{{**k, "use_reloader": False}})
except Exception:
    pass
_FW, _MOD, _APP = "{framework}", "{module}", "{appvar}"
_PORT = int(os.environ.get("PORT", "{port}"))
if _FW in ("fastapi", "starlette") and _MOD and _APP:
    import uvicorn
    _m = __import__(_MOD, fromlist=[_APP])
    uvicorn.run(getattr(_m, _APP), host="0.0.0.0", port=_PORT)
else:
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
    def __init__(self, prof, compose_files, service, host_port, workdir="/app", code_root=None):
        self.profile = prof
        self.compose_files = list(compose_files)
        self.service = service
        self.base_url = f"http://localhost:{host_port}"
        self.healthy = False
        self.workdir = workdir                          # where the app's code lives INSIDE the image
        self.code_root = code_root or prof.root         # host dir that maps to workdir (for piece micro-exec)

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


def _detect_asgi(root):
    """Find the ASGI app object (`app = FastAPI(...)`/`Starlette(...)`) as a top-level module:var so the
    shim can serve it with uvicorn. Returns (module_stem, appvar) or ("", "")."""
    for f in Path(root).rglob("*.py"):
        if any(s in f.parts for s in _SKIP) or f.name.startswith("_wave_"):
            continue
        try:
            src = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = re.search(r"^(\w+)\s*=\s*(?:FastAPI|Starlette)\(", src, re.M)
        if m:
            return f.stem, m.group(1)
    return "", ""


def _write_py(prof, hooks):
    root = Path(prof.root)
    imports = []
    for h in hooks:
        (root / h.filename).write_text(h.code, encoding="utf-8")
        imports.append(f"import {h.filename[:-3]}")
    module, appvar = _detect_asgi(root) if prof.framework in ("fastapi", "starlette") else ("", "")
    (root / "_wave_entry.py").write_text(
        _ENTRY_PY.format(imports="\n".join(imports), entry=prof.entry, framework=prof.framework,
                         module=module, appvar=appvar, port=prof.internal_port), encoding="utf-8")
    (root / "Dockerfile.wave").write_text(_DOCKERFILE_PY.format(entry=prof.entry), encoding="utf-8")


# ---- DB sidecars: boot a real database alongside the app so DB-backed apps reach Rung 2. General by
# the DECLARED driver -- an app needing Postgres/MySQL/Mongo gets one, wired via DATABASE_URL + the
# common per-field env vars. No migrations needed: the sink hook logs the marker at execute time,
# BEFORE the DB processes the query, so injection proves even against an empty schema. --------------
_DB_SIDECARS = {
    "postgres": {
        "image": "postgres:16-alpine",
        "env": {"POSTGRES_USER": "wave", "POSTGRES_PASSWORD": "wave", "POSTGRES_DB": "wave"},
        "health": "pg_isready -U wave -d wave",
        "app_env": {"DATABASE_URL": "postgresql://wave:wave@db:5432/wave",
                    "POSTGRES_HOST": "db", "POSTGRES_PORT": "5432", "POSTGRES_USER": "wave",
                    "POSTGRES_PASSWORD": "wave", "POSTGRES_DB": "wave",
                    "DB_HOST": "db", "DB_PORT": "5432", "DB_USER": "wave", "DB_PASSWORD": "wave", "DB_NAME": "wave"},
    },
    "mysql": {
        "image": "mysql:8",
        "env": {"MYSQL_ROOT_PASSWORD": "wave", "MYSQL_DATABASE": "wave", "MYSQL_USER": "wave", "MYSQL_PASSWORD": "wave"},
        "health": "mysqladmin ping -h 127.0.0.1 -u root -pwave",
        "app_env": {"DATABASE_URL": "mysql+pymysql://root:wave@db:3306/wave",
                    "DB_HOST": "db", "DB_PORT": "3306", "DB_USER": "root", "DB_PASSWORD": "wave", "DB_NAME": "wave",
                    "MYSQL_HOST": "db", "MYSQL_USER": "root", "MYSQL_PASSWORD": "wave", "MYSQL_DATABASE": "wave"},
    },
    "mongo": {
        "image": "mongo:7",
        "env": {},
        "health": "mongosh --quiet --eval \"db.runCommand({ping:1})\"",
        "app_env": {"DATABASE_URL": "mongodb://db:27017/wave", "MONGO_URL": "mongodb://db:27017/wave",
                    "MONGODB_URI": "mongodb://db:27017/wave", "DB_HOST": "db", "DB_PORT": "27017"},
    },
}


def _detect_db(deps_text):
    d = (deps_text or "").lower()
    if any(x in d for x in ("psycopg", "asyncpg", "postgres")):
        return "postgres"
    if any(x in d for x in ("pymysql", "mysqlclient", "mysqldb", "aiomysql", "mysql-connector", "mariadb")):
        return "mysql"
    if any(x in d for x in ("pymongo", "motor")):
        return "mongo"
    return None


def _compose_dict(name, host, internal, db):
    app = {"build": {"context": ".", "dockerfile": "Dockerfile.wave"}, "container_name": name,
           "ports": [f"{host}:{internal}"], "environment": ["vulnerable=1", "tokentimetolive=3600"]}
    services = {"wave-app": app}
    if db:
        spec = _DB_SIDECARS[db]
        services["db"] = {"image": spec["image"],
                          "environment": [f"{k}={v}" for k, v in spec["env"].items()],
                          "healthcheck": {"test": ["CMD-SHELL", spec["health"]], "interval": "3s",
                                          "timeout": "5s", "retries": 25, "start_period": "5s"}}
        app["environment"] += [f"{k}={v}" for k, v in spec["app_env"].items()]
        app["depends_on"] = {"db": {"condition": "service_healthy"}}
    return {"services": services}


def _provision_py(prof, hooks, host_port):
    host_port = host_port or prof.internal_port
    name = "wave-" + Path(prof.root).name.lower()
    _write_py(prof, hooks)
    db = _detect_db(prof.deps_text)
    compose = str(Path(prof.root) / "wave.compose.yml")
    Path(compose).write_text(yaml.safe_dump(_compose_dict(name, host_port, prof.internal_port, db),
                                            sort_keys=False), encoding="utf-8")
    if db:
        print(f"[provision] + {db} sidecar (the app declares a {db} driver)", flush=True)
    return RunningTarget(prof, [compose], "wave-app", host_port), [compose]


_SITECUSTOMIZE = '''"""wave sitecustomize: auto-imported at interpreter startup (via PYTHONPATH) so the
sink hooks load regardless of the app's entrypoint (uvicorn / gunicorn / python ...)."""
try:
{imports}
except Exception as _e:
    import sys
    print("wave: sink-hook load failed:", _e, file=sys.stderr)
'''


def _provision_py_compose(prof, hooks, host_port):
    """Reuse the app's OWN multi-service compose (app + db + other services). Inject the sink hooks via a
    bind-mounted sitecustomize.py + PYTHONPATH on the build service -- entrypoint-agnostic, so it works
    with the app's real Dockerfile CMD. Other services keep their host ports dropped to avoid clashes."""
    d = yaml.safe_load(Path(prof.compose_file).read_text(encoding="utf-8")) or {}
    services = d.get("services", {})
    build_svc, _, internal = _parse_compose(prof.compose_file)
    if not build_svc:
        raise SystemExit("provision(py): the app compose has no build service (prebuilt image?)")
    internal = internal or prof.internal_port
    host = host_port or internal
    # write everything NEXT TO the original compose so its relative build contexts (../backend) resolve
    compose_dir = Path(prof.compose_file).parent
    b = (services.get(build_svc, {}) or {}).get("build")
    ctx = b if isinstance(b, str) else (b or {}).get("context", ".")
    workdir = _dockerfile_workdir((compose_dir / ctx).resolve())   # the build context's Dockerfile WORKDIR

    hook_dir = compose_dir / "_wave_hooks"              # bind-mounted at /wave_hooks (on PYTHONPATH)
    hook_dir.mkdir(exist_ok=True)
    imports = []
    for h in hooks:
        (hook_dir / h.filename).write_text(h.code, encoding="utf-8")
        imports.append(f"    import {h.filename[:-3]}")
    (hook_dir / "sitecustomize.py").write_text(_SITECUSTOMIZE.format(imports="\n".join(imports) or "    pass"),
                                               encoding="utf-8")
    host_hooks = str(hook_dir.resolve()).replace("\\", "/")

    for n, s in services.items():
        if not isinstance(s, dict):
            continue
        if n == build_svc:
            pp = f"/wave_hooks:{workdir}"
            env = s.get("environment")
            if isinstance(env, list):
                s["environment"] = [e for e in env if not str(e).startswith("PYTHONPATH")] + [f"PYTHONPATH={pp}"]
            else:
                env = dict(env or {})
                env["PYTHONPATH"] = pp
                s["environment"] = env
            s["ports"] = [f"{host}:{internal}"]
            s["volumes"] = (s.get("volumes") or []) + [f"{host_hooks}:/wave_hooks:ro"]
        else:
            s.pop("ports", None)                         # reach other services over the internal network
    out = str(compose_dir / "wave.compose.full.yml")     # next to the original -> relative contexts resolve
    Path(out).write_text(yaml.safe_dump(d), encoding="utf-8")
    rt = RunningTarget(prof, [out], build_svc, host, workdir=workdir,
                       code_root=str((compose_dir / ctx).resolve()))
    return rt, [out]


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


def compose_env():
    """docker-compose env with common defaults so a required-var compose (`${POSTGRES_PASSWORD:?}`)
    doesn't fail variable substitution (used by both boot and per-piece micro-exec)."""
    import os as _os
    env = dict(_os.environ)
    for k, v in {"POSTGRES_PASSWORD": "wave", "POSTGRES_USER": "wave", "POSTGRES_DB": "wave",
                 "DB_PASSWORD": "wave", "MYSQL_ROOT_PASSWORD": "wave", "SECRET_KEY": "wave-secret"}.items():
        env.setdefault(k, v)
    return env


def prepare(target, host_port=None):
    """Write the compose + Dockerfile + sink hooks WITHOUT booting. Returns (rt, files, prof) so the
    loop can micro-execute pieces in the built image (`docker compose run --no-deps`) without ever
    starting the whole stack -- run-by-piece, not run-the-whole-app."""
    prof = profile(target)
    hooks = registry.select(prof.deps_text, prof.lang)
    if not hooks:
        raise SystemExit(f"provision: no Registry sink hook for {prof.framework}/{prof.lang}")
    if prof.lang == "py":
        rt, files = _provision_py_compose(prof, hooks, host_port) if prof.compose_file \
            else _provision_py(prof, hooks, host_port)      # reuse the app's own multi-service compose if it ships one
    else:
        rt, files = _provision_js(prof, hooks, host_port)
    return rt, files, prof


# common liveness paths -- an app that 404s on `/` but serves `/health` or `/docs` is UP, not dead.
_HEALTH_PATHS = ("/", "/health", "/healthz", "/ping", "/status", "/api", "/api/health", "/docs",
                 "/login", "/index.html")


def _probe(base_url, timeout=4):
    """Is the SERVER accepting HTTP? Any HTTP response -- INCLUDING 401/403/404/500 -- means it is up and
    serving (the crux fix: a 404 on `/` is a LIVE server, not a dead one). Only a refused connection /
    timeout / DNS failure means it is not up yet. Tries several common paths."""
    for path in _HEALTH_PATHS:
        try:
            with urllib.request.urlopen(base_url + path, timeout=timeout) as r:
                return True, r.status                       # 2xx/3xx -> definitely up
        except urllib.error.HTTPError as e:
            return True, e.code                             # 4xx/5xx -> the server RESPONDED, so it is up
        except Exception:
            continue                                        # refused/timeout on this path -> try the next
    return False, 0


def _service_exited(rt):
    """True if the app service has already EXITED (crashed) -- so we stop waiting the full window."""
    try:
        r = rt._compose("ps", "-a", "--status", "exited", "--services")
        return rt.service in (r.stdout or "").split()
    except Exception:
        return False


_FAIL_SIGNS = (
    ("missing dependency", ("modulenotfounderror", "no module named", "importerror", "cannot find module",
                            "err_module_not_found")),
    ("port clash", ("address already in use", "port is already allocated", "bind: address already in use")),
    ("database not ready", ("could not connect to server", "connection refused", "econnrefused",
                            "server closed the connection", "getaddrinfo")),
    ("crash on startup", ("traceback (most recent call last)", "panic:", "segmentation fault",
                          "unhandledpromiserejection", "fatal error")),
    ("build error", ("failed to solve", "returned a non-zero code", "npm err!", "error: pull access denied")),
)


def _classify_failure(logs):
    """Best-effort reason from the container logs -> feeds an actionable `blocked: <reason>` + escalation."""
    low = (logs or "").lower()
    for reason, needles in _FAIL_SIGNS:
        if any(n in low for n in needles):
            return reason
    return "did not become healthy (unknown -- slow start, wrong entrypoint, or no HTTP listener)"


def provision(target, host_port=None, timeout=600, health_window=180) -> RunningTarget:
    """Build + boot the app and health-gate it. `timeout` bounds the build/up (raised to 600s so a large
    monorepo can finish building); `health_window` bounds the readiness poll. On failure, raises with the
    CLASSIFIED reason + a log tail (so the caller records a specific `blocked: <reason>` and the user sees
    why) instead of a generic message."""
    rt, files, prof = prepare(target, host_port)
    hooks = prof.drivers
    print(f"[provision] building+booting {prof.framework}/{prof.lang} via {len(files)} compose file(s); "
          f"hooks={hooks}", flush=True)
    cmd = ["docker", "compose"]
    for f in files:
        cmd += ["-f", f]
    cmd += ["up", "-d", "--build"]
    try:
        up = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                            timeout=timeout, env=compose_env())
    except subprocess.TimeoutExpired:
        try:
            rt.down()
        except Exception:
            pass
        raise RuntimeError(f"provision: build/boot exceeded {timeout}s (a large repo -- raise timeout, or the "
                           f"build is stuck); provisioning is a Rung-2 concern, static verdicts stand")
    if up.returncode != 0:                     # `up --build` failed outright (build error / bad compose)
        reason = _classify_failure((up.stdout or "") + (up.stderr or ""))
        tail = ((up.stderr or "") + (up.stdout or "")).strip()[-500:]
        try:
            rt.down()
        except Exception:
            pass
        raise RuntimeError(f"provision: compose up failed ({reason}). --- log tail ---\n{tail}")

    deadline = time.time() + health_window
    while time.time() < deadline:
        up_now, status = _probe(rt.base_url)
        if up_now:
            rt.healthy = True
            print(f"[provision] up at {rt.base_url} (HTTP {status}; instrumented: {hooks})", flush=True)
            return rt
        if _service_exited(rt):                # crashed -> don't wait the whole window
            break
        time.sleep(3)

    logs = rt.logs()                           # NOT healthy -> capture WHY, classify, raise actionably
    reason = _classify_failure(logs)
    tail = logs.strip()[-500:]
    try:
        rt.down()
    except Exception:
        pass
    print(f"[provision] NOT healthy at {rt.base_url} -- {reason}", flush=True)
    raise RuntimeError(f"provision: app not healthy at {rt.base_url} -- {reason} "
                       f"({prof.framework}/{prof.lang}). --- log tail ---\n{tail}")
