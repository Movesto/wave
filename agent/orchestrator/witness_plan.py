"""Preflight WITNESS PLAN -- assess, before any heavy boot, what it would TAKE to witness a hypothesis and
whether it's worth it on this machine.

Some findings can't be proven by the in-process scaffold (call one exported function): an UNAUTHENTICATED
HTTP-exec on an INLINE route (e.g. a Hono arrow callback) has no importable function to call -- the only real
witness is to BOOT the app and drive a live request to the route. But booting is not free: a big monorepo is
gigabytes of node_modules and may expect a database/other services. Rather than blind-boot (and risk an OOM on
a weak machine) or silently give up, this module produces a short PLAN for such a lead:

  - what the PROJECT needs to function: runtime, server entrypoint, deps (installed? how many), external
    services it appears to want (DB/redis/...), a coarse cost tier;
  - what the HARNESS needs to prove it: the route to hit, the payload shape, the marker it would watch for;
  - a FEASIBILITY call (ready / heavy / underspecified) with reasons.

The plan is surfaced in the report as an OPT-IN ("to witness this, boot X ..."), so a small self-contained app
is cheap to green-light and a heavy/under-specified one tells you the cost + what's missing instead of guessing
on your behalf. This module only ASSESSES -- it never boots anything (that executor is a separate step that
plugs in behind this gate). Pure + dependency-light; never raises (returns None on any trouble).
"""
from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

# package.json deps whose presence means the app expects an EXTERNAL service the sandbox can't just `install`
# -- these are what make a boot "underspecified" unless the user supplies them (connection string / compose).
_SERVICE_DEPS = {
    "pg": "PostgreSQL", "postgres": "PostgreSQL", "pg-promise": "PostgreSQL", "prisma": "a Prisma database",
    "@prisma/client": "a Prisma database", "mysql": "MySQL", "mysql2": "MySQL", "mariadb": "MariaDB",
    "mongodb": "MongoDB", "mongoose": "MongoDB", "redis": "Redis", "ioredis": "Redis",
    "@aws-sdk/client-s3": "AWS S3", "kafkajs": "Kafka", "amqplib": "RabbitMQ", "nats": "NATS",
    "elasticsearch": "Elasticsearch", "@elastic/elasticsearch": "Elasticsearch", "cassandra-driver": "Cassandra",
}
# package.json script names that START a server, best first.
_START_SCRIPTS = ("start", "serve", "dev", "start:prod", "server", "web")


@dataclass
class WitnessPlan:
    needed: bool = False                       # is a boot-level witness the applicable path for this lead?
    runtime: str = ""                          # bun / node / deno / ...
    package: str = ""                          # the package dir to boot (relative to target or its name)
    entrypoint: str = ""                        # the detected start command (e.g. `bun run dev`) or ""
    deps_installed: int = 0                     # top-level entries in node_modules (0 = not installed)
    direct_deps: int = 0                        # dependencies + devDependencies declared in package.json
    services: list = field(default_factory=list)   # external services the app appears to require
    cost_tier: str = "light"                    # light | medium | heavy (a coarse boot-cost estimate)
    route: str = ""                             # the HTTP route the witness would drive (METHOD /path)
    marker: str = "a planted side-effect marker (a wave_HIT file) or a sealed instrumented-sink hit"
    feasibility: str = "ready"                  # ready | heavy | underspecified
    reasons: list = field(default_factory=list)

    def as_dict(self):
        return {"needed": self.needed, "runtime": self.runtime, "package": self.package,
                "entrypoint": self.entrypoint, "deps_installed": self.deps_installed,
                "direct_deps": self.direct_deps, "services": list(self.services), "cost_tier": self.cost_tier,
                "route": self.route, "marker": self.marker, "feasibility": self.feasibility,
                "reasons": list(self.reasons)}

    def summary(self):
        """One compact human line for the report: what a boot witness would need + cost + feasibility."""
        if not self.needed:
            return ""
        where = self.package or "the server package"
        rt = self.runtime or "its runtime"
        cost = {"light": "light", "medium": "~medium", "heavy": "HEAVY"}.get(self.cost_tier, self.cost_tier)
        inst = "deps installed" if self.deps_installed else "deps NOT yet installed"
        svc = ("needs: " + ", ".join(self.services)) if self.services else "no external services detected"
        drive = f"drive `{self.route}`" if self.route else "drive the route"
        head = {"ready": "a boot-and-drive witness is feasible",
                "heavy": "a boot-and-drive witness is possible but COSTLY on limited hardware",
                "underspecified": "a boot-and-drive witness needs config you'd have to supply"}.get(
                    self.feasibility, self.feasibility)
        tail = (" — " + "; ".join(self.reasons)) if self.reasons else ""
        return (f"{head}: boot {where} on {rt} ({cost} cost, {inst}), {drive}; {svc}. "
                f"Not run (opt-in).{tail}")


def _nearest_package_json(path, target):
    """The nearest package.json at/above `path`, bounded at the repo root (.git) or the scan target."""
    try:
        p = Path(path).resolve()
    except Exception:
        return None
    tgt = Path(target).resolve()
    for d in (p if p.is_dir() else p.parent, *(p if p.is_dir() else p.parent).parents):
        pj = d / "package.json"
        if pj.is_file():
            return pj
        if (d / ".git").is_dir() or d == tgt.parent:
            break
    return None


def _read_json(p):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


def _entrypoint(pkg, runtime):
    """A start command from package.json scripts, else a main/module file, else ''. Runtime-aware runner.
    An explicit WAVE_BOOT_CMD wins (the user telling us exactly how THEIR project boots its server). This is
    only the PREFLIGHT estimate shown in the report; the actual boot re-resolves it against the project's real
    CLI subcommands (see boot_witness._resolve_server_cmd) so we drive what the project ships, not a guess."""
    override = os.environ.get("WAVE_BOOT_CMD", "").strip()
    if override:
        return override
    runner = {"bun": "bun run", "deno": "deno task", "node": "npm run"}.get(runtime, "npm run")
    scripts = pkg.get("scripts") or {}
    for name in _START_SCRIPTS:
        if name in scripts:
            return f"{runner} {name}"
    main = pkg.get("module") or pkg.get("main")
    if main:
        exe = {"bun": "bun", "deno": "deno run -A", "node": "node"}.get(runtime, "node")
        return f"{exe} {main}"
    bins = pkg.get("bin")
    if isinstance(bins, str):
        exe = {"bun": "bun", "deno": "deno run -A", "node": "node"}.get(runtime, "node")
        return f"{exe} {bins}"
    return ""


def _modules_count(pkg_dir):
    """Top-level entries in node_modules (a fast proxy for installed-package count); 0 if not installed."""
    nm = Path(pkg_dir) / "node_modules"
    if not nm.is_dir():
        return 0
    try:
        return sum(1 for _ in os.scandir(nm))
    except OSError:
        return 0


def _cost_tier(modules_count, direct_deps, modules_mb=0):
    """Coarse boot-cost tier. SIZE dominates when we've measured it (package COUNT is unreliable across
    bun/npm/pnpm layouts -- bun's node_modules shows few top-level entries for gigabytes on disk)."""
    if modules_mb > 800 or modules_count > 400 or direct_deps > 150:
        return "heavy"
    if modules_mb > 150 or modules_count > 80 or direct_deps > 40:
        return "medium"
    return "light"


# memory CAP (docker --memory) suggested per cost tier -- a server killed above it comes back `blocked`,
# never a crash. The caller can override with WAVE_BOOT_MEMORY. Coarse but honest: it's the knob that
# actually decides "can my machine run this witness".
_MEM_BY_TIER = {"light": "1g", "medium": "2g", "heavy": "4g"}


def mem_for_tier(tier: str) -> str:
    return os.environ.get("WAVE_BOOT_MEMORY") or _MEM_BY_TIER.get(tier, "2g")


_LOCKFILES = ("bun.lock", "bun.lockb", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "deno.lock")


def workspace_root(target):
    """The INSTALL root to mount for a boot: in a monorepo, deps are hoisted to the WORKSPACE root (where the
    lockfile + the real node_modules live) and each package only SYMLINKS them -- so mounting the nearest
    node_modules (a package's symlink farm) wouldn't resolve. Prefer the OUTERMOST dir (up to the .git
    boundary) that has a lockfile, else the outermost package.json, else the .git dir. Returns
    (root, pkg_subdir) where pkg_subdir is the server package to cd into (relative to root)."""
    p = Path(target).resolve()
    start = p if p.is_dir() else p.parent                      # anchor on a DIR (target may be a source file)
    chain = []
    for d in (start, *start.parents):
        chain.append(d)
        if (d / ".git").is_dir():
            break
    root = None
    for d in reversed(chain):                                  # outermost first: the install/workspace root
        if any((d / lf).exists() for lf in _LOCKFILES):
            root = d
            break
    if root is None:
        for d in reversed(chain):
            if (d / "package.json").is_file():
                root = d
                break
    root = root or chain[-1]
    pkg_dir = root                                             # the package the target belongs to: the
    for d in chain:                                           # INNERMOST package.json at/above it, within root
        if (d / "package.json").is_file():
            pkg_dir = d
            break
    try:
        sub = str(pkg_dir.resolve().relative_to(root.resolve())).replace("\\", "/")
    except Exception:
        sub = "."
    return root, (sub or ".")


def _deps_root(target):
    """(root, node_modules_path) for size measurement -- the workspace root's node_modules (the real,
    hoisted one), not a package's symlink farm."""
    root, _sub = workspace_root(target)
    nm = root / "node_modules"
    return root, (nm if nm.is_dir() else None)


def _dir_size_mb(path, budget_s=5.0):
    """Sum file sizes under `path`, bounded by a wall-clock budget (a 2 GB node_modules can be 100k+ files,
    too slow to fully stat in a preflight). Returns (megabytes, partial?) -- `partial` True means it's a
    LOWER BOUND (the walk was cut off), reported as '>=' so the number is never misleadingly small."""
    if not path or not Path(path).is_dir():
        return 0.0, False
    total, t0, partial = 0, time.monotonic(), False
    try:
        for root, _dirs, files in os.walk(path):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
            if time.monotonic() - t0 > budget_s:
                partial = True
                break
    except OSError:
        pass
    return total / (1024 * 1024), partial


_WS_MODULES_MB = {}        # workspace-root -> (mb, partial): measuring a 1.5 GB node_modules is slow and is the
#                            SAME for every candidate in a target, so measure it once and share it (footprint +
#                            each build_plan), which also keeps the plan's cost tier == the footprint's tier.


def _workspace_modules_mb(target):
    """Measured size of the hoisted (workspace-root) node_modules, cached per root. (mb, partial)."""
    try:
        root, nm = _deps_root(target)
        key = str(root)
        if key not in _WS_MODULES_MB:
            _WS_MODULES_MB[key] = _dir_size_mb(nm) if nm else (0.0, False)
        return _WS_MODULES_MB[key]
    except Exception:
        return 0.0, False


@dataclass
class Footprint:
    package: str = ""
    runtime: str = ""
    source_mb: float = 0.0
    modules_mb: float = 0.0
    modules_partial: bool = False       # modules_mb is a LOWER BOUND (walk was time-capped)
    modules_installed: bool = False
    packages: int = 0                   # top-level node_modules entries
    cost_tier: str = "light"
    mem_cap: str = "2g"                 # the docker --memory the boot will run under
    free_disk_gb: float = 0.0

    def line(self):
        src = f"source {self.source_mb:.0f} MB"
        if self.modules_installed:
            mods = f"node_modules {'>=' if self.modules_partial else ''}{self.modules_mb:.0f} MB"
        else:
            mods = "node_modules NOT installed (first boot installs them -- needs network + that much free disk)"
        tier = {"light": "LIGHT", "medium": "MEDIUM", "heavy": "HEAVY"}.get(self.cost_tier, self.cost_tier)
        return (f"[{tier}] {self.package or 'project'} ({self.runtime}): {src}, {mods}; "
                f"free disk {self.free_disk_gb:.0f} GB. Boot runs under a {self.mem_cap} memory cap "
                f"(set WAVE_BOOT_MEMORY to change; killed above it => blocked, never a crash).")


def project_footprint(target):
    """Measured STORAGE + MEMORY footprint of booting this project's server package -- so the user can judge
    'can my hardware run the witness' BEFORE committing to a boot. Bounded (time-capped size walk); never
    raises. Returns a Footprint (zeros if it can't be measured)."""
    try:
        from . import runtimes
        rt = runtimes.detect(target)
        rt_name = getattr(rt, "name", "") or "node"
        root, nm = _deps_root(target)
        pj = _nearest_package_json(target, target)
        pkg = _read_json(pj) if pj else {}
        pkg_dir = pj.parent if pj else root
        name = pkg.get("name") or pkg_dir.name
        direct = len(pkg.get("dependencies") or {}) + len(pkg.get("devDependencies") or {})
        packages = _modules_count(root)
        source_mb, _ = _dir_size_mb(pkg_dir, budget_s=3.0)          # the package's own source
        modules_mb, partial = _workspace_modules_mb(target)         # shared/cached with build_plan -> same tier
        tier = _cost_tier(packages, direct, modules_mb)
        try:
            free_gb = shutil.disk_usage(str(root)).free / (1024 ** 3)
        except Exception:
            free_gb = 0.0
        return Footprint(package=name, runtime=rt_name, source_mb=source_mb, modules_mb=modules_mb,
                         modules_partial=partial, modules_installed=bool(nm), packages=packages,
                         cost_tier=tier, mem_cap=mem_for_tier(tier), free_disk_gb=free_gb)
    except Exception:
        return Footprint()


def build_plan(target, candidate, route=None, runtime=None):
    """Assess the boot-and-drive witness for ONE candidate. Returns a WitnessPlan (with .needed False when a
    boot witness isn't the applicable path), or None on any trouble. `route` = (method, path, framework, recipe)
    as prove builds it; `runtime` = a runtimes.Runtime (else detected here). Never raises."""
    try:
        from . import runtimes
        file = getattr(candidate, "file", "") or ""
        # A boot-and-drive witness is only the right path for a sink reached through an HTTP ROUTE (the
        # in-process scaffold covers everything callable). No route -> not needed.
        if not route:
            return WitnessPlan(needed=False)
        method, path = (route[0] or "?"), (route[1] or "/?")
        rt = runtime if runtime is not None else runtimes.detect(target)
        rt_name = getattr(rt, "name", "") or "node"

        pj_path = _nearest_package_json(file, target)
        pkg = _read_json(pj_path) if pj_path else {}
        pkg_dir = pj_path.parent if pj_path else Path(target)
        pkg_name = pkg.get("name") or (pj_path.parent.name if pj_path else "")

        deps = dict(pkg.get("dependencies") or {})
        dev = dict(pkg.get("devDependencies") or {})
        direct = len(deps) + len(dev)
        declared = set(deps) | set(dev)
        services = sorted({label for dep, label in _SERVICE_DEPS.items() if dep in declared})
        # a docker-compose at/above the package is a strong signal the app expects stood-up services
        for d in (pkg_dir, Path(target)):
            for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml"):
                if (d / name).is_file() and "a stood-up service set (docker-compose)" not in services:
                    services.append("a stood-up service set (docker-compose)")

        entry = _entrypoint(pkg, rt_name)
        modules = _modules_count(pkg_dir)
        modules_mb, _ = _workspace_modules_mb(target)               # measured size dominates the tier (so the
        tier = _cost_tier(modules, direct, modules_mb)              # plan agrees with project_footprint)

        reasons = []
        feasibility = "ready"
        if not entry:
            feasibility = "underspecified"
            reasons.append("no start script / entrypoint found in package.json")
        if services:
            feasibility = "underspecified"
            reasons.append("expects external service(s) the sandbox can't auto-stand-up")
        if feasibility == "ready" and tier == "heavy":
            feasibility = "heavy"
            reasons.append(f"~{modules_mb:.0f} MB of node_modules to load — sizable memory/boot cost"
                           if modules_mb else f"~{modules or direct} packages to load — sizable memory/boot cost")
        if not modules:
            reasons.append("node_modules not installed yet (first boot installs them)")

        rel_pkg = pkg_name or (str(pkg_dir).replace("\\", "/").rsplit("/", 1)[-1])
        return WitnessPlan(
            needed=True, runtime=rt_name, package=rel_pkg, entrypoint=entry,
            deps_installed=modules, direct_deps=direct, services=services, cost_tier=tier,
            route=f"{method} {path}", feasibility=feasibility, reasons=reasons)
    except Exception:
        return None
