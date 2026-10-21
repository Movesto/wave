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
    """A start command from package.json scripts, else a main/module file, else ''. Runtime-aware runner."""
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


def _cost_tier(modules_count, direct_deps):
    if modules_count > 400 or direct_deps > 150:
        return "heavy"
    if modules_count > 80 or direct_deps > 40:
        return "medium"
    return "light"


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
        tier = _cost_tier(modules, direct)

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
            reasons.append(f"~{modules or direct} packages to load — sizable memory/boot cost")
        if not modules:
            reasons.append("node_modules not installed yet (first boot installs them)")

        rel_pkg = pkg_name or (str(pkg_dir).replace("\\", "/").rsplit("/", 1)[-1])
        return WitnessPlan(
            needed=True, runtime=rt_name, package=rel_pkg, entrypoint=entry,
            deps_installed=modules, direct_deps=direct, services=services, cost_tier=tier,
            route=f"{method} {path}", feasibility=feasibility, reasons=reasons)
    except Exception:
        return None
