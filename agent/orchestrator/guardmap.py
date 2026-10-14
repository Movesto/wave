"""Framework-aware guard / auth map (sast-improvements-v2 #2).

The IDOR check in controls.py only reads a handler's OWN body, so it misses authorization enforced at the
FRAMEWORK layer -- a global NestJS guard, an Express middleware chain, a FastAPI router dependency. On
OpenWA that produced a false IDOR lead: automation-rule.controller has no inline check, but the global
`ApiKeyGuard` (registered as `APP_GUARD`) scopes `request.params['sessionId']` to the key's
`allowedSessions`. This module finds those guards and tells the IDOR check which routes they cover.

A guard counts as SCOPING -- i.e. it actually prevents cross-object access, not merely authenticates --
only when its body BOTH reads a request/route param AND scopes it to the caller (an allow-list, an owner
id, the current user, a policy/ability check). A role-only guard (`@RequireRole`) or a bare token check is
NOT scoping and does not clear an IDOR. Conservative by design: the dangerous direction is clearing a REAL
IDOR, so coverage is asserted only on strong evidence; an unrecognized framework yields no coverage (the
IDOR check falls back to its existing body-only behavior).

Deterministic, regex over source (no model, no tree-sitter) -- cheap and robust across JS/TS + Python.
"""
from __future__ import annotations

import re
from pathlib import Path

_EXT = (".ts", ".tsx", ".js", ".mjs", ".cjs", ".py")
_SKIP_DIRS = {"node_modules", ".git", "dist", "build", "vendor", "__pycache__", ".venv", "venv"}

# --- scoping evidence: a guard body that reads a request param AND scopes it to the caller ---
_PARAM_READ = re.compile(
    r"request\.params|req\.params|\bparams\s*\[|@Param\b|getParameter\s*\(|request\.user|req\.user|"
    r"path_params|kwargs\.get|request\.path_params")
_SCOPE_OWN = re.compile(
    r"allowedSessions|allowed_sessions|allowedIps|owner[_]?Id|current[_]?[Uu]ser|\breq\.user\b|"
    r"\brequest\.user\b|principal|\btenant|validateApiKey|authorize\s*\(|\bcan\s*\(|\bability\b|"
    r"\bpolicy\b|user[_]?id\b|\bscope[ds]?\b", re.I)

# --- guard / middleware DEFINITIONS ---
_NEST_GUARD_DEF = re.compile(r"class\s+(\w+)\s+implements\s+CanActivate")           # NestJS CanActivate
_EXPRESS_MW_DEF = re.compile(                                                        # (req,res,next) fn
    r"(?:function\s+(\w+)\s*\(|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\()[^;{]*\breq\b[^;{]*"
    r"\bres\b[^;{]*\bnext\b")

# --- GLOBAL application (covers every route) ---
_APP_GUARD = re.compile(r"APP_GUARD[\s\S]{0,120}?useClass\s*:\s*(\w+)|useGlobalGuards\s*\(\s*new\s+(\w+)")
_FASTAPI_GLOBAL = re.compile(r"FastAPI\s*\([^)]*dependencies\s*=\s*\[[^\]]*Depends\s*\(\s*(\w+)")
# --- CLASS / ROUTER level application ---
_USE_GUARDS = re.compile(r"@UseGuards\s*\(\s*([^)]*)\)")                             # NestJS @UseGuards(A, B)
_INCLUDE_ROUTER_DEP = re.compile(r"include_router\s*\([^)]*dependencies\s*=\s*\[[^\]]*Depends\s*\(\s*(\w+)")


def _iter_files(target):
    root = Path(target)
    for p in root.rglob("*"):
        if p.is_dir() or p.suffix.lower() not in _EXT:
            continue
        if set(p.parts) & _SKIP_DIRS:
            continue
        yield p


def _guard_bodies(src):
    """Yield (guard_name, body) for each guard/middleware DEFINITION in a source string. body is the slice
    from the definition to the next top-level `class `/`function ` or EOF -- enough to classify scoping."""
    defs = []
    for m in _NEST_GUARD_DEF.finditer(src):
        defs.append((m.group(1), m.start()))
    for m in _EXPRESS_MW_DEF.finditer(src):
        defs.append((m.group(1) or m.group(2), m.start()))
    defs.sort(key=lambda d: d[1])
    for i, (name, start) in enumerate(defs):
        end = defs[i + 1][1] if i + 1 < len(defs) else len(src)
        # cap the window so one huge file can't bleed one guard's scope into the next
        yield name, src[start:min(end, start + 6000)]


def _is_scoping(body):
    return bool(_PARAM_READ.search(body) and _SCOPE_OWN.search(body))


class GuardMap:
    def __init__(self):
        self.scoping_classes: set[str] = set()      # guard/middleware names whose body SCOPES a resource
        self.all_guard_classes: set[str] = set()    # every guard/middleware we found (scoping or not)
        self.global_scoping = False                 # a scoping guard is applied app-wide (APP_GUARD/global)
        self.class_scoped_files: set[str] = set()   # files whose class-level @UseGuards names a scoping guard

    def covers_idor(self, file: str = "") -> bool:
        """True when a SCOPING guard covers this route's handler -- globally, or via the controller's
        class-level @UseGuards. Such a route's missing INLINE ownership check is not an IDOR gap."""
        if self.global_scoping:
            return True
        return str(file).replace("\\", "/") in self.class_scoped_files

    def why(self, file: str = "") -> str:
        if self.global_scoping:
            names = ", ".join(sorted(self.scoping_classes)) or "a global guard"
            return f"covered by a global scoping guard ({names})"
        if str(file).replace("\\", "/") in self.class_scoped_files:
            return "covered by a class-level @UseGuards scoping guard"
        return ""


def build(target) -> GuardMap:
    """Scan the repo for guard/middleware definitions, classify scoping ones, and record global + class-level
    application. Returns a GuardMap (empty -> no coverage, so callers fall back to body-only detection)."""
    gm = GuardMap()
    files = list(_iter_files(target))
    # pass 1: classify every guard/middleware definition
    for p in files:
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name, body in _guard_bodies(src):
            if not name:
                continue
            gm.all_guard_classes.add(name)
            if _is_scoping(body):
                gm.scoping_classes.add(name)
    # pass 2: find where guards are applied (needs scoping_classes from pass 1)
    for p in files:
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        fp = str(p).replace("\\", "/")
        # global: NestJS APP_GUARD / useGlobalGuards, FastAPI app-level dependency
        for m in _APP_GUARD.finditer(src):
            g = m.group(1) or m.group(2)
            if g in gm.scoping_classes:
                gm.global_scoping = True
        for m in _FASTAPI_GLOBAL.finditer(src):
            if m.group(1) in gm.scoping_classes:
                gm.global_scoping = True
        # class/router level: @UseGuards naming a scoping guard => this file's handlers are covered
        for m in _USE_GUARDS.finditer(src):
            named = set(re.findall(r"\w+", m.group(1)))
            if named & gm.scoping_classes:
                gm.class_scoped_files.add(fp)
    return gm
