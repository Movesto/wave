"""Route / entrypoint extractor — the SAST->DAST bridge.

Enumerates the app's HTTP attack surface as Route(method, path, file, function) across the
frameworks the MVP targets, and best-effort maps a discovered sink (file, function) to the route
that reaches it. Also exposes the set of handler functions per file so discover.py can seed
handler PARAMETERS as taint sources (framework source coverage).

Deterministic, no model. Light parsers (no yaml dependency).
"""
import re
from pathlib import Path
from dataclasses import dataclass

_SKIP = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "vendor",
         "target", "out", ".next", "coverage"}


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    file: str
    function: str


def _iter(target, exts):
    p = Path(target)
    if p.is_file():
        yield p
        return
    for f in p.rglob("*"):
        if f.suffix.lower() in exts and not any(s in f.parts for s in _SKIP):
            yield f


# ---- Connexion / OpenAPI (VAmPI): paths[*][method].operationId = module.path.func -------------
def _openapi_routes(target):
    routes = []
    for f in _iter(target, {".yml", ".yaml"}):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "paths:" not in text and "operationId" not in text:
            continue
        cur_path, cur_method = None, None
        for line in text.splitlines():
            m = re.match(r"^  (/[^\s:]*):\s*$", line)                 # 2-space indent path key
            if m:
                cur_path, cur_method = m.group(1), None
                continue
            m = re.match(r"^    (get|post|put|delete|patch|options|head):\s*$", line, re.I)
            if m and cur_path:
                cur_method = m.group(1).upper()
                continue
            m = re.search(r"operationId:\s*([\w.]+)", line)
            if m and cur_path and cur_method:
                func = m.group(1).split(".")[-1]
                routes.append(Route(cur_method, cur_path, m.group(1), func))
    return routes


# ---- Express (NodeGoat): app|router.<method>("path", ..., handler) ----------------------------
_EXPRESS = re.compile(
    r"\b(?:app|router|[A-Za-z_$][\w$]*)\.(get|post|put|delete|patch|all)\s*\(\s*"
    r"['\"]([^'\"]+)['\"]\s*,(.+?)\)\s*;?\s*$")


def _express_routes(target):
    routes = []
    for f in _iter(target, {".js", ".mjs", ".ts"}):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            m = _EXPRESS.search(line.strip())
            if not m:
                continue
            method, path, rest = m.group(1).upper(), m.group(2), m.group(3)
            # handler = last `x.y` / bare identifier in the arg list
            h = re.findall(r"([A-Za-z_$][\w$]*)\s*(?:\)|,|$)", rest)
            func = h[-1] if h else ""
            routes.append(Route(method, path, str(f), func))
    return routes


# ---- NestJS (brokencrystals): @Controller('base') + method @Get('sub') ------------------------
_NEST_CTRL = re.compile(r"@Controller\(\s*['\"]?([^'\")]*)['\"]?\s*\)")
_NEST_METH = re.compile(r"@(Get|Post|Put|Delete|Patch)\(\s*['\"]?([^'\")]*)['\"]?\s*\)")


def _nest_routes(target):
    routes = []
    for f in _iter(target, {".ts"}):
        if "controller" not in f.name.lower():
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        base_m = _NEST_CTRL.search(text)
        base = ("/" + base_m.group(1).strip("/")) if base_m and base_m.group(1) else ""
        lines = text.splitlines()
        for i, line in enumerate(lines):
            m = _NEST_METH.search(line)
            if not m:
                continue
            sub = m.group(2).strip("/")
            path = "/".join(x for x in [base.strip("/"), sub] if x)
            path = "/" + path
            # the method name is on this or a following line: `async name(` / `name(`
            func = ""
            for j in range(i, min(i + 4, len(lines))):
                fm = re.search(r"(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(", lines[j])
                if fm and fm.group(1) not in ("Get", "Post", "Put", "Delete", "Patch"):
                    func = fm.group(1)
                    break
            routes.append(Route(m.group(1).upper(), path, str(f), func))
    return routes


# ---- Flask / FastAPI: @app.route|@app.get|@router.post(...) def name(...) ----------------------
_FLASK = re.compile(r"@(?:app|router|bp|blueprint|[\w]+)\.(route|get|post|put|delete|patch)\("
                    r"\s*['\"]([^'\"]+)['\"](?:[^)]*methods\s*=\s*\[([^\]]*)\])?")


def _flask_routes(target):
    routes = []
    for f in _iter(target, {".py"}):
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines):
            m = _FLASK.search(line)
            if not m:
                continue
            verb, path, methods = m.group(1), m.group(2), m.group(3)
            path = re.sub(r"<(?:[^:>]+:)?([A-Za-z_]\w*)>", r"{\1}", path)   # Flask <int:id> / <id> -> {id}
            ms = ([verb.upper()] if verb != "route"
                  else [x.strip().strip("'\"").upper() for x in methods.split(",")] if methods
                  else ["GET"])
            func = ""
            for j in range(i, min(i + 5, len(lines))):
                fm = re.match(r"\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(", lines[j])
                if fm:
                    func = fm.group(1)
                    break
            for mth in ms:
                routes.append(Route(mth, path, str(f), func))
    return routes


def extract_routes(target, profile=None):
    """All routes across supported frameworks (deduped)."""
    routes = []
    for fn in (_openapi_routes, _express_routes, _nest_routes, _flask_routes):
        try:
            routes += fn(target)
        except Exception:
            continue
    seen, out = set(), []
    for r in routes:
        k = (r.method, r.path, r.function)
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out


def handler_functions(routes):
    """Set of handler function names -> used to seed handler params as taint sources."""
    return {r.function for r in routes if r.function}


def route_for(routes, file, function):
    """Best-effort: the route reaching a sink at (file, function). Direct function-name match
    first (NestJS handler sinks), then same-file match. Returns 'METHOD /path' or ''."""
    if function:
        hit = [r for r in routes if r.function == function]
        if hit:
            return f"{hit[0].method} {hit[0].path}"
    base = Path(file).name
    hit = [r for r in routes if Path(r.file).name == base and r.file != r.function]
    if hit:
        return f"{hit[0].method} {hit[0].path}"
    return ""
