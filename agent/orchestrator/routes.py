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
    framework: str = ""            # which extractor produced it -> picks the drive recipe


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


# ---- Rust: Rocket / Actix attribute macros -- #[get("/path")] fn name(...) --------------------
_RUST_ATTR = re.compile(r'#\[\s*(get|post|put|delete|patch|head|options)\s*\(\s*"([^"]*)"')


def _rust_routes(target):
    routes = []
    for f in _iter(target, {".rs"}):
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines):
            m = _RUST_ATTR.search(line)
            if not m:
                continue
            method, path = m.group(1).upper(), "/" + m.group(2).lstrip("/").split("?")[0]
            func = ""
            for j in range(i + 1, min(i + 6, len(lines))):     # `pub async fn name(` on a following line
                fm = re.search(r"\bfn\s+([A-Za-z_]\w*)\s*[(<]", lines[j])
                if fm:
                    func = fm.group(1)
                    break
            routes.append(Route(method, path, str(f), func))
    return routes


# ---- Java: Spring @GetMapping("/sub") + class @RequestMapping("/base") -------------------------
_SPRING_M = re.compile(r'@(Get|Post|Put|Delete|Patch)Mapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?["\']([^"\']*)["\']')
_SPRING_R = re.compile(r'@RequestMapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?["\']([^"\']*)["\']')


def _spring_routes(target):
    routes = []
    for f in _iter(target, {".java"}):
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        rm = _SPRING_R.search("\n".join(lines[:60]))           # class-level base (first @RequestMapping)
        base = ("/" + rm.group(1).strip("/")) if rm and rm.group(1) else ""
        for i, line in enumerate(lines):
            m = _SPRING_M.search(line)
            if not m:
                continue
            sub = m.group(2).strip("/")
            path = "/" + "/".join(x for x in [base.strip("/"), sub] if x)
            func = ""
            for j in range(i + 1, min(i + 5, len(lines))):     # `public X name(` method decl
                fm = re.search(r"\b(?:public|private|protected)\s+[\w<>,\[\]\s.]+?\s+([A-Za-z_]\w*)\s*\(", lines[j])
                if fm:
                    func = fm.group(1)
                    break
            routes.append(Route(m.group(1).upper(), path, str(f), func))
    return routes


# ---- C#: ASP.NET [HttpGet("x")]/[Route("base")] + minimal-api app.MapGet("/x", handler) --------
_CS_HTTP = re.compile(r'\[\s*Http(Get|Post|Put|Delete|Patch)\s*(?:\(\s*"([^"]*)")?')
_CS_ROUTE = re.compile(r'\[\s*Route\s*\(\s*"([^"]*)"')
_CS_MINIMAL = re.compile(r'\.Map(Get|Post|Put|Delete)\s*\(\s*"([^"]*)"')


def _csharp_routes(target):
    routes = []
    for f in _iter(target, {".cs"}):
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        base_m = _CS_ROUTE.search("\n".join(lines[:80]))
        base = ("/" + base_m.group(1).strip("/").replace("[controller]", "")) if base_m else ""
        for i, line in enumerate(lines):
            mm = _CS_MINIMAL.search(line)                      # minimal API
            if mm:
                routes.append(Route(mm.group(1).upper(), "/" + mm.group(2).lstrip("/"), str(f), ""))
                continue
            m = _CS_HTTP.search(line)
            if not m:
                continue
            sub = (m.group(2) or "").strip("/")
            path = "/" + "/".join(x for x in [base.strip("/"), sub] if x)
            func = ""
            for j in range(i + 1, min(i + 5, len(lines))):
                fm = re.search(r"\b(?:public|private|protected|internal)\s+[\w<>,\[\]\s.]+?\s+([A-Za-z_]\w*)\s*\(",
                               lines[j])
                if fm:
                    func = fm.group(1)
                    break
            routes.append(Route(m.group(1).upper(), path, str(f), func))
    return routes


# ---- Go: gin/echo r.GET("/x", h) / chi r.Get(...) / net-http mux.HandleFunc("/x", h) -----------
_GO = re.compile(r"\b\w+\.(GET|POST|PUT|DELETE|PATCH|Get|Post|Put|Delete|Patch|Handle|HandleFunc)\s*"
                 r'\(\s*[`"]([^`"]+)[`"]\s*,\s*(.+?)\)\s*$')


def _go_routes(target):
    routes = []
    for f in _iter(target, {".go"}):
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            m = _GO.search(line.strip())
            if not m:
                continue
            verb = m.group(1).upper()
            if verb in ("HANDLE", "HANDLEFUNC"):
                verb = "ANY"
            h = re.findall(r"([A-Za-z_]\w*)\s*\)?\s*$", m.group(3))
            routes.append(Route(verb, m.group(2), str(f), h[-1] if h else ""))
    return routes


# ---- Ruby (Rails routes.rb) + PHP (Laravel Route::get) -----------------------------------------
_RAILS = re.compile(r"""^\s*(get|post|put|patch|delete)\s+['"]([^'"]+)['"].*?(?:to:\s*['"]([^'"#]+)#(\w+))?""")
_LARAVEL = re.compile(r"""Route::(get|post|put|patch|delete|any)\s*\(\s*['"]([^'"]+)['"]\s*,\s*"""
                      r"""(?:\[\s*[\w\\]+::class\s*,\s*['"](\w+)['"]|['"][\w\\]+@(\w+))""")


def _rails_routes(target):
    routes = []
    for f in _iter(target, {".rb"}):
        if "routes" not in f.name.lower():                     # only the routes DSL file (avoid controller FPs)
            continue
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            m = _RAILS.match(line)
            if m:
                routes.append(Route(m.group(1).upper(), "/" + m.group(2).lstrip("/"), str(f), m.group(4) or ""))
    return routes


def _laravel_routes(target):
    routes = []
    for f in _iter(target, {".php"}):
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            m = _LARAVEL.search(line)
            if m:
                routes.append(Route(m.group(1).upper(), "/" + m.group(2).lstrip("/"), str(f),
                                    m.group(3) or m.group(4) or ""))
    return routes


# ---- FILE-BASED routing (Next.js / SvelteKit / Nuxt): the route PATH comes from the FILE PATH, not a
# decorator. pages/api/users/[id].ts -> /api/users/{id}; app/api/x/route.ts (export GET) -> GET /x; a
# SvelteKit +server.ts / a Nuxt server/api file the same way. This is the modern JS-app attack surface. ----
_FILE_ROUTE_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs")
_HTTP_EXPORT = re.compile(r"export\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b")
_DEFAULT_FN = re.compile(r"export\s+default\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)")


def _seg_route(segs, drop_last_file):
    """Turn path segments into a URL: drop the extension (or the whole filename for route.ts/+server.ts),
    skip `index`/route-groups `(x)`, and map dynamic segments [id]/[...slug]/$id -> {id}/{slug}."""
    segs = list(segs)
    if drop_last_file:
        segs = segs[:-1]
    elif segs:
        for e in _FILE_ROUTE_EXTS:
            if segs[-1].endswith(e):
                segs[-1] = segs[-1][:-len(e)]
                break
    out = []
    for s in segs:
        if s in ("index", "") or (s.startswith("(") and s.endswith(")")):   # index / route group -> not in URL
            continue
        s = re.sub(r"\[\.\.\.([^\]]+)\]", r"{\1}", s)       # [...slug] catch-all
        s = re.sub(r"\[([^\]]+)\]", r"{\1}", s)             # [id] -> {id}
        s = re.sub(r"\$(\w+)", r"{\1}", s)                  # remix-style $id -> {id}
        out.append(s)
    return "/" + "/".join(out)


def _filebased_routes(target):
    """Next.js (pages + app router), SvelteKit, and Nuxt file-based routes. Each Route carries its own
    framework tag (extract_routes keeps it, since this extractor spans several)."""
    routes = []
    for f in _iter(target, set(_FILE_ROUTE_EXTS)):
        parts = [p for p in str(f).replace("\\", "/").split("/") if p]
        if not parts:
            continue
        name, low = parts[-1], [p.lower() for p in parts]
        stem = name.split(".")[0].lower()
        text = None

        def content():
            nonlocal text
            if text is None:
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    text = ""
            return text

        if stem == "route" and "app" in low:               # Next.js APP router: app/.../route.ts
            path = _seg_route(parts[low.index("app") + 1:], drop_last_file=True)
            for m in (_HTTP_EXPORT.findall(content()) or ["ANY"]):
                routes.append(Route(m.upper(), path, str(f), (m if m != "ANY" else ""), "nextjs"))
        elif "pages" in low and low.index("pages") + 1 < len(parts) \
                and parts[low.index("pages") + 1].lower() == "api":     # Next.js PAGES router: pages/api/...
            path = _seg_route(parts[low.index("pages") + 1:], drop_last_file=False)
            m = _DEFAULT_FN.search(content())
            routes.append(Route("ANY", path, str(f), (m.group(1) if m else ""), "nextjs"))
        elif stem == "+server" and "routes" in low:        # SvelteKit: src/routes/.../+server.ts
            path = _seg_route(parts[low.index("routes") + 1:], drop_last_file=True)
            for m in (_HTTP_EXPORT.findall(content()) or ["ANY"]):
                routes.append(Route(m.upper(), path, str(f), (m if m != "ANY" else ""), "sveltekit"))
        elif "server" in low and low.index("server") + 1 < len(parts) \
                and parts[low.index("server") + 1].lower() in ("api", "routes"):   # Nuxt: server/api/...
            path = _seg_route(parts[low.index("server") + 1:], drop_last_file=False)
            routes.append(Route("ANY", path, str(f), "", "nuxt"))
    return routes


_EXTRACTORS = [(_openapi_routes, "openapi"), (_express_routes, "express"), (_nest_routes, "nestjs"),
               (_flask_routes, "flask"), (_rust_routes, "rust"), (_spring_routes, "spring"),
               (_csharp_routes, "aspnet"), (_go_routes, "go"), (_rails_routes, "rails"),
               (_laravel_routes, "laravel"), (_filebased_routes, None)]   # None = keep each route's own framework
# frameworks emitted by the multi-framework file-based extractor (for the drive-recipe coverage check).
_FILE_FRAMEWORKS = ("nextjs", "sveltekit", "nuxt")


def extract_routes(target, profile=None):
    """All routes across supported frameworks (deduped), each tagged with its framework."""
    from dataclasses import replace
    routes = []
    for fn, name in _EXTRACTORS:
        try:
            routes += [(r if name is None else replace(r, framework=name)) for r in fn(target)]
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


# Per-framework "drive the real route" recipe -- how to issue an actual request to a route IN-PROCESS (no
# real server/port), so the model witnesses the attacker value reaching the sink through the framework's
# request handling (Half B), instead of calling the handler positionally (which fails -- handlers read the
# request object, not positional args). {m}=lowercase method, {M}=method, {path}=route path. Model-facing.
DRIVE_RECIPES = {
    "flask": ("Flask:   from <app module> import app; c=app.test_client(); "
              "r=c.{m}('{path}', query_string={{'<param>':'<payload>'}}); print(r.status_code, r.get_data())\n"
              "  FastAPI: from fastapi.testclient import TestClient; from <app module> import app; "
              "c=TestClient(app); r=c.{m}('{path}', params={{'<param>':'<payload>'}}); print(r.status_code, r.text)"),
    "openapi": ("Connexion/OpenAPI (Python): import the Connexion app; its underlying Flask app is `app.app` -- "
                "`c=app.app.test_client(); r=c.{m}('{path}?<param>=<payload>'); print(r.status_code, r.get_data())`."),
    "express": ("Node Express: `const request=require('supertest'); const app=require('<app module>'); "
                "const r=await request(app).{m}('{path}').query({{'<param>':'<payload>'}}); console.log(r.status, r.text)` "
                "(supertest needs no listening port). If the app isn't exported, call the handler with a mock "
                "req/res: `handler({{query:{{...}}, params:{{...}}, body:{{...}}}}, mockRes)`."),
    "nestjs": ("NestJS: bootstrap a testing module (`Test.createTestingModule({{imports:[AppModule]}})`) + supertest "
               "against the app, {M} {path}; or instantiate the controller and call the handler method with the "
               "crafted argument (a DTO/param object)."),
    "spring": ("Java Spring: MockMvc -- `mockMvc.perform({m}(\"{path}\").param(\"<name>\",\"<payload>\"))` under "
               "@WebMvcTest/@SpringBootTest; or instantiate the @Controller and call the handler method directly "
               "with the crafted argument."),
    "aspnet": ("ASP.NET: `WebApplicationFactory<Program>` / TestServer -- "
               "`factory.CreateClient().GetAsync(\"{path}?<param>=<payload>\")`; or call the controller action "
               "method directly with the crafted argument."),
    "go": ("Go: `req := httptest.NewRequest(\"{M}\", \"{path}?<param>=<payload>\", body); w := httptest.NewRecorder(); "
           "router.ServeHTTP(w, req); fmt.Println(w.Code, w.Body.String())` (or call the handler func directly)."),
    "rails": ("Rails: an integration test -- `{m} \"{path}\", params: {{'<param>'=>'<payload>'}}` -- or instantiate "
              "the controller and call the action."),
    "laravel": ("Laravel/PHP: a feature test -- `$this->{m}('{path}?<param>=<payload>')` through the HTTP kernel; "
                "or call the controller method with a crafted Request."),
    "rust": ("Rust actix: `let req = test::TestRequest::{m}().uri(\"{path}?<param>=<payload>\").to_request(); "
             "let resp = test::call_service(&app, req).await;` -- Rocket: "
             "`let client = Client::tracked(rocket()).unwrap(); client.{m}(\"{path}?<param>=<payload>\").dispatch()`."),
    "nextjs": ("Next.js API route ({M} {path}). PAGES router (export default handler): mock req/res -- "
               "`const {{createMocks}}=require('node-mocks-http'); const h=require('<this file>').default; "
               "const {{req,res}}=createMocks({{method:'{M}', query:{{'<param>':'<payload>'}}, body:{{}}}}); "
               "await h(req,res); console.log(res._getStatusCode(), res._getData());`  APP router (export "
               "{M}): call it with a Request -- `const {{{M}}}=require('<this file>'); const r=await {M}(new "
               "Request('http://x{path}?<param>=<payload>')); console.log(r.status, await r.text());`"),
    "sveltekit": ("SvelteKit +server.ts (export {M}): import the handler and call it with a mock RequestEvent -- "
                  "`const {{{M}}}=require('<this file>'); const r=await {M}({{ url:new URL('http://x{path}?"
                  "<param>=<payload>'), request:new Request('http://x{path}'), params:{{}} }}); "
                  "console.log(r.status, await r.text());`"),
    "nuxt": ("Nuxt server route ({path}, defineEventHandler): import the handler and call it with a mock H3 "
             "event carrying the query/body, then read the returned value -- adapt to the handler's signature."),
}


def drive_recipe(route):
    """The framework-specific 'drive the real route' recipe for a Route, or '' if the framework is unknown."""
    tpl = DRIVE_RECIPES.get(getattr(route, "framework", "") or "")
    if not tpl:
        return ""
    return tpl.format(m=(route.method or "get").lower(), M=(route.method or "GET"), path=route.path)


def find_route(routes, file, function):
    """The Route object reaching a sink at (file, function). EXACT file path first (file-based routing: the
    route IS the file, and basenames like `route.ts`/`index.ts` collide across dirs), then function-name
    (decorated handlers), then basename. Returns the Route (method/path/framework) or None."""
    nf = str(file or "").replace("\\", "/")
    exact = [r for r in routes if str(r.file or "").replace("\\", "/") == nf]
    if exact:
        return exact[0]
    if function:
        hit = [r for r in routes if r.function == function]
        if hit:
            return hit[0]
    base = Path(file).name
    hit = [r for r in routes if Path(r.file).name == base and r.file != r.function]
    return hit[0] if hit else None


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
