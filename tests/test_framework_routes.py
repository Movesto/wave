"""Framework-aware route normalization: modern JS frameworks register HTTP handlers with NO decorator --
by file convention + export name. The decorator/callback _ROUTE patterns miss them entirely, which is the
Next.js App-Router blind spot (an `export async function POST()` in a route.ts was never seen as an entry).
These lock in that such handlers now (a) pin as ROUTES so the file is selected, and (b) count as REMOTE
entries so reachability ranks them -- without false-flagging a lowercase `get`/`getUser` getter."""
from pathlib import Path

from agent.orchestrator import repomap, reachability, routes
from agent.orchestrator.codemap import Func, FileInfo


def _routes(src, name="route.ts", lang="typescript"):
    import tempfile, os
    d = tempfile.mkdtemp()
    p = os.path.join(d, name)
    Path(p).write_text(src, encoding="utf-8")
    finfo = FileInfo(path=p, lang=lang)
    routes, _sinks, _dyn = repomap.scan_pins(finfo)
    return routes


# -------------------------------------------------- route pins (scan_pins) --------------------------------

def test_app_router_method_export_pins_as_route():
    routes = _routes("export async function POST(req) {\n  return handle(req)\n}\n")
    assert routes, "an App-Router `export async function POST(` must pin as a ROUTE"


def test_app_router_arrow_export_pins_as_route():
    routes = _routes("export const GET = async (req) => json(req)\n")
    assert routes, "the arrow-assigned `export const GET =` handler must pin as a ROUTE"


def test_server_actions_directive_pins_as_route():
    routes = _routes("'use server'\nexport async function updateProfile(data) { save(data) }\n")
    assert routes, "a `'use server'` directive must mark the file as a server entry surface"


def test_remix_loader_pins_as_route():
    routes = _routes("export async function loader({ request }) { return fetchData(request) }\n")
    assert routes, "a Remix `export async function loader(` must pin as a ROUTE"


def test_plain_lowercase_getter_is_not_a_route():
    # `export function get(...)` / a camelCase getter is NOT a route -- no over-pinning.
    assert not _routes("export function get(id) { return store[id] }\n")
    assert not _routes("export function getUser(id) { return store[id] }\n")


# -------------------------------------------------- entry trust (reachability) ----------------------------

def test_entry_trust_recognizes_uppercase_method_export():
    assert reachability.entry_trust(Func(name="GET", file="route.ts", line=1, exported=True)) == "remote"
    assert reachability.entry_trust(Func(name="POST", file="route.ts", line=1)) == "remote"  # trusted w/o export flag


def test_entry_trust_ignores_lowercase_getter():
    assert reachability.entry_trust(Func(name="get", file="svc.ts", line=1, exported=True)) is None
    assert reachability.entry_trust(Func(name="getUser", file="svc.ts", line=1, exported=True)) is None


def test_entry_trust_framework_export_requires_export_flag():
    assert reachability.entry_trust(Func(name="loader", file="r.tsx", line=1, exported=True)) == "remote"
    assert reachability.entry_trust(Func(name="loader", file="x.ts", line=1, exported=False)) is None


# -------------------------------------------------- end-to-end selection ----------------------------------

def test_build_map_selects_and_ranks_route_file(tmp_path):
    (tmp_path / "route.ts").write_text(
        "export async function POST(req) {\n"
        "  const body = await req.json()\n"
        "  return require('child_process').execSync(body.cmd)\n"
        "}\n", encoding="utf-8")
    (tmp_path / "util.ts").write_text(
        "export function helper(x){ return require('child_process').execSync(x) }\n", encoding="utf-8")
    res = repomap.build_map(str(tmp_path), out=str(tmp_path / "m.md"))
    names = [Path(p).name for p in res["pinned"]]
    assert "route.ts" in names, "the App-Router route file must be selected"
    assert names.index("route.ts") < names.index("util.ts"), f"route (entry+sink) should rank first; {names}"


# -------------------------------------------------- chained multi-line JS routes (Hono/opencode) ----------
# A big server file declares many routes as CHAINED, multi-line `.post(\n "path",\n ...,\n handler\n)` blocks.
# The single-line _EXPRESS regex sees none of them, and an inline arrow handler has no name to map a sink to.
# The route is DECLARED in the project's own source -- the extractor must read it, and find_route must place a
# sink INSIDE one handler on the RIGHT route (by line span), not the first route in the file.
_CHAINED_SERVER = '''\
const app = new Hono()
  .get(
    "/health",
    (c) => c.json({ ok: true }),
  )
  .post(
    "/session/:sessionID/shell",
    validator("json", ShellInput),
    async (c) => {
      const body = c.req.valid("json")
      const msg = await SessionPrompt.shell({ ...body })
      return c.json(msg)
    },
  )
  .get(
    "/session/:sessionID/messages",
    (c) => c.json(list()),
  )
'''


def test_chained_multiline_route_is_extracted(tmp_path):
    f = tmp_path / "server.ts"
    f.write_text(_CHAINED_SERVER, encoding="utf-8")
    rs = routes.extract_routes(str(tmp_path))
    paths = {(r.method, r.path) for r in rs}
    assert ("POST", "/session/:sessionID/shell") in paths, f"chained .post route must extract; got {paths}"
    shell = next(r for r in rs if r.path == "/session/:sessionID/shell")
    assert shell.line < shell.end and shell.framework == "hono"   # carries a span + framework


def test_find_route_places_inline_sink_on_the_right_route(tmp_path):
    f = tmp_path / "server.ts"
    f.write_text(_CHAINED_SERVER, encoding="utf-8")
    rs = routes.extract_routes(str(tmp_path))
    sink_line = _CHAINED_SERVER.splitlines().index(
        "      const msg = await SessionPrompt.shell({ ...body })") + 1
    r = routes.find_route(rs, str(f), "", line=sink_line)
    assert r is not None and r.path == "/session/:sessionID/shell", \
        f"a sink inside the shell handler must map to that route, not the first in the file; got {r}"


def test_single_line_route_still_owned_by_express(tmp_path):
    # a classic single-line express route must NOT be duplicated by the multi-line extractor
    (tmp_path / "app.js").write_text('app.get("/u", getUser)\n', encoding="utf-8")
    rs = [r for r in routes.extract_routes(str(tmp_path)) if r.path == "/u"]
    assert len(rs) == 1 and rs[0].function == "getUser"
