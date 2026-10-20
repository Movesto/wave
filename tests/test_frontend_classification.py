"""Server files must NOT be misclassified as frontend -- that suppresses their server-only sinks (ssrf/crlf/
sql/...), which is the dangerous direction. Regression for a real miss: next.js `src/server/app-render/
action-handler.ts` imports `react-server-dom-webpack/server` + `next/dist/...`, which the framework-import
heuristic read as 'frontend', dropping its two SSRF `fetch()` sinks so the file never pinned."""
from pathlib import Path

from agent.orchestrator import reachability as R, repomap
from agent.orchestrator.codemap import FileInfo


# -------------------------------------------------- is_frontend --------------------------------------------

def test_server_dir_overrides_isomorphic_framework_import():
    # the exact shape of the miss: a .ts under server/ importing React's SERVER build + a next server module
    assert R.is_frontend("packages/next/src/server/app-render/action-handler.ts",
                         imports=["react-server-dom-webpack/server", "next/dist/compiled/busboy"]) is False


def test_backend_dir_overrides_react_import():
    assert R.is_frontend("api/backend/user-service.ts", imports=["react"]) is False


def test_server_entrypoint_import_is_not_a_frontend_signal():
    # react-dom/server is server code shipped by an isomorphic package; alone it must not mark a file frontend
    assert R.is_frontend("lib/render-to-html.ts", imports=["react-dom/server"]) is False


def test_real_client_code_is_still_frontend():
    # positive controls -- the fix must not under-detect genuine browser code
    assert R.is_frontend("src/components/Button.tsx") is True                     # JSX
    assert R.is_frontend("client/app.ts", imports=["react"]) is True              # frontend dir
    assert R.is_frontend("src/widgets/chart.ts", imports=["vue"]) is True            # bare framework import
    assert R.is_frontend("src/ui/store.ts", source="window.localStorage.getItem('x')") is True  # browser global


# -------------------------------------------------- end to end through scan_pins ---------------------------

def _sinks(tmp_path, subdir, name="handler.ts"):
    d = tmp_path / subdir
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_text("export async function POST(req) {\n"
                 "  const url = req.body.target\n"
                 "  const res = await fetch(url)\n"      # server-only ssrf sink
                 "  return res\n"
                 "}\n", encoding="utf-8")
    finfo = FileInfo(path=str(p), lang="typescript")
    _routes, sinks, _dyn = repomap.scan_pins(finfo)
    return [lbl for _ln, lbl, _c in sinks]


def test_fetch_pins_as_ssrf_under_server_dir(tmp_path):
    labels = _sinks(tmp_path, "server/app-render")
    assert "ssrf" in labels, "a server-side fetch() must pin as SSRF, not be suppressed as frontend"


def test_fetch_is_suppressed_under_client_dir(tmp_path):
    labels = _sinks(tmp_path, "client/pages")
    assert "ssrf" not in labels, "a browser fetch() is not SSRF -- still suppressed in frontend code"
