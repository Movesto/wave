"""Reproduction-harness scaffold -- the harness owns the GLUE, the model owns the PAYLOAD.

Every model we tried nails exploit payloads but drowns in setup: which module system (ESM/CJS/TS),
require vs import, launching a browser, wiring the async. So the harness writes a ready-to-run probe
into the mounted repo that loads the suspect function CORRECTLY and reports what happened; the model
just runs it with a payload and reads the result. It turns "fight the module loader for 8 steps" into
"supply one payload." The model can still hand-roll its own script -- the scaffold is a fast path, not
a cage.

The JS probe uses dynamic import (handles ESM, CJS interop, and .ts under tsx) and, in `render` mode,
renders the function's output in headless chromium and reports a canary -- the deterministic XSS check.
"""
from pathlib import Path

_JS = '''\
// wave reproduction scaffold: loads the target function, calls it with your payload (argv[2]), reports.
const TARGET = {target!r};
const FUNC = {func!r};
const MODE = {mode!r};                 // "call" (see the return/effect) or "render" (browser XSS check)
const payload = process.argv[2] ?? "";

async function loadFn() {{
  const mod = await import(TARGET);    // dynamic import: works for ESM, CJS interop, and .ts under tsx
  return mod[FUNC] ?? (mod.default && mod.default[FUNC]) ?? mod.default;
}}

(async () => {{
  let fn;
  try {{ fn = await loadFn(); }}
  catch (e) {{ console.log("WAVE_LOAD_ERROR:", e && e.message); process.exit(2); }}
  if (typeof fn !== "function") {{ console.log("WAVE_LOAD_ERROR: not a function:", FUNC); process.exit(2); }}
  if (MODE === "render") {{
    let html;
    try {{ html = String(await fn(payload)); }}
    catch (e) {{ console.log("WAVE_CALL_ERROR:", e && e.message); process.exit(1); }}
    const {{ createRequire }} = await import("module");   // ESM import ignores NODE_PATH -> use require
    const require = createRequire("/opt/wave/_.js");
    const {{ chromium }} = require("playwright");
    const b = await chromium.launch({{ args: ["--no-sandbox"] }});
    const p = await b.newPage();
    await p.setContent(html);
    await new Promise(r => setTimeout(r, 300));
    const hit = await p.evaluate(() => window.__wave || "none");
    console.log("WAVE_RENDER_CANARY:", hit);   // if this equals your canary token, the payload EXECUTED
    console.log("WAVE_OUTPUT:", html.slice(0, 400));
    await b.close();
  }} else {{
    try {{
      const out = await fn(payload);
      console.log("WAVE_RESULT:", typeof out === "string" ? out.slice(0, 800) : JSON.stringify(out).slice(0, 800));
    }} catch (e) {{ console.log("WAVE_CALL_ERROR:", e && e.message); }}
  }}
}})();
'''

_PY = '''\
import sys, importlib.util
sys.path.insert(0, {root!r})
_spec = importlib.util.spec_from_file_location("_wave_t", {target!r})
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
_fn = getattr(_mod, {func!r}, None)
_payload = sys.argv[1] if len(sys.argv) > 1 else ""
if _fn is None:
    print("WAVE_LOAD_ERROR: no function", {func!r}); sys.exit(2)
try:
    print("WAVE_RESULT:", str(_fn(_payload))[:800])
except Exception as _e:
    print("WAVE_CALL_ERROR:", type(_e).__name__, _e)
'''


def _rel(path, target):
    try:
        return str(Path(path).resolve().relative_to(Path(target).resolve())).replace("\\", "/")
    except Exception:
        return Path(path).name


def build(candidate, target, mode="call", workdir="/work"):
    """Write a reproduction scaffold next to the mounted repo (host side); return (container_path,
    run_hint) the model can invoke, or None if we can't scaffold this candidate. Caller must remove()
    it afterwards."""
    func = (getattr(candidate, "unit", "") or "").split("(")[0].strip()
    if not func:
        return None
    path = getattr(candidate, "file", "") or ""
    rel = _rel(path, target)
    mod_c = f"{workdir}/{rel}"
    is_js = path.lower().endswith((".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"))
    root = Path(target)
    if is_js:
        host = root / ".wave_repro.mjs"
        host.write_text(_JS.format(target=mod_c, func=func, mode=mode), encoding="utf-8")
        cont = f"{workdir}/.wave_repro.mjs"
        return cont, f"tsx {cont} '<payload>'"
    if path.lower().endswith(".py"):
        host = root / ".wave_repro.py"
        host.write_text(_PY.format(root=workdir, target=mod_c, func=func), encoding="utf-8")
        cont = f"{workdir}/.wave_repro.py"
        return cont, f"python3 {cont} '<payload>'"
    return None


def remove(target):
    """Delete any scaffold we wrote."""
    for name in (".wave_repro.mjs", ".wave_repro.py"):
        try:
            (Path(target) / name).unlink()
        except OSError:
            pass
