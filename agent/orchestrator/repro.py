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
  // fast path: a named export, a property of the default export, or the default export itself.
  const direct = mod[FUNC] ?? (mod.default && mod.default[FUNC]) ?? mod.default;
  if (typeof direct === "function") return direct;
  // deep path: FUNC is often a METHOD nested inside an exported object or a factory-built instance
  // (e.g. `export const X = Node.create({{ method(){{}} }})`, a class prototype, a registry object).
  // Walk the export graph (bounded depth + a visited set for cycles) for a function property named
  // FUNC and bind it so its `this` stays the owning object. Runs only when the fast path missed, so it
  // never changes behaviour for a normally-exported function.
  const seen = new Set();
  const stack = Object.keys(mod).map(k => [mod[k], 0]);
  if (mod.default && typeof mod.default === "object") stack.push([mod.default, 0]);
  while (stack.length) {{
    const [val, depth] = stack.pop();
    if (val == null || depth > 5) continue;
    const t = typeof val;
    if (t !== "object" && t !== "function") continue;
    if (seen.has(val)) continue;
    seen.add(val);
    let f;
    try {{ f = val[FUNC]; }} catch (e) {{ f = undefined; }}   // a getter may throw
    if (typeof f === "function") return f.bind(val);
    let keys = [];
    try {{ keys = Object.keys(val); }} catch (e) {{ keys = []; }}
    for (const k of keys) {{
      let child;
      try {{ child = val[k]; }} catch (e) {{ continue; }}
      const ct = typeof child;
      if (child != null && (ct === "object" || ct === "function")) stack.push([child, depth + 1]);
    }}
  }}
  return undefined;
}}

(async () => {{
  let fn;
  try {{ fn = await loadFn(); }}
  catch (e) {{ console.log("WAVE_LOAD_ERROR:", e && e.message); process.exit(2); }}
  if (typeof fn !== "function") {{
    console.log("WAVE_LOAD_ERROR:", FUNC, "could not be loaded as a callable (it is likely a method nested",
      "in a factory/class config the scaffold cannot reach, or needs constructor args). This is a SCAFFOLD",
      "limitation, NOT evidence the code is safe. WRITE YOUR OWN short repro: import", TARGET + ",",
      "construct/obtain the object, invoke the sink directly with a crafted payload, and observe the effect.",
      "Do NOT conclude 'unproven'/'refuted' just because this fast-path scaffold could not load it.");
    process.exit(2);
  }}
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
    // the arg may be a JSON value (object/array/string) so the taint can flow through a PROPERTY
    // (e.g. {{"path":"; id"}} or a URL-like {{"href":"https://x/; id","hash":"","search":"","pathname":"/x"}});
    // if it isn't valid JSON, treat it as a raw string (fn("; id")).
    let arg;
    try {{ arg = JSON.parse(payload); }} catch {{ arg = payload; }}
    try {{
      const out = await fn(arg);
      console.log("WAVE_RESULT:", typeof out === "string" ? out.slice(0, 800) : JSON.stringify(out).slice(0, 800));
    }} catch (e) {{ console.log("WAVE_CALL_ERROR:", e && e.message); }}
  }}
}})();
'''

_PY = '''\
import sys, json, importlib.util
sys.path.insert(0, {root!r})
_spec = importlib.util.spec_from_file_location("_wave_t", {target!r})
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
_fn = getattr(_mod, {func!r}, None)
if not callable(_fn):
    # deep path: FUNC may be a METHOD defined on a class in this module, not a top-level function.
    # Restrict to methods actually declared on a module-level class (via __dict__) so we never grab an
    # unrelated builtin attribute that happens to share the name. Runs only when the top-level lookup missed.
    import inspect as _inspect
    for _name, _obj in list(vars(_mod).items()):
        if _inspect.isclass(_obj):
            _cand = _obj.__dict__.get({func!r})
            if callable(_cand):
                _fn = _cand
                break
_payload = sys.argv[1] if len(sys.argv) > 1 else ""
try:            # JSON arg lets the taint flow through a property (e.g. {{"cmd":"; id"}}); else raw string
    _arg = json.loads(_payload)
except Exception:
    _arg = _payload
if not callable(_fn):
    print("WAVE_LOAD_ERROR:", {func!r}, "could not be loaded as a callable -- it may be a method needing an "
          "instance/args, or built dynamically. This is a SCAFFOLD limitation, NOT evidence the code is safe. "
          "WRITE YOUR OWN short repro: import the module, construct the object, call the sink with a crafted "
          "payload, and observe. Do NOT conclude 'unproven'/'refuted' just because this scaffold could not load it.")
    sys.exit(2)
try:
    print("WAVE_RESULT:", str(_fn(_arg))[:800])
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
    """Delete any scaffold we wrote, plus any files the MODEL authored via write_file (recorded in the
    .wave_written.txt manifest) so the target repo is left pristine."""
    root = Path(target)
    for name in (".wave_repro.mjs", ".wave_repro.py"):
        try:
            (root / name).unlink()
        except OSError:
            pass
    manifest = root / ".wave_written.txt"
    try:
        rels = manifest.read_text(encoding="utf-8").splitlines()
    except OSError:
        rels = []
    for rel in rels:
        rel = rel.strip()
        if not rel:
            continue
        try:                                                # stay inside the target; never delete outside it
            p = (root / rel).resolve()
            p.relative_to(root.resolve())
            p.unlink()
        except (OSError, ValueError):
            pass
    try:
        manifest.unlink()
    except OSError:
        pass
