"""Shared brief/scaffold helpers for the investigation loop -- extracted so BOTH the legacy `state.py`
run_loop AND the new Stage-3 `prove.py` can build the model's investigation brief WITHOUT importing
`state` (whose top-level pulls the whole legacy graph: discover, provision, oracle, bizlogic, browser...).

Pure and dependency-light on purpose: only stdlib + a duck-typed `candidate` (needs .file/.line/.unit/
.cwe/.family/.sink). No model, no docker, no tree-sitter at import.
"""
from pathlib import Path


def _code_window(path, line, ctx=22):
    """Line-numbered source around the candidate's sink -- the code the model investigates."""
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    lo, hi = max(0, (line or 1) - 1 - ctx), min(len(lines), (line or 1) + ctx)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(lo, hi))


def _rel(path, target):
    try:
        return str(Path(path).resolve().relative_to(Path(target).resolve())).replace("\\", "/")
    except Exception:
        return Path(path).name


def _is_js(path):
    return (path or "").lower().endswith((".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"))


_XSS_CWES = {"CWE-79", "CWE-80", "CWE-83", "CWE-116"}   # classes that need a real browser to PROVE (render + observe)


def _image_for(path):
    """A runtime image that can run this candidate's language (the model can install more if it needs)."""
    if _is_js(path):
        return "node:20-slim"
    p = (path or "").lower()
    if p.endswith(".php"):
        return "php:8.2-cli"
    if p.endswith(".rb"):
        return "ruby:3-slim"
    if p.endswith(".go"):
        return "golang:1-alpine"
    return "python:3.12-slim"


def _brief_for(candidate, target, reason, scaffold=None, mode="call"):
    rel = _rel(candidate.file, target)
    code = _code_window(candidate.file, getattr(candidate, "line", 0))
    fn = str(candidate.unit).split("(")[0].strip()
    extra = ""
    if scaffold:
        cont, run_hint = scaffold
        if mode == "render":
            ex = run_hint.replace("<payload>", "<img src=x onerror=window.__wave=1>")
            extra = (f"\nA reproduction scaffold is ready at {cont} -- it loads this module, calls "
                     f"{fn}(YOUR_PAYLOAD), renders the output in headless chromium, and prints "
                     f"WAVE_RENDER_CANARY and WAVE_OUTPUT. Use this EXACT canary payload (no quotes, so the "
                     f"shell can't mangle it, and an event handler because setContent won't run <script>):"
                     f"\n  {ex}\n"
                     f"If WAVE_RENDER_CANARY prints 1, the payload EXECUTED -> conclude confirmed. If it "
                     f"prints 'none', LOOK AT WAVE_OUTPUT: if your <img tag appears RAW/unescaped there, the "
                     f"output IS reflected unescaped = still XSS (the canary just misfired -- that is enough "
                     f"to confirm). Only conclude refuted if WAVE_OUTPUT shows it ESCAPED (e.g. &lt;img). "
                     f"Supply ONLY the payload; the scaffold owns the browser/module glue.")
        else:
            extra = (f"\nA reproduction scaffold is ready at {cont} -- it loads this module and calls "
                     f"{fn}(ARG), printing WAVE_RESULT + WAVE_CALL_ERROR. The ARG is parsed as JSON if it can "
                     f"be, so the taint can flow through a PROPERTY -- match the function's signature:\n"
                     f"  - takes a string:  {run_hint.replace('<payload>', '; id')}\n"
                     f"  - takes an object: {run_hint.replace('<payload>', chr(39) + '{{\"path\": \"; id\"}}' + chr(39))}\n"
                     f"  - takes a URL:     pass {chr(39)}{{\"href\":\"https://x/; id\",\"hash\":\"\",\"search\":\"\","
                     f"\"pathname\":\"/x\"}}{chr(39)}\n"
                     f"For OS-command injection the injected command's output is often NOT returned -- inject a "
                     f"MARKER side effect into /work (which persists; each command runs in a fresh container so "
                     f"/tmp does NOT persist). Best: do it in ONE command, e.g. run the scaffold with a payload "
                     f"like `; touch /work/wave_HIT` then `; sleep 1; ls -l /work/wave_HIT` appended -- if the "
                     f"file exists it executed = confirmed. For SQLi/path/etc. read "
                     f"WAVE_RESULT. Supply ONLY the arg; the scaffold owns the module-loading glue. You may still "
                     f"write your own script if it doesn't fit.")
    elif candidate.cwe in _XSS_CWES:
        extra = (
            "\nThis is a possible XSS. A headless browser is available. To PROVE it, RENDER the vulnerable "
            "output with a CANARY payload and check whether it EXECUTED as script. Here is a COMPLETE, "
            "WORKING script -- write it to a file and run `node /tmp/x.js`, only adapting (a) the require "
            "path/module system, (b) which function you call to build the output, (c) the payload:\n"
            "```js\n"
            "const { chromium } = require('playwright');\n"
            "const mod = require('/work/" + rel + "');   // if it uses `export`, use `await import(...)` instead\n"
            "(async () => {\n"
            "  const html = mod." + str(candidate.unit).split('(')[0].strip() + "('<img src=x onerror=\"window.__wave=1\">');  // build output WITH the payload\n"
            "  const b = await chromium.launch({ args: ['--no-sandbox'] });\n"
            "  const p = await b.newPage();\n"
            "  await p.setContent(String(html));\n"
            "  await new Promise(r => setTimeout(r, 300));\n"
            "  console.log('CANARY:', await p.evaluate(() => window.__wave || 'none'));\n"
            "  await b.close();\n"
            "})();\n"
            "```\n"
            "If CANARY prints 1, the payload EXECUTED -> conclude confirmed (evidence: the canary fired). "
            "If it prints 'none' (the output was escaped), the code is safe -> conclude refuted. The repo's "
            "node_modules and tsx are installed; write the script to a file to avoid shell-quoting issues.")
    elif _is_js(candidate.file):
        extra = ("\nThis is JavaScript/TypeScript. `tsx` is installed: run a .ts file or inline TS with "
                 "`tsx -e \"...\"` or `tsx <file>.ts`; the repo's node_modules ARE installed so its "
                 "require/import dependencies resolve. Load the exported function and call it with your "
                 "payload (e.g. `node -e \"require('/work/app').f('; id')\"` or the tsx equivalent).")
    return (f"File: {rel} (mounted at /work/{rel}). Function: {candidate.unit}.\n"
            f"Suspected {candidate.cwe} ({candidate.family}); sink: {candidate.sink}.\n"
            f"A quick automatic check was inconclusive ({reason}).\n\nCode around the sink:\n{code}\n\n"
            f"The whole repository is mounted at your working directory (/work). Prove or refute whether "
            f"this is a REAL, exploitable {candidate.cwe} by running code.{extra}")
