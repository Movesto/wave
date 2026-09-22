"""Shared brief/scaffold helpers for the investigation loop -- extracted so BOTH the legacy `state.py`
run_loop AND the new Stage-3 `prove.py` can build the model's investigation brief WITHOUT importing
`state` (whose top-level pulls the whole legacy graph: discover, provision, oracle, bizlogic, browser...).

Pure and dependency-light on purpose: only stdlib + a duck-typed `candidate` (needs .file/.line/.unit/
.cwe/.family/.sink). No model, no docker, no tree-sitter at import.
"""
import re
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
# CWE-639 (IDOR) / CWE-284/862/863 (broken access control) -> the differential/state observer: a no-sink
# class proven behaviourally (run as user A requesting user B's resource, observe the crossed boundary).
_MODE_BY_CWE = {"CWE-1336": "ssti", "CWE-94": "ssti", "CWE-1321": "protopoll", "CWE-502": "deser",
                "CWE-639": "differential", "CWE-284": "differential", "CWE-862": "differential",
                "CWE-863": "differential", "CWE-566": "differential"}
_C_EXTS = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx")
# C/C++ memory-safety / format-string: compile with AddressSanitizer + UBSan and let the SANITIZER be the
# observer (a crafted input that trips ASan = a witnessed, near-zero-FP memory-safety proof, like a fuzzer).
_ASAN_CWE = {"CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125", "CWE-134", "CWE-787", "CWE-190", "CWE-416"}
# ...and the sink FUNCTIONS themselves -- so a C/C++ finding routes to asan even when the notebook mislabels
# its class (e.g. `other`) and no CWE survives. The sink text is the reliable signal for memory bugs.
_ASAN_SINKS = re.compile(r"\b(strcpy|strcat|stpcpy|sprintf|vsprintf|gets|memcpy|memmove|memset|alloca|"
                         r"strncpy|strncat|scanf|sscanf|realloc|malloc|free|wcscpy|wcscat)\b|"
                         r"\b(printf|fprintf|snprintf|syslog)\s*\(\s*\w+\s*\)")


def _is_c(path):
    return (path or "").lower().endswith(_C_EXTS)


def _is_rust(path):
    return (path or "").lower().endswith(".rs")


# other COMPILED languages that (like Rust) can't be imported+called -- each gets a minimal build-and-run
# repro recipe. ext -> proof mode.
_COMPILED_MODE = {".go": "go", ".java": "java", ".cs": "dotnet",
                  ".kt": "kotlin", ".kts": "kotlin", ".swift": "swift", ".scala": "scala", ".sc": "scala",
                  ".ex": "elixir", ".exs": "elixir", ".sh": "bash", ".bash": "bash", ".lua": "lua",
                  ".hs": "haskell", ".dart": "dart", ".pl": "perl", ".pm": "perl",
                  ".rb": "ruby", ".php": "php"}


def _compiled_mode_for(path):
    p = (path or "").lower()
    for ext, mode in _COMPILED_MODE.items():
        if p.endswith(ext):
            return mode
    return None


def _proof_mode(candidate):
    """Pick the investigate proof shape for a candidate: asan (C/C++ compile+sanitizer) > rust (cargo repro)
    > go/java/dotnet (compile+run repro) > sanitizer (return-value) > per-class brief (ssti/protopoll/deser)
    > render (DOM XSS) > call (default). Used by prove and patch so scaffold, image, and brief stay consistent."""
    cwe = getattr(candidate, "cwe", "") or ""
    file = getattr(candidate, "file", "")
    if _is_c(file) and (cwe in _ASAN_CWE or _ASAN_SINKS.search(getattr(candidate, "sink", "") or "")):
        return "asan"
    if _is_rust(file):                                     # Rust: compile a minimal cargo repro + run it
        return "rust"
    cm = _compiled_mode_for(file)                          # Go / Java / C#: compile a minimal repro + run it
    if cm:
        return cm
    if _is_sanitizer(candidate):
        return "sanitizer"
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
                     (".kt", "zenika/kotlin"), (".kts", "zenika/kotlin"), (".swift", "swift:5.10"),
                     (".scala", "virtuslab/scala-cli"), (".sc", "virtuslab/scala-cli"),
                     (".ex", "elixir:latest"), (".exs", "elixir:latest"), (".sh", "bash:5"),
                     (".bash", "bash:5"), (".lua", "nickblah/lua:5.4"), (".hs", "haskell:latest"),
                     (".dart", "dart:stable"), (".pl", "perl:latest"), (".pm", "perl:latest"),
                     (".cc", "gcc:13"), (".cpp", "gcc:13"), (".cxx", "gcc:13"), (".hpp", "gcc:13"),
                     (".hh", "gcc:13"), (".hxx", "gcc:13"), (".c", "gcc:13"), (".h", "gcc:13")):
        if p.endswith(ext):
            return img
    return "python:3.12-slim"


def _asan_brief(candidate, target, rel, code, fn):
    """C/C++ memory-safety proof: the model writes a self-contained PoC, compiles it with AddressSanitizer +
    UBSan, and runs it -- the SANITIZER is the observer (a report = a witnessed, near-zero-FP proof)."""
    cxx = rel.lower().endswith((".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"))
    cc = "g++" if cxx else "gcc"
    ext = "cpp" if cxx else "c"
    return (
        f"File: {rel}. Function: {candidate.unit}. Suspected {candidate.cwe} ({candidate.family}); "
        f"sink: {candidate.sink}.\n\nCode around the sink:\n{code}\n\n"
        f"This is a C/C++ MEMORY-SAFETY / format-string finding. PROVE it with AddressSanitizer -- the "
        f"compiler's own bug detector -- as the witness (a fuzzer-grade, near-zero-false-positive oracle). "
        f"The repo is mounted at /work. Steps:\n"
        f"1. Write a SELF-CONTAINED proof-of-concept at /work/wave_poc.{ext}: include or COPY the vulnerable "
        f"function `{fn}` (and only the minimal declarations/types it needs -- stub anything external), and a "
        f"main() that calls it with a CRAFTED input that should trip the bug (an oversized buffer for an "
        f"overflow, e.g. a 500-char string; a user-controlled format string like \"%n%n%s%s\" for a format "
        f"bug; a negative/huge size for an integer/alloc bug).\n"
        f"2. Compile WITH the sanitizers:\n"
        f"   {cc} -fsanitize=address,undefined -g -w /work/wave_poc.{ext} -o /work/wave_poc\n"
        f"   (if it won't compile standalone, copy in the missing struct/typedef/#define -- keep the "
        f"vulnerable line identical; you only need it to build, not to be the whole program.)\n"
        f"3. Run it:  /work/wave_poc <your crafted arg>   (also try a SHORT/benign arg as a control).\n"
        f"CONFIRMED if the run prints an `ERROR: AddressSanitizer:` report (heap/stack/global-buffer-overflow, "
        f"use-after-free, ...) or a `runtime error:` from UBSan on the crafted input but NOT on the benign one "
        f"-- cite that exact report line as the evidence. REFUTED if both inputs run clean (a real guard: a "
        f"bounds check, strncpy with a correct size, snprintf, a length validation). If you truly cannot get "
        f"a standalone PoC to compile after trying, conclude 'blocked'. Do NOT conclude confirmed without an "
        f"actual sanitizer report.")


def _rust_brief(candidate, target, rel, code, fn):
    """Rust proof: a Rust function can't be imported+called like Python -- it must be COMPILED. So stand up a
    minimal cargo project, copy the vulnerable logic in, `cargo add` any crates it uses (network for the build
    only), and RUN it with a crafted vs. benign input. The WITNESS is an observed runtime effect: a panic
    (`.unwrap()`/index/slice on bad input = a real DoS), an `overflow` abort, a marker side-effect for a
    Command/shell sink, or traversal reaching outside the intended dir -- the Rust analogue of the ASan report."""
    return (
        f"File: {rel}. Function: {candidate.unit}. Suspected {candidate.cwe} ({candidate.family}); "
        f"sink: {candidate.sink}.\n\nCode around the sink:\n{code}\n\n"
        f"This file is `{rel}` -- it is RUST (a `.rs` file), NOT any other language; do not second-guess this or "
        f"go looking for another compiler. You cannot import+call it like Python; you must COMPILE a minimal repro "
        f"and RUN it with cargo. "
        f"The repo is mounted at /work (read it for the exact logic/types). Because EACH command runs in a "
        f"FRESH container, do the WHOLE repro in ONE command, and use network 'host' on that command so cargo "
        f"can fetch crates (set image rust:1-slim). Recipe:\n"
        f"1. `export CARGO_HOME=/wave_deps/cargo` (persists the crate cache across your attempts), then "
        f"`cd /tmp && cargo new --quiet wave_poc && cd wave_poc`.\n"
        f"2. Put the vulnerable logic of `{fn}` into src/main.rs -- COPY it verbatim (keep the suspect line "
        f"identical: the `.unwrap()`, the index, the arithmetic, the Command/format string). Stub only what "
        f"you must to compile. `cargo add <crate>` for any external crate it uses (e.g. chrono, regex).\n"
        f"3. Write `fn main()` that calls it TWICE and prints a label before each: a CRAFTED malicious input, "
        f"then a BENIGN control. Choose the payload by class:\n"
        f"   - panic / .unwrap() / index / slice (DoS): an input that makes it panic (e.g. a non-parsing "
        f"string for parse+unwrap, an out-of-range index). WITNESS = `thread '...' panicked at ...` on the "
        f"crafted input but NOT the benign one.\n"
        f"   - integer overflow (CWE-190): a value that overflows; a debug build aborts with `attempt to "
        f"... with overflow` = the witness.\n"
        f"   - command injection (CWE-78): if it builds a shell string for std::process::Command, inject "
        f"`; touch /tmp/wave_HIT` and, in the SAME command afterwards, `ls -l /tmp/wave_HIT` -- the file "
        f"existing is the witness.\n"
        f"   - path traversal (CWE-22): a `../../` input; witness = it opens/reads a file OUTSIDE the intended "
        f"dir (print the resolved path / the leaked contents).\n"
        f"4. `cargo run --quiet` (add `--` and args if your main reads them).\n"
        f"CONFIRMED only if the crafted input produces the observed effect (cite the exact panic/overflow line, "
        f"the wave_HIT file, or the leaked path) AND the benign input does not. REFUTED if BOTH run clean "
        f"(a real guard: the code returns a Result/Option and handles the error, validates, bounds-checks, or "
        f"uses a parameterized/escaped API). If it needs a whole framework/DB you cannot stand up, or won't "
        f"compile standalone after trying, conclude 'blocked' (a panic-only finding is a DoS, not RCE -- say "
        f"so). Do NOT conclude confirmed without an observed runtime effect.")


# per-language compile-and-run repro recipes (Go / Java / C#) -- the compiled-language analog of _rust_brief.
_COMPILED = {
    "go": {"name": "Go", "image": "golang:1-alpine",
           "setup": "cd /tmp && rm -rf poc && mkdir poc && cd poc && go mod init poc",
           "deps": "go get <module>   (needs network 'host')",
           "file": "main.go (package main)",
           "run": "go run .",
           "crash": "a `panic:` or `runtime error: index out of range` / nil-pointer dereference",
           "cmd": "exec.Command(\"sh\", \"-c\", <tainted>) -> inject `; touch /tmp/wave_HIT`"},
    "java": {"name": "Java", "image": "eclipse-temurin:21-jdk",
             "setup": "write Repro.java: `public class Repro { public static void main(String[] a) throws "
                      "Exception { ... } }` and copy the method in",
             "deps": "dependency-free code just runs `java Repro.java` (JDK 21 launches a single source file); "
                     "for external jars, download them to /tmp and use `javac -cp <jars> Repro.java && "
                     "java -cp .:<jars> Repro`",
             "file": "Repro.java",
             "run": "java Repro.java   (or javac Repro.java && java Repro)",
             "crash": "an `Exception in thread \"main\"` stack trace (NPE, IndexOutOfBounds, a thrown parse error)",
             "cmd": "Runtime.getRuntime().exec(new String[]{\"sh\",\"-c\",<tainted>}) -> `; touch /tmp/wave_HIT`"},
    "dotnet": {"name": "C#", "image": "the dotnet SDK image",
               "setup": "cd /tmp && rm -rf poc && dotnet new console -o poc && cd poc",
               "deps": "dotnet add package <pkg>   (needs network 'host')",
               "file": "Program.cs",
               "run": "dotnet run",
               "crash": "an `Unhandled exception.` stack trace (NullReference, IndexOutOfRange, a thrown parse error)",
               "cmd": "Process.Start(new ProcessStartInfo{FileName=\"sh\",Arguments=\"-c ...\"}) -> "
                      "`; touch /tmp/wave_HIT`"},
    "kotlin": {"name": "Kotlin", "image": "a Kotlin/JVM image (kotlinc). If kotlinc is missing, install it "
                       "or fall back to a Gradle/JVM build",
               "setup": "write Repro.kt with `fun main() { ... }` and copy the function in",
               "deps": "for external libs, add the jar to the classpath; dependency-free code needs none",
               "file": "Repro.kt",
               "run": "kotlinc Repro.kt -include-runtime -d /tmp/r.jar && java -jar /tmp/r.jar",
               "crash": "an `Exception in thread \"main\"` stack trace (NPE, IndexOutOfBounds, a thrown parse error)",
               "cmd": "ProcessBuilder(\"sh\", \"-c\", <tainted>).start() -> `; touch /tmp/wave_HIT`"},
    "swift": {"name": "Swift", "image": "swift:5.10 (has swiftc)",
              "setup": "write repro.swift: copy the function, then top-level code that calls it (a .swift file "
                       "runs top-level statements as main)",
              "deps": "dependency-free code just runs; SwiftPM deps need a Package.swift (heavier)",
              "file": "repro.swift",
              "run": "swift repro.swift",
              "crash": "a `Fatal error:` trap (force-unwrap of nil `!`, out-of-range index, precondition/assert)",
              "cmd": "Process() with executableURL=/bin/sh and arguments [\"-c\", <tainted>] -> "
                     "`; touch /tmp/wave_HIT`"},
    "scala": {"name": "Scala", "image": "a scala-cli / scala-sbt image",
              "setup": "write repro.scala with `@main def run() = { ... }` and copy the function in",
              "deps": "scala-cli fetches deps from a `//> using dep <org::name::ver>` line at the top",
              "file": "repro.scala",
              "run": "scala-cli run repro.scala   (or scala repro.scala)",
              "crash": "an `Exception in thread \"main\"` stack trace (NPE, IndexOutOfBounds, a thrown parse error)",
              "cmd": "sys.process.Process(Seq(\"sh\", \"-c\", <tainted>)).! -> `; touch /tmp/wave_HIT`"},
    "elixir": {"name": "Elixir", "image": "elixir:latest (elixir/mix)",
               "setup": "write repro.exs: `defmodule R do ... end` copying the function, then call it at the bottom",
               "deps": "Mix.install([...]) at the top of the script pulls hex deps (needs network 'host')",
               "file": "repro.exs",
               "run": "elixir repro.exs",
               "crash": "an `** (` exception (e.g. `** (RuntimeError)`, `** (MatchError)`, `** (ArgumentError)`)",
               "cmd": "System.cmd(\"sh\", [\"-c\", <tainted>]) -> `; touch /tmp/wave_HIT`"},
    "bash": {"name": "Bash/shell", "image": "bash:5 (or any image with bash)",
             "setup": "write repro.sh that defines (or `source`s) the function, then calls it with your arg",
             "deps": "none",
             "file": "repro.sh",
             "run": "bash repro.sh <arg>",
             "crash": "bash rarely 'crashes' -- the risk here is command execution; witness that (below). A "
                      "nonzero exit is not proof by itself",
             "cmd": "the function passes input to eval / `sh -c` / backticks / `$(...)` -> inject `; touch "
                    "/tmp/wave_HIT` and confirm the file appears (that IS the proof)"},
    "lua": {"name": "Lua", "image": "nickblah/lua:5.4 (best-effort; install lua if missing)",
            "setup": "write repro.lua copying the function, then call it",
            "deps": "luarocks (heavier); stdlib needs none",
            "file": "repro.lua",
            "run": "lua repro.lua",
            "crash": "a `lua: ...:` runtime error (nil index, bad argument)",
            "cmd": "os.execute(<tainted>) / io.popen(<tainted>) -> `; touch /tmp/wave_HIT`"},
    "haskell": {"name": "Haskell", "image": "haskell:latest (ghc/runghc)",
                "setup": "write Repro.hs with `main :: IO ()` and copy the function",
                "deps": "cabal (heavier); base/process modules need none",
                "file": "Repro.hs",
                "run": "runghc Repro.hs",
                "crash": "an exception (`*** Exception:`, a `Prelude.head: empty list`-style partial-function error)",
                "cmd": "System.Process.callCommand(<tainted>) -> `; touch /tmp/wave_HIT`"},
    "dart": {"name": "Dart", "image": "dart:stable",
             "setup": "write repro.dart with `void main() { ... }` and copy the function",
             "deps": "dart pub add <pkg> (needs network 'host')",
             "file": "repro.dart",
             "run": "dart run repro.dart",
             "crash": "an `Unhandled exception:` (RangeError, a Null check operator `!` on null)",
             "cmd": "Process.runSync('sh', ['-c', <tainted>]) -> `; touch /tmp/wave_HIT`"},
    "perl": {"name": "Perl", "image": "perl:latest",
             "setup": "write repro.pl copying the sub, then call it",
             "deps": "cpanm <Module> (needs network 'host'); core modules need none",
             "file": "repro.pl",
             "run": "perl repro.pl <arg>",
             "crash": "a fatal error (`Can't locate`, `died at`, an `undefined subroutine`)",
             "cmd": "system(<tainted>) / `qx//` / backticks / open with a `|` pipe -> `; touch /tmp/wave_HIT`"},
    "ruby": {"name": "Ruby", "image": "ruby:3-slim",
             "setup": "write repro.rb: `require`/copy the method (add the file's dir to $LOAD_PATH), then call it",
             "deps": "gem install <gem> (needs network 'host'); stdlib needs none",
             "file": "repro.rb",
             "run": "ruby repro.rb <arg>",
             "crash": "an exception (`NoMethodError`, `undefined method`, a raised `RuntimeError`)",
             "cmd": "system(<tainted>) / `%x[...]` / backticks / `Kernel.eval` -> `; touch /tmp/wave_HIT`"},
    "php": {"name": "PHP", "image": "php:8.2-cli",
            "setup": "write repro.php that `require`s the file (or copies the function), then calls it",
            "deps": "composer require <pkg> (needs network 'host'); stdlib needs none",
            "file": "repro.php",
            "run": "php repro.php <arg>",
            "crash": "a `PHP Fatal error` / an `Uncaught` exception",
            "cmd": "system/exec/shell_exec/passthru/`eval`(<tainted>) -> `; touch /tmp/wave_HIT`"},
}


# every proof mode that stands up a standalone repro and runs it (needs a longer step timeout for build/fetch)
COMPILED_MODES = {"rust", *_COMPILED}


def _compiled_brief(candidate, target, rel, code, fn, lang):
    """Go / Java / C# proof: like Rust, a compiled function can't be imported+called -- COMPILE a minimal
    repro and RUN it. The witness is an observed runtime effect: a crash/stack trace on the crafted input, a
    wave_HIT marker (Command/shell sink), or a leaked traversal path."""
    c = _COMPILED[lang]
    return (
        f"File: {rel}. Function: {candidate.unit}. Suspected {candidate.cwe} ({candidate.family}); "
        f"sink: {candidate.sink}.\n\nCode around the sink:\n{code}\n\n"
        f"The file `{rel}` is {c['name']}, NOT any other language -- do not second-guess this or hunt for a "
        f"different compiler. You cannot reliably import+call one function of it in isolation like Python -- "
        f"stand up a minimal standalone repro and RUN it. The repo is mounted at /work (read it for the exact "
        f"logic/types). Because "
        f"EACH command runs in a FRESH container, do the WHOLE repro in ONE command, and use network 'host' on "
        f"it if you must fetch dependencies (image: {c['image']}). Recipe:\n"
        f"1. {c['setup']}.\n"
        f"2. Put the vulnerable logic of `{fn}` into {c['file']} -- COPY it verbatim (keep the suspect line "
        f"identical). Stub only what you must to compile; add external deps with: {c['deps']}.\n"
        f"3. Write a main that calls it TWICE with a label before each: a CRAFTED malicious input, then a "
        f"BENIGN control. Pick the payload by class:\n"
        f"   - crash / DoS (nil deref, index/bounds, bad parse, overflow): an input that triggers {c['crash']} "
        f"on the crafted input but NOT the benign one.\n"
        f"   - command injection (CWE-78): {c['cmd']}, then in the SAME command afterwards `ls -l "
        f"/tmp/wave_HIT` -- the file existing is the witness.\n"
        f"   - path traversal (CWE-22): a `../../` input; witness = it opens/reads a file OUTSIDE the intended "
        f"dir (print the resolved path / leaked contents).\n"
        f"4. {c['run']}.\n"
        f"CONFIRMED only if the crafted input produces the observed effect (cite the exact crash/stack line, "
        f"the wave_HIT file, or the leaked path) AND the benign input does not. REFUTED if BOTH run clean "
        f"(a real guard: validated input, a checked error/exception, a bounds check, a parameterized/escaped "
        f"API). If it needs a whole framework/DB/build you cannot stand up, or won't compile standalone after "
        f"trying, conclude 'blocked' (a crash-only finding is a DoS, not RCE -- say so). Do NOT conclude "
        f"confirmed without an observed runtime effect.")


def _differential_brief(candidate, target, rel, code, fn):
    """The DIFFERENTIAL / STATE observer: a no-sink access-control class (IDOR / broken authz) is proven
    BEHAVIOURALLY -- run the handler as user A requesting user B's resource and observe whether the ownership
    boundary is crossed. The harness owns the recipe (a 2-identity synthetic mini-harness); the model owns the
    framing (which arg is the caller identity vs. the target id) and drives it. Verdict is always human-review
    (anomalous_state), never a witnessed injection."""
    return (
        f"File: {rel}. Function: {candidate.unit}. Suspected {candidate.cwe} ({candidate.family}); "
        f"sink: {candidate.sink}.\n\nCode around the handler:\n{code}\n\n"
        f"This is a possible BROKEN ACCESS CONTROL / IDOR -- there is NO injection sink to trip; the proof is "
        f"BEHAVIOURAL: run the handler as ONE user requesting ANOTHER user's resource and observe whether it "
        f"returns their data (a crossed ownership boundary). The repo is mounted at /work. Build a minimal "
        f"TWO-IDENTITY harness at /work/wave_diff.py and run it:\n"
        f"1. import the handler `{fn}` from its module (add /work to sys.path; stub any import it needs).\n"
        f"2. STUB the data store it reads (the db/ORM/get call) with an in-memory dict seeded with TWO users' "
        f"records, e.g.:  store = {{1: {{'owner':'userA','secret':'A-DATA'}}, 2: {{'owner':'userB',"
        f"'secret':'B-DATA'}}}}  -- monkeypatch the exact function the handler calls so it returns store[id].\n"
        f"3. Call the handler TWICE (you decide which parameter is the CALLER IDENTITY (user/session) and "
        f"which is the TARGET id; if unsure, try both orderings):\n"
        f"   - BASELINE: as userA requesting userA's OWN record (id=1) -> expect 'A-DATA'.\n"
        f"   - ATTACK:   as userA requesting userB's record (id=2)     -> if it returns 'B-DATA', there is NO "
        f"ownership check.\n"
        f"4. print both results clearly (e.g. 'BASELINE: ...' and 'ATTACK: ...').\n"
        f"CONCLUDE 'anomalous_state' (human-review) if the ATTACK call returned userB's data / mutated userB's "
        f"record / elevated the role -- cite the two printed outputs as the observed DELTA. CONCLUDE 'refuted' "
        f"if the handler raised/denied/returned nothing on the cross-user request (an ownership guard exists). "
        f"This is a business-logic judgment anchored to a real observed state change -- use 'anomalous_state', "
        f"NEVER 'confirmed' (that is reserved for a tool-witnessed injection). If you cannot import/stub the "
        f"handler to drive it, conclude 'blocked'.")


def _reach_block(reach):
    """Half-B instruction (precision_and_measurement_plan.md): don't stop at proving the SINK fires --
    drive the attacker value IN AT THE UNTRUSTED ENTRY and let it flow down the real chain, so the PATH
    (attacker-reachability) is WITNESSED, not just inferred from the call graph. `reach` = (entry, path)."""
    if not reach:
        return ""
    entry, path = reach
    chain = " -> ".join(path) if path else entry
    return (
        f"\n\nREACHABILITY -- prove the WHOLE hypothesis, not just the sink. The untrusted entry that "
        f"reaches this sink is `{entry}` (path: {chain}). Do NOT stop once the sink fires in isolation: "
        f"reconstruct this chain and feed your attacker payload IN AT `{entry}`, letting it flow down to "
        f"the sink -- that witnesses an attacker can actually reach it. If a link won't run standalone "
        f"(needs a value/import from elsewhere), pull the real source it needs into your script until the "
        f"chain runs. In your conclusion, STATE which you did: 'reach WITNESSED' (drove from `{entry}`) or "
        f"'reach NOT witnessed' (only exercised the sink function directly).")


def _brief_for(candidate, target, reason, scaffold=None, mode="call", reach=None):
    rel = _rel(candidate.file, target)
    code = _code_window(candidate.file, getattr(candidate, "line", 0))
    fn = str(candidate.unit).split("(")[0].strip()
    if mode == "asan":                                     # C/C++ compile-with-sanitizer proof (self-contained)
        return _asan_brief(candidate, target, rel, code, fn)
    if mode == "rust":                                     # Rust: minimal cargo repro + run (panic/overflow/marker)
        return _rust_brief(candidate, target, rel, code, fn)
    if mode in _COMPILED:                                  # go/java/c#/kotlin/swift/scala/elixir/bash/lua/...
        return _compiled_brief(candidate, target, rel, code, fn, mode)
    if mode == "differential":                             # IDOR / access-control 2-identity harness
        return _differential_brief(candidate, target, rel, code, fn)
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
            f"this is a REAL, exploitable {candidate.cwe} by running code.{extra}{_reach_block(reach)}")
