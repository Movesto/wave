"""The reachability gate -- does UNTRUSTED input actually reach a proven sink?

Proving a sink FIRES (Stage 3) is not proving it is a VULN. An eval-runner executes code by design; a
dangerous helper reached only by trusted internal code is not attacker-exploitable. This gate walks the
Stage-1 call graph BACKWARD from the sink's enclosing function to an UNTRUSTED-FACING entry -- a decorated
HTTP route, or a main/handler/consumer. Found -> the confirmation stands (and we cite the path). Not found
-> the finding is DOWNGRADED to `anomalous_state` (human-review): the sink is real, but no untrusted path
was established (it may be internal/intended). The finding is never DROPPED -- only re-categorized -- because
the name-based call graph can miss edges.

Honest limits: this is FUNCTION-level reachability over codemap's name-matched call graph, NOT value-level
taint (whether the specific tainted argument flows to the sink) -- the architecture's open §10.4. It is a
coarse precision gate, not a soundness proof; the safe direction on uncertainty is human-review, not silence.
"""
import re
from collections import deque

# --- Execution-context gate: server-side sink classes cannot occur in BROWSER/frontend code. A client-side
# `fetch(url)` is not server-side SSRF; browser code has no SQL, filesystem, or shell. So a server-only sink
# proven in frontend code is a mislabel, not a vuln (the client/server analogue of the reachability gate). ---

# server-side classes that make no sense in the browser (xss + redirect DO occur client-side, so not here)
# authorization is enforced SERVER-side: a browser/React click-handler that forwards an id is not where the
# authz check lives (the backend command is), so authz/IDOR in a frontend file is misplaced -- treat it like
# the other server-only classes (MemWhale flagged approveLesson/deleteLesson in App.tsx this way).
SERVER_ONLY_CLASSES = {"ssrf", "sqli", "nosqli", "cmd", "path", "deser", "authz", "idor", "access", "bola"}
SERVER_ONLY_CWE = {"CWE-918", "CWE-89", "CWE-943", "CWE-78", "CWE-22", "CWE-502", "CWE-95",
                   "CWE-639", "CWE-284", "CWE-862", "CWE-863", "CWE-566"}

# browser-only globals -- their presence in the source is a reliable "this runs in a browser" signal (Node
# has no window/document/localStorage), and catches a plain .js util that no path/suffix rule would.
_BROWSER_SIGNAL = re.compile(r"\bwindow\.|\bdocument\.|\blocalStorage\b|\bsessionStorage\b|\bnavigator\.|"
                             r"import\.meta\.env|\baddEventListener\s*\(|\bdispatchEvent\s*\(")
_FRONTEND_IMPORT = re.compile(r"\b(react|next|vue|svelte|@angular|solid-js|preact|@remix-run|react-router)\b", re.I)
# only UNAMBIGUOUS frontend dirs -- "components"/"pages"/"views" also occur server-side (MVC templates),
# and misclassifying a backend file there would SUPPRESS a real vuln (the dangerous direction); the
# browser-global signal + JSX + framework-import catch real frontend robustly without them.
_FRONTEND_DIRS = {"frontend", "client", "public", "webapp", "www"}


def is_frontend(path, source="", imports=()):
    """Best-effort: does this file run in the BROWSER (not the server)? JSX suffix, a frontend directory, a
    frontend-framework import, or a browser-only global in the source. Python is virtually never frontend."""
    p = str(path).replace("\\", "/").lower()
    if p.rsplit(".", 1)[-1] in ("tsx", "jsx"):
        return True
    if p.endswith(".py"):                                   # server language -- never browser code
        return False
    if set(p.split("/")) & _FRONTEND_DIRS:
        return True
    if any(_FRONTEND_IMPORT.search(str(i)) for i in (imports or ())):
        return True
    return bool(source and _BROWSER_SIGNAL.search(source))

# decorator / attribute-macro / annotation signals that a function receives external input DIRECTLY.
# Matched (lowercased) against a function's captured decorators -- codemap now captures Rust #[get], Java
# @GetMapping, C#/PHP [Http*]/#[Route] as decorators too, so these cover the non-py/js web frameworks.
_ROUTE_HINTS = ("route", ".get(", ".post(", ".put(", ".delete(", ".patch(", "app.", "router.", "blueprint",
                "@get", "@post", "@put", "@delete", "@patch", "endpoint", "api_route", "websocket", "on_event",
                "#[get", "#[post", "#[put", "#[delete", "#[patch", "#[head", "#[options", "#[route",  # rust
                "@getmapping", "@postmapping", "@putmapping", "@deletemapping", "@patchmapping",       # spring
                "@requestmapping",
                "[httpget", "[httppost", "[httpput", "[httpdelete", "[httppatch", "[route(", "#[route")  # c#/symfony
# Entry TRUST TIERS (Shift 3, docs/trust_boundary_plan.md). 'remote' = a network/route/event handler that
# carries ATTACKER input. 'local' = a process/CLI entry -- a script's main() run from a shell, whose input is
# argv/local and whose operator is a developer/CI, NOT a remote attacker. A `confirmed` needs a REMOTE path;
# a merely-LOCAL reach means remote exploitability is NOT established -> human review (fail-safe default).
_REMOTE_ENTRY_NAMES = {"handler", "handle", "lambda_handler", "handle_request", "on_message", "on_request"}
_LOCAL_ENTRY_NAMES = {"main"}                               # a CLI/process main() is NOT a remote attack surface


def entry_trust(func):
    """The trust level of an entry point: 'remote' (route decorator or a network/event handler name),
    'local' (a bare CLI/process main()), or None (not an entry). Route decorators always win."""
    decs = " ".join(getattr(func, "decorators", None) or []).lower()
    if any(h in decs for h in _ROUTE_HINTS):
        return "remote"
    name = (getattr(func, "name", "") or "").lower()
    if name in _REMOTE_ENTRY_NAMES:
        return "remote"
    if name in _LOCAL_ENTRY_NAMES:
        return "local"
    return None


def is_untrusted_entry(func):
    """True if `func` takes external/attacker input directly: a decorated HTTP route, or a
    main/handler/consumer entry. (Merely being `exported` is NOT enough -- a library's public API is called
    by trusted code; that is exactly the eval-runner false positive.) See entry_trust for the tier."""
    return entry_trust(func) is not None


def reaches_untrusted_entry(cmap, sink_name, max_hops=12):
    """BFS BACKWARD over the call graph from `sink_name` to an untrusted-facing entry. PREFERS a REMOTE entry:
    a LOCAL/CLI entry is remembered as a fallback but the search continues, so a sink reachable from BOTH a
    route and a main() is reported REMOTE. Returns (entry_func, path, trust) with trust in {'remote','local'},
    or (None, None, None) if no entry is reached."""
    if not sink_name:
        return None, None, None
    fallback = None                                         # a local entry found -> keep looking for a remote one
    for f in cmap.funcs.get(sink_name, []):                 # the sink function is itself an entry?
        t = entry_trust(f)
        if t == "remote":
            return f, [sink_name], "remote"
        if t == "local" and fallback is None:
            fallback = (f, [sink_name], "local")
    seen = {sink_name}
    q = deque([[sink_name]])
    while q:
        path = q.popleft()
        if len(path) > max_hops:
            continue
        for caller in cmap.callers_of(path[0]):
            if caller in seen:
                continue
            seen.add(caller)
            for f in cmap.funcs.get(caller, []):
                t = entry_trust(f)
                if t == "remote":
                    return f, [caller] + path, "remote"
                if t == "local" and fallback is None:
                    fallback = (f, [caller] + path, "local")
            q.append([caller] + path)
    return fallback if fallback else (None, None, None)


def _ambiguous_names(cmap, path):
    """Names in the chain that are defined in MORE THAN ONE place -- a name-based call edge to such a name is
    a GUESS (the graph matched on name, not binding), e.g. `decode`/`load`/`run`. A chain that leans on one
    is low-confidence (open question 10.1: false name-based edges)."""
    return [n for n in path if len(cmap.funcs.get(n, [])) > 1]


def gate(cmap, sink_func_name):
    """Classify a proven sink by reachability. Returns (reachable: bool, confidence: str, note: str,
    trust: str|None). confidence 'high' = a clean chain with no ambiguous (common-name) edges; 'low' = the
    ONLY path relies on an ambiguous name-based edge. trust = the reached entry's tier ('remote'|'local'):
    a 'local' (CLI/process) reach means remote exploitability is NOT established -> prove downgrades to review."""
    entry, path, trust = reaches_untrusted_entry(cmap, (sink_func_name or "").split("(")[0].strip())
    if entry is None:
        return False, "high", (
            "sink PROVEN to fire, but no path from an untrusted-facing entry (route / handler) reaches it -- "
            "may be internal/intended; needs human review (function-level, name-based)"), None
    ambig = _ambiguous_names(cmap, path)
    conf = "low" if ambig else "high"
    note = f"reachable from {trust} entry {entry.name} via {'->'.join(path)}"
    if conf == "low":
        note += (f"  [LOW confidence: {sorted(set(ambig))} is defined in multiple places -- this name-based "
                 f"call edge may be false (open Q 10.1)]")
    return True, conf, note, trust


# --- Desktop-app context: a Tauri/Electron app is single-user + local, so there is NO multi-tenant
# authorization boundary -- an IDOR/authz "finding" there is usually moot (the user owns their own data).
# Injection classes still matter (untrusted files, a synced/remote backend), so only authz is downgraded.
import functools
from pathlib import Path as _Path

_DESKTOP_SKIP = {"node_modules", ".git", "target", "dist", "build", "vendor", ".venv", "venv"}
_MODULE_MANIFESTS = ("build.gradle", "build.gradle.kts", "pom.xml", "package.json", "Cargo.toml",
                     "pyproject.toml", "go.mod", "composer.json", "Gemfile")

# a file that IS a server/web endpoint -- a real multi-tenant boundary where authz matters, even in a repo
# that ALSO ships a desktop build (the Stirling app/saas case). Overrides the desktop-authz downgrade.
_SERVER_ENDPOINT = re.compile(
    r"@RestController|@Controller\b|@(Get|Post|Put|Delete|Patch|Request)Mapping|@PathVariable|"
    r"HttpServletRequest|@app\.(route|get|post|put|delete|patch)|@router\.|@blueprint|APIRouter\(|"
    r"FastAPI\(|Flask\(|express\(\)|\brouter\.(get|post|put|delete)\(|app\.(get|post|put|delete)\(", re.I)


def is_server_endpoint(path, source=""):
    """True when the file exposes an HTTP/server endpoint (route decorator / servlet / framework router). Such
    a file is a real multi-tenant boundary -- authz applies there regardless of any sibling desktop build."""
    if not source:
        try:
            source = _Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
    return bool(_SERVER_ENDPOINT.search(source))


def _module_root(file, repo_root):
    """The nearest ancestor dir (within repo_root) that has a build manifest -- the finding's MODULE root; else
    repo_root. Lets desktop-ness be judged per-module so a web module isn't tagged desktop by a sibling build."""
    root = _Path(repo_root).resolve()
    try:
        cur = _Path(file).resolve()
        cur = cur.parent if cur.suffix else cur
    except Exception:
        return root
    while True:
        if any((cur / m).exists() for m in _MODULE_MANIFESTS):
            return cur
        if cur == root or root not in cur.parents:
            return root
        cur = cur.parent


@functools.lru_cache(maxsize=128)
def _detect_desktop(root):
    """Tauri/Electron markers anywhere under `root` (a repo or a single module). Cached per path."""
    root = _Path(root)
    try:
        if (root / "src-tauri").is_dir():                    # Tauri's conventional backend dir
            return True
        for ct in list(root.rglob("Cargo.toml"))[:30]:       # `tauri` as a dependency
            if any(s in ct.parts for s in _DESKTOP_SKIP):
                continue
            if re.search(r'(?im)^\s*tauri\s*=', ct.read_text(encoding="utf-8", errors="replace")):
                return True
        for pj in list(root.rglob("package.json"))[:30]:     # electron / @tauri-apps in package.json
            if any(s in pj.parts for s in _DESKTOP_SKIP):
                continue
            t = pj.read_text(encoding="utf-8", errors="replace").lower()
            if '"electron"' in t or "@tauri-apps" in t:
                return True
    except Exception:
        pass
    return False


def is_desktop_app(target, file=None):
    """Desktop (single-user Tauri/Electron) context. With `file`, judged for the MODULE containing that file
    (so a web module in a repo that ALSO ships a desktop build is NOT mislabeled desktop). Without `file`,
    whole-repo (legacy). Deterministic; cached."""
    root = _module_root(file, target) if file else _Path(target)
    return _detect_desktop(str(root))
