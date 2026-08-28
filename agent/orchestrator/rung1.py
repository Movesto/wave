"""Rung 1 of the confirmation ladder (investigation-loop plan §3.4): TARGETED MICRO-EXECUTION.

"Import, mock, call" -- not "extract code." Patch the sink (DB execute / outbound HTTP) with a TRIPWIRE,
import the candidate's handler, and CALL IT DIRECTLY with a marked payload. If the marker lands in the
sink in an unsafe position (SQL statement not params / outbound URL), the vuln is confirmed WITHOUT an
HTTP server or a real backend -- the rung that decouples proof from full provisioning.

ARCHITECTURE (evidence-grounded plan, Phase 1): the work is split into two roles behind a seam, so more
languages and evidence sources slot in without touching the rest:
  * an EXECUTOR runs the candidate's function in its runtime with sinks tripwired and returns an
    Observation -- the RAW FACTS (which sinks were hit, with what text/params), never a verdict.
  * an OBSERVER (`_verdict_from_hits`, the canary-in-sink observer) interprets those facts into a
    verdict. Today the executor is Python-only; a NodeExecutor (Phase 2) is just another implementation
    of the same interface, dispatched by the candidate's language.

Rung-1 confirmations rank WEAKER than Rung 2 (a function out of context can differ from the running app)
and record the stubs used. SOUNDNESS: a confirmation requires the marker to reach the sink in an unsafe
position -- exactly the runtime oracle's predicate. If the handler can't be imported/called, or nothing
reaches a sink, the verdict is UNKNOWN (never a finding, never a clear).
"""
from __future__ import annotations

import contextlib
import importlib.util
import inspect
import os
import secrets
import sys
from dataclasses import dataclass, field


@dataclass
class MicroResult:
    verdict: str                 # "proven" | "safe" | "unknown"
    reason: str
    marker: str = ""
    evidence: str = ""
    stubs: list = field(default_factory=list)
    rung: int = 1


@dataclass
class Observation:
    """The RAW FACTS from one micro-execution -- what the sinks saw, whether the handler ran, and why it
    couldn't (if it couldn't). Carries NO verdict: an Observer turns this into a MicroResult."""
    sink_hits: list = field(default_factory=list)   # [(kind, text, params_repr)] captured by the tripwire
    ran: bool = False                               # the handler was actually imported + called
    error: str = ""                                 # why it couldn't run (import failure / no handler)
    stubs: list = field(default_factory=list)       # which sink stubs applied


class _Tripwire:
    """Collects sink hits during a micro-exec. Each hit: (kind, statement/url, params_repr)."""

    def __init__(self):
        self.hits = []

    def sql(self, statement, params=None):
        self.hits.append(("sql", str(statement), repr(params)))

    def http(self, url):
        self.hits.append(("http", str(url), ""))

    def path(self, p):
        self.hits.append(("path", str(p), ""))


class _FakeResult:
    def fetchone(self): return None
    def fetchall(self): return []
    def scalar(self): return None
    def __iter__(self): return iter([])
    def keys(self): return []


def _url_of(a, k):
    """Best-effort URL from an HTTP-client call's args (get(url) / request(method, url) / url=)."""
    if k.get("url"):
        return k["url"]
    for x in a:
        if isinstance(x, str) and ("://" in x or x.startswith("/")):
            return x
    return a[0] if a else ""


@contextlib.contextmanager
def _tripwires(tw):
    """Patch DB execute + outbound HTTP + file open to the tripwire; restore on exit. Records the stubs
    that actually applied (best-effort across sqlalchemy / sqlite3 / requests)."""
    applied, undo = [], []

    def patch(obj, name, fn):
        if obj is None or not hasattr(obj, name):
            return
        orig = getattr(obj, name)
        setattr(obj, name, fn)
        undo.append((obj, name, orig))

    # sqlalchemy Connection/Engine.execute -> record the statement text
    try:
        import sqlalchemy.engine as _sae

        def _sa_exec(self, statement, *a, **k):
            tw.sql(statement, a[0] if a else k.get("parameters"))
            return _FakeResult()
        patch(_sae.Connection, "execute", _sa_exec)
        patch(_sae.Connection, "exec_driver_sql", _sa_exec)
        applied.append("sqlalchemy")
    except Exception:
        pass
    # psycopg2 (Postgres): stub connect + pools -> a fake connection whose cursor.execute is the tripwire.
    # This both survives DB-at-import (Manga_ryu) AND observes the SQL, without a real Postgres.
    try:
        import psycopg2
        import psycopg2.pool

        class _PgCur:
            description = None
            rowcount = -1

            def execute(self, q, params=None):
                tw.sql(q, params)
                return self

            def fetchone(self): return None
            def fetchall(self): return []
            def __iter__(self): return iter([])
            def close(self): pass
            def __enter__(self): return self
            def __exit__(self, *a): pass

        class _PgConn:
            def cursor(self, *a, **k): return _PgCur()
            def commit(self): pass
            def rollback(self): pass
            def close(self): pass
            def __enter__(self): return self
            def __exit__(self, *a): pass

        class _PgPool:
            def __init__(self, *a, **k): pass
            def getconn(self, *a, **k): return _PgConn()
            def putconn(self, *a, **k): pass
            def closeall(self): pass

        patch(psycopg2, "connect", lambda *a, **k: _PgConn())
        patch(psycopg2.pool, "ThreadedConnectionPool", _PgPool)
        patch(psycopg2.pool, "SimpleConnectionPool", _PgPool)
        applied.append("psycopg2")
    except Exception:
        pass
    # raw MySQL drivers (pymysql / mysqlclient) -> fake conn with a tripwire cursor
    for _mod in ("pymysql", "MySQLdb"):
        try:
            _m = __import__(_mod)

            def _mysql_connect(*a, **k):
                class _C:
                    def execute(self, q, params=None):
                        tw.sql(q, params)
                        return self
                    def fetchone(self): return None
                    def fetchall(self): return []
                    def __iter__(self): return iter([])
                    def close(self): pass
                    def __enter__(self): return self
                    def __exit__(self, *x): pass

                class _Cn:
                    def cursor(self, *a, **k): return _C()
                    def commit(self): pass
                    def rollback(self): pass
                    def close(self): pass
                    def __enter__(self): return self
                    def __exit__(self, *x): pass
                return _Cn()
            patch(_m, "connect", _mysql_connect)
            applied.append(_mod)
        except Exception:
            pass
    # outbound HTTP (requests / httpx / urllib) -> record the URL so an SSRF marker is observed
    for _mod in ("requests", "httpx"):
        try:
            _m = __import__(_mod)

            def _http(*a, **k):
                tw.http(_url_of(a, k))
                raise RuntimeError("wave-rung1: outbound call stubbed after recording")
            for _fn in ("get", "post", "put", "delete", "patch", "request", "head"):
                patch(_m, _fn, _http)
            applied.append(_mod)
        except Exception:
            pass
    try:
        import urllib.request as _ur

        def _urlopen(url=None, *a, **k):
            tw.http(getattr(url, "full_url", url) or "")
            raise RuntimeError("wave-rung1: urlopen stubbed after recording")
        patch(_ur, "urlopen", _urlopen)
        applied.append("urllib")
    except Exception:
        pass
    tw._stubs = applied
    try:
        yield
    finally:
        for obj, name, orig in reversed(undo):
            with contextlib.suppress(Exception):
                setattr(obj, name, orig)


def _pkg_root(path):
    """Directory to put on sys.path so the module's OWN intra-repo imports resolve: walk up while an
    __init__.py exists (so `import package.sibling` works), else the file's immediate directory."""
    d = os.path.dirname(os.path.abspath(path))
    while os.path.isfile(os.path.join(d, "__init__.py")):
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return d


def _load_module(path):
    root = _pkg_root(path)
    if root not in sys.path:
        sys.path.insert(0, root)                          # so sibling/intra-repo imports (not pip deps) resolve
    spec = importlib.util.spec_from_file_location(f"_wave_micro_{secrets.token_hex(3)}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)                          # may run module-level code (patched sinks apply)
    return mod


def _call_args(fn, marker, target_param=None):
    """Build kwargs for a handler: marker into the target (or each) str param, benign defaults elsewhere."""
    sig = inspect.signature(fn)
    variants = []
    str_params = [n for n, p in sig.parameters.items()
                  if p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY) and n not in ("self", "cls")]
    for tgt in ([target_param] if target_param else str_params):
        args = {}
        for n, p in sig.parameters.items():
            if n in ("self", "cls"):
                continue
            args[n] = marker if n == tgt else ("1" if "id" in n.lower() else "")
        variants.append((tgt, args))
    return variants


def _verdict_from_hits(hits, marker, cwe):
    """The CANARY-IN-SINK observer: given the raw sink hits from an Observation, decide whether the
    marker reached a sink in an UNSAFE position. Facts in, verdict out -- the model never touches this."""
    from urllib.parse import urlparse
    for kind, text, params in hits:
        if kind == "sql" and marker in text and marker not in (params or ""):
            return ("proven", f"marker reached the SQL statement (not params): {text[:120]}")
        if kind == "http":
            # SSRF requires HOST control -- the marker must reach the outbound URL's HOSTNAME, not just a
            # path segment appended to a fixed internal base (that is the app's normal fetch-by-id, not SSRF).
            try:
                host = urlparse(text if "://" in text else "//" + text, scheme="http").hostname or ""
            except ValueError:
                host = ""
            if marker.lower() in host.lower():
                return ("proven", f"marker controls the outbound HOST: {text[:160]}")
        if kind == "path" and marker in text and ("../" in text or text.strip().startswith("/")):
            return ("proven", f"marker reached a file path with traversal: {text[:160]}")
    # marker only in params (parameterized) -> safe, if a SQL sink was hit at all
    if cwe == "CWE-89" and any(k == "sql" and marker in (p or "") for k, t, p in hits):
        return ("safe", "marker reached the SQL sink only as a bound parameter (parameterized)")
    return ("unknown", f"no sink reached with the marker in an unsafe position ({len(hits)} sink hit(s))")


def _observe(obs, marker, cwe) -> MicroResult:
    """Apply the canary observer to an Observation -> MicroResult. An Observation that couldn't run is
    UNKNOWN with its own reason; otherwise the sink hits decide proven/safe/unknown."""
    if obs.error:
        return MicroResult("unknown", obs.error, stubs=obs.stubs)
    v, why = _verdict_from_hits(obs.sink_hits, marker, cwe)
    return MicroResult(v, why, marker=marker, evidence=why if v != "unknown" else "", stubs=obs.stubs)


def _payload(cwe):
    """(arg value, search marker). For SSRF the value is HOST-SHAPED so a genuine URL argument controls
    the outbound HOST (real SSRF); a value that only lands in a path segment won't match the host."""
    token = secrets.token_hex(4)
    if cwe == "CWE-918":
        return f"http://wz{token}.wave.test/", f"wz{token}.wave.test"
    return "WZ" + token, "WZ" + token


class PythonExecutor:
    """EXECUTOR for Python candidates: import the handler IN-PROCESS with sinks tripwired, call it with a
    marked payload across arg-variants, and return the raw sink hits as an Observation (no verdict)."""
    lang = "py"

    def run(self, candidate, payload, target_param=None) -> Observation:
        path = getattr(candidate, "file", "")
        unit = getattr(candidate, "unit", "") or ""
        func_name = unit.split("(")[0].strip() if unit else ""
        if not path.endswith(".py") or not func_name:
            return Observation(error="no importable Python handler for this candidate")
        tw = _Tripwire()
        try:
            with _tripwires(tw):
                mod = _load_module(path)
                fn = getattr(mod, func_name, None)
                if fn is None or not callable(fn):
                    return Observation(error=f"handler {func_name!r} not found/callable after import",
                                       stubs=getattr(tw, "_stubs", []))
                for _tgt, args in _call_args(fn, payload, target_param):
                    with contextlib.suppress(Exception):
                        fn(**args)                            # hits accumulate in the tripwire across variants
                return Observation(sink_hits=list(tw.hits), ran=True, stubs=getattr(tw, "_stubs", []))
        except Exception as e:
            return Observation(error=f"micro-exec could not run in-process: {type(e).__name__}: {e}",
                               stubs=getattr(tw, "_stubs", []))


# ---- In-CONTAINER micro-execution: run the same driver inside the built image, where the target's
# real deps (fastapi/psycopg2/...) live -- for real apps whose deps are NOT importable on the host. ----
_DRIVER = r'''
import sys, json, inspect, importlib.util
_HITS = []
def _sql(s, p=None): _HITS.append(("sql", str(s), repr(p)))
def _http(u): _HITS.append(("http", str(u), ""))
try:
    import sqlalchemy.engine as _sae
    def _e(self, statement, *a, **k):
        _sql(statement, a[0] if a else k.get("parameters"))
        class _R:
            def fetchone(s): return None
            def fetchall(s): return []
            def scalar(s): return None
            def __iter__(s): return iter([])
        return _R()
    _sae.Connection.execute = _e
    _sae.Connection.exec_driver_sql = _e
except Exception: pass
try:
    import psycopg2, psycopg2.pool
    class _Cur:
        description = None; rowcount = -1
        def execute(self, q, p=None): _sql(q, p); return self
        def fetchone(self): return None
        def fetchall(self): return []
        def __iter__(self): return iter([])
        def close(self): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
    class _Conn:
        def cursor(self, *a, **k): return _Cur()
        def commit(self): pass
        def rollback(self): pass
        def close(self): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
    class _Pool:
        def __init__(self, *a, **k): pass
        def getconn(self, *a, **k): return _Conn()
        def putconn(self, *a, **k): pass
        def closeall(self): pass
    psycopg2.connect = lambda *a, **k: _Conn()
    psycopg2.pool.ThreadedConnectionPool = _Pool
    psycopg2.pool.SimpleConnectionPool = _Pool
except Exception: pass
def _urlof(a, k):
    if k.get("url"): return k["url"]
    for x in a:
        if isinstance(x, str) and ("://" in x or x.startswith("/")): return x
    return a[0] if a else ""
for _mod in ("requests", "httpx"):
    try:
        _m = __import__(_mod)
        def _http_stub(*a, **k): _http(_urlof(a, k)); raise RuntimeError("stub")
        for _fn in ("get","post","put","delete","patch","request","head"): setattr(_m, _fn, _http_stub)
    except Exception: pass
try:
    import urllib.request as _ur
    def _uo(url=None, *a, **k): _http(getattr(url,"full_url",url) or ""); raise RuntimeError("stub")
    _ur.urlopen = _uo
except Exception: pass
for _mod in ("pymysql", "MySQLdb"):
    try:
        _m = __import__(_mod)
        def _myc(*a, **k):
            class _C:
                def execute(self,q,p=None): _sql(q,p); return self
                def fetchone(self): return None
                def fetchall(self): return []
                def __iter__(self): return iter([])
                def close(self): pass
                def __enter__(self): return self
                def __exit__(self,*x): pass
            class _Cn:
                def cursor(self,*a,**k): return _C()
                def commit(self): pass
                def rollback(self): pass
                def close(self): pass
                def __enter__(self): return self
                def __exit__(self,*x): pass
            return _Cn()
        setattr(_m, "connect", _myc)
    except Exception: pass
MARKER = __MARKER__
sys.path.insert(0, "/app")
try:
    _spec = importlib.util.spec_from_file_location("_wt", __MODPATH__)
    _mod = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_mod)
    _fn = getattr(_mod, __FUNC__, None)
    if _fn is None: raise RuntimeError("no func " + __FUNC__)
    _sig = inspect.signature(_fn)
    _ps = [n for n, p in _sig.parameters.items() if n not in ("self", "cls")]
    for _tgt in (_ps or [None]):
        _args = {}
        for n, p in _sig.parameters.items():
            if n in ("self", "cls"): continue
            _args[n] = MARKER if n == _tgt else ("1" if "id" in n.lower() else "")
        try: _fn(**_args)
        except Exception: pass
        if any(MARKER in h[1] for h in _HITS): break
except Exception as _e2:
    print("WAVE_MICRO_ERR::" + type(_e2).__name__ + ": " + str(_e2))
print("WAVE_MICRO_RESULT::" + json.dumps({"hits": _HITS}))
'''


def _container_path(candidate_file, target):
    from pathlib import Path
    try:
        rel = Path(candidate_file).resolve().relative_to(Path(target).resolve())
        return "/app/" + str(rel).replace("\\", "/")
    except Exception:
        return "/app/" + Path(candidate_file).name


def _container_modpath(candidate_file, code_root, workdir):
    from pathlib import Path
    try:
        rel = Path(candidate_file).resolve().relative_to(Path(code_root).resolve())
        return workdir.rstrip("/") + "/" + str(rel).replace("\\", "/")
    except Exception:
        return workdir.rstrip("/") + "/" + Path(candidate_file).name


class PythonContainerExecutor:
    """EXECUTOR for Python candidates whose deps live only in the app image: run the driver INSIDE the
    built image with `--no-deps --build` (builds on demand, never boots the stack). Returns the raw sink
    hits as an Observation. `rt` is the prepared RunningTarget (compose file, build service, code_root)."""

    def run(self, candidate, payload, rt, timeout=180) -> Observation:
        import json as _json
        import re as _re
        import subprocess
        from . import provision

        unit = getattr(candidate, "unit", "") or ""
        func = unit.split("(")[0].strip()
        if rt is None or not rt.compose_files:
            return Observation(error="target not prepared (no compose) for in-container micro-exec")
        if not func:
            return Observation(error="no handler function for in-container micro-exec")
        modpath = _container_modpath(getattr(candidate, "file", ""), rt.code_root, rt.workdir)
        driver = (_DRIVER.replace("__MARKER__", repr(payload)).replace("__MODPATH__", repr(modpath))
                  .replace("__FUNC__", repr(func)))
        cmd = ["docker", "compose"]
        for f in rt.compose_files:
            cmd += ["-f", f]
        cmd += ["run", "--rm", "--no-deps", "--build", "-T", "--entrypoint", "python", rt.service, "-c", driver]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, encoding="utf-8",
                               errors="replace", env=provision.compose_env())
        except Exception as e:
            return Observation(error=f"in-container micro-exec failed to run: {type(e).__name__}: {e}")
        out = (r.stdout or "") + (r.stderr or "")
        m = _re.search(r"WAVE_MICRO_RESULT::(\{.*\})", out)
        if not m:
            err = _re.search(r"WAVE_MICRO_ERR::(.*)", out)
            return Observation(error=f"in-container micro-exec: no result "
                                     f"({err.group(1) if err else out[-160:]})")
        hits = [tuple(h) for h in _json.loads(m.group(1)).get("hits", [])]
        return Observation(sink_hits=hits, ran=True, stubs=["in-container"])


def micro_exec_container(candidate, rt, timeout=180) -> MicroResult:
    """Backward-compatible wrapper: run the in-container executor and observe the result."""
    payload, marker = _payload(getattr(candidate, "cwe", ""))
    obs = PythonContainerExecutor().run(candidate, payload, rt, timeout=timeout)
    return _observe(obs, marker, getattr(candidate, "cwe", ""))


# Executor dispatch by candidate language. Only Python today; NodeExecutor (Phase 2) registers here as
# {"js": NodeExecutor()} and everything else -- the observer, the verdict, the loop -- stays unchanged.
_PY_EXEC = PythonExecutor()
_EXECUTORS = {"py": _PY_EXEC}


def _lang_of(candidate):
    return "py" if (getattr(candidate, "file", "") or "").endswith(".py") else ""


def micro_exec(candidate, target_param=None, rt=None) -> MicroResult:
    """Confirm a candidate by micro-execution. Dispatch an EXECUTOR by language to run the function and
    return raw facts; the canary OBSERVER renders the verdict. Try IN-PROCESS first (fast; needs deps on
    the host), then fall back to IN-CONTAINER when a prepared `rt` is given (deps live in the image)."""
    cwe = getattr(candidate, "cwe", "")
    payload, marker = _payload(cwe)
    executor = _EXECUTORS.get(_lang_of(candidate), _PY_EXEC)   # unknown lang -> Python (yields its own error)
    mr = _observe(executor.run(candidate, payload, target_param), marker, cwe)
    if mr.verdict in ("proven", "safe"):
        return mr
    if rt is not None:
        cmr = _observe(PythonContainerExecutor().run(candidate, payload, rt), marker, cwe)
        if cmr.verdict in ("proven", "safe"):
            return cmr
        if mr.verdict == "unknown" and cmr.verdict != "unknown":
            return cmr
    return mr
