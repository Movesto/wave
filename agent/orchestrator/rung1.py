"""Rung 1 of the confirmation ladder (investigation-loop plan §3.4): TARGETED MICRO-EXECUTION.

"Import, mock, call" -- not "extract code." Patch the sink (DB execute / outbound HTTP) with a TRIPWIRE,
import the candidate's handler, and CALL IT DIRECTLY with a marked payload. If the marker lands in the
sink in an unsafe position (SQL statement not params / outbound URL), the vuln is confirmed WITHOUT an
HTTP server or a real backend -- the rung that decouples proof from full provisioning.

This module runs micro-exec IN-PROCESS (the target's deps must be importable here). For real apps whose
deps live only in the container, the same driver runs inside the built image (Rung-1 in-container -- the
documented next step). Rung-1 confirmations rank WEAKER than Rung 2 (a function out of context can
differ from the running app) and record the stubs used.

SOUNDNESS: a confirmation requires the marker to reach the sink in an unsafe position -- exactly the
runtime oracle's predicate. If the handler can't be imported/called, or nothing reaches a sink, the
verdict is UNKNOWN (never a finding, never a clear).
"""
from __future__ import annotations

import contextlib
import importlib.util
import inspect
import secrets
from dataclasses import dataclass, field


@dataclass
class MicroResult:
    verdict: str                 # "proven" | "safe" | "unknown"
    reason: str
    marker: str = ""
    evidence: str = ""
    stubs: list = field(default_factory=list)
    rung: int = 1


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
    # requests outbound HTTP -> record the URL
    try:
        import requests

        def _req(method, url, *a, **k):
            tw.http(url)
            raise RuntimeError("wave-rung1: outbound call stubbed after recording")
        for m in ("get", "post", "put", "delete", "patch", "request", "head"):
            patch(requests, m, (lambda mm: (lambda url=None, *a, **k: _req(mm, url, *a, **k)))(m))
        applied.append("requests")
    except Exception:
        pass
    tw._stubs = applied
    try:
        yield
    finally:
        for obj, name, orig in reversed(undo):
            with contextlib.suppress(Exception):
                setattr(obj, name, orig)


def _load_module(path):
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


def _verdict_from_hits(tw, marker, cwe):
    for kind, text, params in tw.hits:
        if kind == "sql" and marker in text and marker not in (params or ""):
            return ("proven", f"marker reached the SQL statement (not params): {text[:120]}")
        if kind == "http" and marker in text:
            return ("proven", f"marker reached the outbound URL: {text[:160]}")
        if kind == "path" and marker in text and ("../" in text or text.strip().startswith("/")):
            return ("proven", f"marker reached a file path with traversal: {text[:160]}")
    # marker only in params (parameterized) -> safe, if a SQL sink was hit at all
    if cwe == "CWE-89" and any(k == "sql" and marker in (p or "") for k, t, p in tw.hits):
        return ("safe", "marker reached the SQL sink only as a bound parameter (parameterized)")
    return ("unknown", f"no sink reached with the marker ({len(tw.hits)} sink hit(s))")


def micro_exec(candidate, target_param=None) -> MicroResult:
    """Import the candidate's handler with sinks tripwired and call it with a marked payload."""
    path = getattr(candidate, "file", "")
    unit = getattr(candidate, "unit", "") or ""
    func_name = unit.split("(")[0].strip() if unit else ""
    if not path.endswith(".py") or not func_name:
        return MicroResult("unknown", "no importable Python handler for this candidate")
    marker = "WZ" + secrets.token_hex(4)
    tw = _Tripwire()
    try:
        with _tripwires(tw):
            mod = _load_module(path)
            fn = getattr(mod, func_name, None)
            if fn is None or not callable(fn):
                return MicroResult("unknown", f"handler {func_name!r} not found/callable after import",
                                   stubs=getattr(tw, "_stubs", []))
            for _tgt, args in _call_args(fn, marker, target_param):
                with contextlib.suppress(Exception):
                    fn(**args)
                v, why = _verdict_from_hits(tw, marker, getattr(candidate, "cwe", ""))
                if v == "proven":
                    return MicroResult("proven", why, marker=marker, evidence=why, stubs=getattr(tw, "_stubs", []))
    except Exception as e:
        return MicroResult("unknown", f"micro-exec could not run in-process: {type(e).__name__}: {e}",
                           stubs=getattr(tw, "_stubs", []))
    v, why = _verdict_from_hits(tw, marker, getattr(candidate, "cwe", ""))
    return MicroResult(v, why, marker=marker, evidence=why if v != "unknown" else "", stubs=getattr(tw, "_stubs", []))
