"""Sink Instrumentation Registry — the crux component.

A curated library of per-driver "modified drivers": each turns a sink into a verifiable oracle by
logging the exact value that reaches it BEFORE execution (marker `WAVE-SINK-<KIND>`). Seeded by the
Phase-0 hooks proven on VAmPI (SQLAlchemy) and NodeGoat (mongodb). The instrumented-sink oracle
(oracle.py, later) greps these markers to PROVE a payload reached the sink unescaped.

Per the Phase-0 finding (F1/R2/G1): instrumentation is PER-DRIVER, so this is an extensible list,
not a one-off. Add a hook per (driver) as new stacks are targeted.

THE REQUEST-CONTEXT GATE (self-trigger hardening): the core-language hooks (eval/exec/fs/ssrf) are
always-on global wraps, so in a sandbox that runs arbitrary model-written code a bare driver
(`node -e "eval(payload)"`) would trip them and forge a SEALED tape-grade confirm that never went
through the app. To close that, every hook builds its marker through a shared context module
(`context_module`): the SEALED form (`WAVE-SINK-X#<secret>`, the only form oracle.scan counts) is
emitted ONLY when the sink fires WHILE the app is serving an inbound HTTP request; a sink reached from
code the model ran directly logs the BARE token, which the sealed oracle ignores. Without a per-run
secret (legacy boot path) the gate is inert and behaviour is unchanged.
"""
import re
from dataclasses import dataclass
from typing import Callable


@dataclass
class SinkHook:
    name: str            # driver id, e.g. "sqlalchemy"
    lang: str            # "py" | "js"
    detect: tuple        # substrings in deps/imports that indicate this driver is in use
    marker: str          # log marker to grep, e.g. "WAVE-SINK-SQL"
    filename: str        # module written into the build, e.g. "_wave_sink_sqlalchemy.py"
    code: str            # the hook source (the modified driver)
    kind: str            # sink class: "sql" | "nosql" | "template" | "shell" | ...


# ---- THE REQUEST-CONTEXT GATE: a shared module every hook loads to build its marker ------------------
# Written alongside the sink hooks and loaded FIRST. It tracks whether the app is CURRENTLY serving an
# inbound HTTP request (JS: an AsyncLocalStorage anchored on http/https Server 'request'; PY: a ContextVar
# set across the WSGI/ASGI entry of Flask/Django/Bottle/Starlette). `seal(token)` returns the counted
# `token#<secret>` only inside a served request, else the bare token. See the module docstring.
@dataclass
class ContextModule:
    filename: str
    code: str


_CTX_JS = ContextModule(
    "_wave_sink_ctx.js",
    '''// wave request-context gate (shared by the JS sink hooks). A SEALED WAVE-SINK marker -- the only form
// oracle.scan counts, carrying the per-run secret -- is emitted ONLY while the app is serving an inbound
// HTTP request. A sink reached from a bare driver the model wrote (e.g. `node -e "eval(x)"`), NOT through
// the app's request path, logs the BARE token, which the sealed oracle ignores. This stops the always-on
// eval/exec/fs/ssrf wraps from forging a tape-grade confirm out of code the model ran directly.
"use strict";
var _secret = process.env.WAVE_WITNESS || "";
var _als = null;
try {
  var AsyncLocalStorage = require("async_hooks").AsyncLocalStorage;
  _als = new AsyncLocalStorage();
  ["http", "https"].forEach(function (name) {          // http.Server and https.Server are SEPARATE prototypes
    try {
      var proto = require(name).Server && require(name).Server.prototype;
      if (!proto || proto.__waveCtx) return;
      var origEmit = proto.emit;
      proto.emit = function (event) {                  // every inbound request dispatches via emit('request')
        if (event === "request") {
          var self = this, args = arguments;
          return _als.run({ req: true }, function () { return origEmit.apply(self, args); });
        }
        return origEmit.apply(this, arguments);
      };
      proto.__waveCtx = true;
    } catch (e) {}
  });
} catch (e) {}
function inRequest() {
  try { var s = _als && _als.getStore(); return !!(s && s.req); } catch (e) { return false; }
}
function seal(token) { return (inRequest() && _secret) ? (token + "#" + _secret) : token; }
module.exports = { inRequest: inRequest, seal: seal };
''')

_CTX_PY = ContextModule(
    "_wave_sink_ctx.py",
    '''"""wave request-context gate (shared by the Python sink hooks; twin of _wave_sink_ctx.js). A SEALED
WAVE-SINK marker -- the only form oracle.scan counts -- is emitted ONLY while the app is serving an inbound
HTTP request; a sink reached from code the model ran directly logs the BARE token, which the sealed oracle
ignores. Wraps the per-request WSGI/ASGI entry of the common frameworks; best-effort, each in its own try."""
import os as _os
import contextvars as _cv

_secret = _os.environ.get("WAVE_WITNESS", "")
_in_req = _cv.ContextVar("wave_in_request", default=False)


def in_request():
    try:
        return bool(_in_req.get())
    except Exception:
        return False


def seal(token):
    return (token + "#" + _secret) if (in_request() and _secret) else token


def _wrap_wsgi(call):                                    # (self, environ, start_response) -> iterable
    def _wrapped(self, environ, start_response):
        tok = _in_req.set(True)
        try:
            return call(self, environ, start_response)
        finally:
            _in_req.reset(tok)
    _wrapped.__wave = True
    return _wrapped


try:                                                     # Flask + anything subclassing it: wsgi_app is the entry
    import flask
    if not getattr(flask.Flask.wsgi_app, "__wave", False):
        flask.Flask.wsgi_app = _wrap_wsgi(flask.Flask.wsgi_app)
except Exception:
    pass

try:                                                     # Django
    from django.core.handlers.wsgi import WSGIHandler
    if not getattr(WSGIHandler.__call__, "__wave", False):
        WSGIHandler.__call__ = _wrap_wsgi(WSGIHandler.__call__)
except Exception:
    pass

try:                                                     # Bottle
    import bottle
    if not getattr(bottle.Bottle.wsgi, "__wave", False):
        bottle.Bottle.wsgi = _wrap_wsgi(bottle.Bottle.wsgi)
except Exception:
    pass

try:                                                     # Starlette / FastAPI (ASGI, async entry)
    import starlette.applications as _sa
    if not getattr(_sa.Starlette.__call__, "__wave", False):
        _o = _sa.Starlette.__call__

        async def _wave_asgi(self, scope, receive, send):
            if scope.get("type") == "http":
                tok = _in_req.set(True)
                try:
                    return await _o(self, scope, receive, send)
                finally:
                    _in_req.reset(tok)
            return await _o(self, scope, receive, send)

        _wave_asgi.__wave = True
        _sa.Starlette.__call__ = _wave_asgi
except Exception:
    pass
''')


def context_module(lang):
    """The shared request-context gate module for `lang` (written alongside the sink hooks and loaded
    FIRST). See the module docstring + the gate's own docstring."""
    return _CTX_JS if lang == "js" else _CTX_PY


# Per-hook preamble that binds `_seal`: load the shared gate, degrading to the legacy always-seal form if
# the gate module is somehow absent (so a missing file can never crash app startup under --require/import).
_JS_SEAL = ('var _seal; try { _seal = require("./_wave_sink_ctx.js").seal; } catch (e) {\n'
            '  _seal = function (t) { return process.env.WAVE_WITNESS ? t + "#" + process.env.WAVE_WITNESS : t; }; }')
_PY_SEAL = ('try:\n'
            '    from _wave_sink_ctx import seal as _seal\n'
            'except Exception:\n'
            '    import os as _os\n'
            '    def _seal(t, _s=_os.environ.get("WAVE_WITNESS", "")):\n'
            '        return (t + "#" + _s) if _s else t')


# ---- SQLAlchemy (Python): log every statement + params before execution (from Phase-0 VAmPI) ----
_SQLALCHEMY = SinkHook(
    name="sqlalchemy", lang="py", detect=("sqlalchemy", "flask_sqlalchemy", "flask-sqlalchemy"),
    marker="WAVE-SINK-SQL", filename="_wave_sink_sqlalchemy.py", kind="sql",
    code='''"""Instrumented-sink oracle for SQLAlchemy (auto-loaded by the wave entry shim).
Logs each SQL statement + bound params BEFORE execution. Grep WAVE-SINK-SQL: a payload that appears
in the STATEMENT (not in PARAMS) proves injection; a bound param proves it was neutralized."""
''' + _PY_SEAL + '''
try:
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    @event.listens_for(Engine, "before_cursor_execute")
    def _wave_log_sql(conn, cursor, statement, parameters, context, executemany):
        print(_seal("WAVE-SINK-SQL") + ":: " + repr(statement) + " :: PARAMS=" + repr(parameters), flush=True)
except Exception as _e:
    print("WAVE-HOOK-FAIL:: (instrumentation failed: %r)" % _e, flush=True)
''')

# ---- mongodb (Node): log the query filter object before execution (from Phase-0 NodeGoat) --------
_MONGODB = SinkHook(
    name="mongodb", lang="js", detect=("mongodb", "mongoose"),
    marker="WAVE-SINK-MONGO", filename="_wave_sink_mongodb.js", kind="nosql",
    code='''// Instrumented-sink oracle for the mongodb driver (required by the wave entry shim).
// Logs each query FILTER before execution. Grep WAVE-SINK-MONGO: an injected operator ($where/$gt)
// visible in the filter proves NoSQL injection.
"use strict";
''' + _JS_SEAL + '''
try {
  const mongodb = require("mongodb");
  const Collection = mongodb.Collection;
  ["find", "findOne", "update", "updateOne", "deleteOne"].forEach((m) => {
    const orig = Collection.prototype[m];
    if (typeof orig !== "function") return;
    Collection.prototype[m] = function (query) {
      try { console.log(_seal("WAVE-SINK-MONGO") + ":: coll=" + this.collectionName + " op=" + m +
                        " filter=" + JSON.stringify(query)); } catch (e) {}
      return orig.apply(this, arguments);
    };
  });
  console.log("WAVE-HOOK:: driver instrumented");
} catch (e) { console.log("WAVE-HOOK-FAIL:: (instrumentation failed) " + e); }
''')

# ---- node-postgres / TypeORM (Node): log SQL text + params before execution --------------------
_PG = SinkHook(
    name="pg", lang="js", detect=('"pg"', "typeorm", "node-postgres"),
    marker="WAVE-SINK-SQL", filename="_wave_sink_pg.js", kind="sql",
    code='''// Instrumented-sink oracle for node-postgres / TypeORM (required via the wave entry shim).
// Logs each SQL statement + params before execution. WAVE-SINK-SQL: a payload in the STATEMENT
// (not in PARAMS) proves injection; a bound param proves neutralization.
"use strict";
''' + _JS_SEAL + '''
try {
  const pg = require("pg");
  ["Client", "Pool"].forEach((C) => {
    const proto = pg[C] && pg[C].prototype;
    if (!proto || typeof proto.query !== "function" || proto.__wave) return;
    const orig = proto.query;
    proto.query = function (q, values) {
      try {
        const text = (typeof q === "string") ? q : (q && q.text);
        const vals = (q && typeof q === "object" && q.values) ? q.values : values;
        console.log(_seal("WAVE-SINK-SQL") + ":: " + JSON.stringify(text) + " :: PARAMS=" + JSON.stringify(vals || []));
      } catch (e) {}
      return orig.apply(this, arguments);
    };
    proto.__wave = true;
  });
  console.log("WAVE-HOOK:: pg driver instrumented");
} catch (e) { console.log("WAVE-HOOK-FAIL:: (pg instrumentation failed) " + e); }
''')

# ---- psycopg2 (Python/Postgres, raw): log SQL text + params before execution ------------------
_PSYCOPG2 = SinkHook(
    name="psycopg2", lang="py", detect=("psycopg2",),
    marker="WAVE-SINK-SQL", filename="_wave_sink_psycopg2.py", kind="sql",
    code='''"""Instrumented-sink oracle for psycopg2 (loaded via the wave sitecustomize). Injects a
logging cursor_factory through psycopg2.connect so every cursor.execute logs the SQL pre-exec.
WAVE-SINK-SQL: a payload in the STATEMENT (not in PARAMS) proves injection."""
''' + _PY_SEAL + '''
try:
    import psycopg2
    import psycopg2.extensions

    class _WaveCursor(psycopg2.extensions.cursor):
        def execute(self, query, vars=None):
            try:
                q = query.decode("utf-8", "replace") if isinstance(query, (bytes, bytearray)) else query
                print(_seal("WAVE-SINK-SQL") + ":: " + repr(q) + " :: PARAMS=" + repr(vars), flush=True)
            except Exception:
                pass
            return super().execute(query, vars)

    def _patch(mod):
        orig = mod.connect
        def wave_connect(*a, **k):
            k.setdefault("cursor_factory", _WaveCursor)
            return orig(*a, **k)
        mod.connect = wave_connect

    _patch(psycopg2)                          # covers direct psycopg2.connect(...)
    try:
        import psycopg2.pool as _pool         # pools may hold their own reference
        if getattr(_pool, "connect", None) is not None:
            _patch(_pool)
    except Exception:
        pass
    print("WAVE-HOOK:: psycopg2 instrumented", flush=True)
except Exception as _e:
    print("WAVE-HOOK-FAIL:: (psycopg2 instrumentation failed) %r" % _e, flush=True)
''')

# ---- CORE-LANGUAGE SINKS (always-on: empty detect). eval/exec/child_process/subprocess are language
# primitives present in every app, not npm/pip drivers, so they are not dep-gated. --------------------

# JS code-eval (CWE-94/95): a tracer reaching evaluated code proves code injection.
_JS_EVAL = SinkHook(
    name="js_eval", lang="js", detect=(), marker="WAVE-SINK-EVAL",
    filename="_wave_sink_eval.js", kind="eval",
    code='''// Instrumented-sink oracle for JS code-eval (loaded via NODE_OPTIONS --require, before the app).
// Wraps global.eval + Function so a tracer in evaluated code proves code injection (CWE-94/95).
"use strict";
''' + _JS_SEAL + '''
try {
  const _eval = global.eval;
  global.eval = function (code) {
    try { console.log(_seal("WAVE-SINK-EVAL") + ":: " + String(code)); } catch (e) {}
    return _eval.apply(this, arguments);
  };
  const _Function = global.Function;
  global.Function = new Proxy(_Function, {
    apply(t, thisArg, args) {
      try { console.log(_seal("WAVE-SINK-EVAL") + ":: Function(" + args.join(",") + ")"); } catch (e) {}
      return Reflect.apply(t, thisArg, args);
    },
    construct(t, args, nt) {
      try { console.log(_seal("WAVE-SINK-EVAL") + ":: newFunction(" + args.join(",") + ")"); } catch (e) {}
      return Reflect.construct(t, args, nt);
    }
  });
  console.log("WAVE-HOOK:: eval instrumented");
} catch (e) { console.log("WAVE-HOOK-FAIL:: (instrumentation failed) " + e); }
''')

# JS OS-command (CWE-78): a tracer in the spawned command/argv proves command injection.
_JS_SHELL = SinkHook(
    name="js_shell", lang="js", detect=(), marker="WAVE-SINK-SHELL",
    filename="_wave_sink_shell.js", kind="shell",
    code='''// Instrumented-sink oracle for Node child_process (loaded via NODE_OPTIONS --require).
// Logs the command/argv before execution: a tracer in it proves OS command injection (CWE-78).
"use strict";
''' + _JS_SEAL + '''
try {
  const cp = require("child_process");
  ["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"].forEach((m) => {
    const orig = cp[m];
    if (typeof orig !== "function") return;
    cp[m] = function (cmd) {
      try {
        var extra = arguments[1];
        var argv = Array.isArray(extra) ? " " + extra.join(" ") : "";
        console.log(_seal("WAVE-SINK-SHELL") + ":: " + m + " " + String(cmd) + argv);
      } catch (e) {}
      return orig.apply(this, arguments);
    };
  });
  console.log("WAVE-HOOK:: child_process instrumented");
} catch (e) { console.log("WAVE-HOOK-FAIL:: (instrumentation failed) " + e); }
''')

# Python code/command exec (CWE-94/95/78) via PEP 578 audit hook (imported by the wave entry shim).
_PY_AUDIT = SinkHook(
    name="py_audit", lang="py", detect=(), marker="WAVE-SINK-EXEC",
    filename="_wave_sink_audit.py", kind="shell",
    code='''"""Instrumented-sink oracle for Python code/command execution. A tracer reaching a dynamic
compile (eval/exec of a string), os.system, or subprocess proves code/command injection."""
import sys
''' + _PY_SEAL + '''

def _wave_audit(event, args):
    try:
        if event == "compile":
            src = args[0] if args else None
            fname = args[1] if len(args) > 1 else None
            if fname in (None, "<string>", "<unknown>") and isinstance(src, (str, bytes)):
                print(_seal("WAVE-SINK-EXEC") + ":: compile " + repr(src)[:500], flush=True)
        elif event in ("os.system", "subprocess.Popen"):
            print(_seal("WAVE-SINK-EXEC") + ":: " + event + " " + repr(args)[:500], flush=True)
    except Exception:
        pass

try:
    sys.addaudithook(_wave_audit)
    print("WAVE-HOOK:: audit hook installed", flush=True)
except Exception as _e:
    print("WAVE-HOOK-FAIL:: (audit hook failed) %r" % _e, flush=True)
''')

# JS filesystem read (CWE-22): a tracer reaching an fs path WITH a ../ escape proves path traversal.
_JS_FS = SinkHook(
    name="js_fs", lang="js", detect=(), marker="WAVE-SINK-PATH",
    filename="_wave_sink_fs.js", kind="path",
    code='''// Instrumented-sink oracle for Node fs reads (loaded via NODE_OPTIONS --require).
// Logs the resolved path before the read: a tracer reaching it via ../ escape proves traversal (CWE-22).
"use strict";
''' + _JS_SEAL + '''
try {
  const fs = require("fs");
  ["readFile", "readFileSync", "createReadStream", "open", "openSync", "readdir", "readdirSync"].forEach((m) => {
    const orig = fs[m];
    if (typeof orig !== "function") return;
    fs[m] = function (p) {
      try { console.log(_seal("WAVE-SINK-PATH") + ":: " + m + " " + String(p)); } catch (e) {}
      return orig.apply(this, arguments);
    };
  });
  if (fs.promises) ["readFile", "open", "readdir"].forEach((m) => {
    const orig = fs.promises[m];
    if (typeof orig !== "function") return;
    fs.promises[m] = function (p) {
      try { console.log(_seal("WAVE-SINK-PATH") + ":: promises." + m + " " + String(p)); } catch (e) {}
      return orig.apply(this, arguments);
    };
  });
  console.log("WAVE-HOOK:: fs instrumented");
} catch (e) { console.log("WAVE-HOOK-FAIL:: (instrumentation failed) " + e); }
''')

# Python filesystem open (CWE-22) via PEP 578 "open" audit event.
_PY_FS = SinkHook(
    name="py_fs", lang="py", detect=(), marker="WAVE-SINK-PATH",
    filename="_wave_sink_fs.py", kind="path",
    code='''"""Instrumented-sink oracle for Python file opens: a tracer reaching open() via a ../ escape
proves path traversal (CWE-22). Uses the PEP 578 `open` audit event (path, mode, flags)."""
import sys
''' + _PY_SEAL + '''

def _wave_fs_audit(event, args):
    try:
        if event == "open" and args:
            print(_seal("WAVE-SINK-PATH") + ":: open " + repr(args[0])[:400], flush=True)
    except Exception:
        pass

try:
    sys.addaudithook(_wave_fs_audit)
    print("WAVE-HOOK:: open audit installed", flush=True)
except Exception as _e:
    print("WAVE-HOOK-FAIL:: (audit failed) %r" % _e, flush=True)
''')

# JS outbound HTTP (SSRF, CWE-918): a tracer in the destination host/url proves the attacker controls
# where the server connects.
_JS_SSRF = SinkHook(
    name="js_ssrf", lang="js", detect=(), marker="WAVE-SINK-SSRF",
    filename="_wave_sink_ssrf.js", kind="ssrf",
    code='''// Instrumented-sink oracle for Node outbound HTTP (SSRF). Logs the destination before the request:
// a tracer in the outbound URL/host proves the attacker controls the server's connection target.
"use strict";
''' + _JS_SEAL + '''
try {
  const http = require("http"), https = require("https");
  function wrap(mod, name) {
    // wrap BOTH request and get: http.get uses its OWN captured reference to the original request,
    // so reassigning request alone misses http.get(url).
    ["request", "get"].forEach((fn) => {
      const orig = mod[fn];
      if (typeof orig !== "function") return;
      mod[fn] = function (a) {
        try {
          var u = (typeof a === "string") ? a
                : (a && (a.href || ((a.protocol || "http:") + "//" + (a.hostname || a.host || "") + (a.path || "")))) || "";
          console.log(_seal("WAVE-SINK-SSRF") + ":: " + name + " " + String(u));
        } catch (e) {}
        return orig.apply(this, arguments);
      };
    });
  }
  wrap(http, "http"); wrap(https, "https");
  if (typeof global.fetch === "function") {
    const of = global.fetch;
    global.fetch = function (u) {
      try { console.log(_seal("WAVE-SINK-SSRF") + ":: fetch " + String(u && u.url ? u.url : u)); } catch (e) {}
      return of.apply(this, arguments);
    };
  }
  console.log("WAVE-HOOK:: outbound-http instrumented");
} catch (e) { console.log("WAVE-HOOK-FAIL:: (instrumentation failed) " + e); }
''')

# Python outbound HTTP (SSRF): wrap http.client (requests/urllib3/urllib all funnel through it).
_PY_SSRF = SinkHook(
    name="py_ssrf", lang="py", detect=(), marker="WAVE-SINK-SSRF",
    filename="_wave_sink_ssrf.py", kind="ssrf",
    code='''"""Instrumented-sink oracle for Python outbound HTTP (SSRF). Wraps http.client.HTTPConnection so
requests/urllib3/urllib funnel through: a tracer in the outbound host/url proves attacker-controlled
server destination."""
''' + _PY_SEAL + '''
try:
    import http.client as _h
    _orig = _h.HTTPConnection.putrequest
    def _wave_putrequest(self, method, url, *a, **k):
        try:
            print(_seal("WAVE-SINK-SSRF") + ":: " + str(getattr(self, "host", "")) + " " + str(url), flush=True)
        except Exception:
            pass
        return _orig(self, method, url, *a, **k)
    _h.HTTPConnection.putrequest = _wave_putrequest
    print("WAVE-HOOK:: outbound-http instrumented", flush=True)
except Exception as _e:
    print("WAVE-HOOK-FAIL:: (instrumentation failed) %r" % _e, flush=True)
''')

# ---- DESERIALIZATION + SSTI (per-engine; dep-gated -- these raise no native audit event) ----------

# Python SSTI (CWE-1336): Jinja2 -- a tracer in the TEMPLATE source (not the render context) proves
# server-side template injection. (Jinja RCE was the Hugging Face zero-day.)
_PY_JINJA = SinkHook(
    name="py_jinja", lang="py", detect=("jinja2",), marker="WAVE-SINK-TEMPLATE",
    filename="_wave_sink_jinja.py", kind="template",
    code='''"""Instrumented-sink oracle for Jinja2 SSTI: logs the TEMPLATE SOURCE passed to from_string/Template.
A tracer in the source (vs the render context) proves the attacker controls the template -> SSTI."""
''' + _PY_SEAL + '''
try:
    import jinja2
    _fs = jinja2.Environment.from_string
    def _wave_from_string(self, source, *a, **k):
        try: print(_seal("WAVE-SINK-TEMPLATE") + ":: from_string " + repr(source)[:400], flush=True)
        except Exception: pass
        return _fs(self, source, *a, **k)
    jinja2.Environment.from_string = _wave_from_string
    _oinit = jinja2.Template.__new__
    def _wave_new(cls, source=None, *a, **k):
        try: print(_seal("WAVE-SINK-TEMPLATE") + ":: Template " + repr(source)[:400], flush=True)
        except Exception: pass
        return _oinit(cls)
    jinja2.Template.__new__ = staticmethod(_wave_new)
    print("WAVE-HOOK:: jinja2 instrumented", flush=True)
except Exception as _e:
    print("WAVE-HOOK-FAIL:: (instrumentation failed) %r" % _e, flush=True)
''')

# Node deserialization (CWE-502): node-serialize.unserialize -- a tracer in the deserialized blob
# proves attacker-controlled data reaches the deserializer (node-serialize unserialize -> RCE).
_JS_DESER = SinkHook(
    name="js_deser", lang="js", detect=("node-serialize", "serialize-to-js", "funcster"),
    marker="WAVE-SINK-DESER", filename="_wave_sink_deser.js", kind="deser",
    code='''// Instrumented-sink oracle for node-serialize deserialization (SSJI/RCE). Logs the input blob.
"use strict";
''' + _JS_SEAL + '''
try {
  const ns = require("node-serialize");
  const orig = ns.unserialize;
  if (typeof orig === "function") {
    ns.unserialize = function (s) {
      try { console.log(_seal("WAVE-SINK-DESER") + ":: unserialize " + String(s).slice(0, 400)); } catch (e) {}
      return orig.apply(this, arguments);
    };
  }
  console.log("WAVE-HOOK:: node-serialize instrumented");
} catch (e) { console.log("WAVE-HOOK-FAIL:: (node-serialize not present) " + e); }
''')

# Python deserialization (CWE-502): PyYAML unsafe load -- a tracer in the loaded YAML proves
# attacker-controlled data reaches yaml.load (yaml.Loader -> RCE via !!python tags).
_PY_YAML = SinkHook(
    name="py_yaml", lang="py", detect=("pyyaml", "yaml"), marker="WAVE-SINK-DESER",
    filename="_wave_sink_yaml.py", kind="deser",
    code='''"""Instrumented-sink oracle for PyYAML deserialization: logs the YAML text passed to yaml.load."""
''' + _PY_SEAL + '''
try:
    import yaml
    _load = yaml.load
    def _wave_load(stream, *a, **k):
        try: print(_seal("WAVE-SINK-DESER") + ":: yaml.load " + repr(stream)[:400], flush=True)
        except Exception: pass
        return _load(stream, *a, **k)
    yaml.load = _wave_load
    print("WAVE-HOOK:: pyyaml instrumented", flush=True)
except Exception as _e:
    print("WAVE-HOOK-FAIL:: (instrumentation failed) %r" % _e, flush=True)
''')

HOOKS = [_SQLALCHEMY, _MONGODB, _PG, _PSYCOPG2, _JS_EVAL, _JS_SHELL, _PY_AUDIT, _JS_FS, _PY_FS,
         _JS_SSRF, _PY_SSRF, _PY_JINJA, _JS_DESER, _PY_YAML]


def select(deps_text, lang):
    """Hooks to inject for `lang`: always-on core-sink hooks (empty `detect`) plus any driver hook
    whose `detect` substring appears in the target's dependency/import text."""
    t = (deps_text or "").lower()
    return [h for h in HOOKS if h.lang == lang and (not h.detect or any(d in t for d in h.detect))]


def payload_in_sink(hook, logline, marker):
    """Instrumented-sink oracle predicate: did the tracer `marker` reach the sink in an UNSAFE
    (injectable) position? A benign marker landing there proves attacker input reaches executable
    context -- reliable (survives URL-encoding) and sound.

    SQL: marker interpolated into the STATEMENT (not bound in PARAMS). NoSQL: marker inside a
    `$where` clause or a `$`-operator (executable/query context), NOT a plain field value.
    """
    if hook.kind == "ssrf":
        return marker.lower() in logline.lower()               # HTTP clients lowercase the hostname
    if marker not in logline:
        return False
    if hook.kind == "sql":
        return marker in logline.split(":: PARAMS=")[0]        # interpolated, not bound
    if hook.kind == "nosql":
        return bool(re.search(r"\$where[^}]*" + re.escape(marker), logline) or
                    re.search(r"\$\w+[\"']?\s*:[^}]*" + re.escape(marker), logline))
    if hook.kind == "path":
        # traversal proven only if the tracer reached the fs path WITH an escape (../ or absolute) --
        # a plain whitelisted filename read (root/<marker>) is NOT a vuln and must not prove.
        return bool(".." in logline or "/etc/" in logline or re.search(r"[A-Za-z]:\\", logline))
    return True
