"""Sink Instrumentation Registry — the crux component.

A curated library of per-driver "modified drivers": each turns a sink into a verifiable oracle by
logging the exact value that reaches it BEFORE execution (marker `WAVE-SINK-<KIND>`). Seeded by the
Phase-0 hooks proven on VAmPI (SQLAlchemy) and NodeGoat (mongodb). The instrumented-sink oracle
(oracle.py, later) greps these markers to PROVE a payload reached the sink unescaped.

Per the Phase-0 finding (F1/R2/G1): instrumentation is PER-DRIVER, so this is an extensible list,
not a one-off. Add a hook per (driver) as new stacks are targeted.
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


# ---- SQLAlchemy (Python): log every statement + params before execution (from Phase-0 VAmPI) ----
_SQLALCHEMY = SinkHook(
    name="sqlalchemy", lang="py", detect=("sqlalchemy", "flask_sqlalchemy", "flask-sqlalchemy"),
    marker="WAVE-SINK-SQL", filename="_wave_sink_sqlalchemy.py", kind="sql",
    code='''"""Instrumented-sink oracle for SQLAlchemy (auto-loaded by the wave entry shim).
Logs each SQL statement + bound params BEFORE execution. Grep WAVE-SINK-SQL: a payload that appears
in the STATEMENT (not in PARAMS) proves injection; a bound param proves it was neutralized."""
try:
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    @event.listens_for(Engine, "before_cursor_execute")
    def _wave_log_sql(conn, cursor, statement, parameters, context, executemany):
        print("WAVE-SINK-SQL:: " + repr(statement) + " :: PARAMS=" + repr(parameters), flush=True)
except Exception as _e:
    print("WAVE-SINK-SQL:: (instrumentation failed: %r)" % _e, flush=True)
''')

# ---- mongodb (Node): log the query filter object before execution (from Phase-0 NodeGoat) --------
_MONGODB = SinkHook(
    name="mongodb", lang="js", detect=("mongodb", "mongoose"),
    marker="WAVE-SINK-MONGO", filename="_wave_sink_mongodb.js", kind="nosql",
    code='''// Instrumented-sink oracle for the mongodb driver (required by the wave entry shim).
// Logs each query FILTER before execution. Grep WAVE-SINK-MONGO: an injected operator ($where/$gt)
// visible in the filter proves NoSQL injection.
"use strict";
try {
  const mongodb = require("mongodb");
  const Collection = mongodb.Collection;
  ["find", "findOne", "update", "updateOne", "deleteOne"].forEach((m) => {
    const orig = Collection.prototype[m];
    if (typeof orig !== "function") return;
    Collection.prototype[m] = function (query) {
      try { console.log("WAVE-SINK-MONGO:: coll=" + this.collectionName + " op=" + m +
                        " filter=" + JSON.stringify(query)); } catch (e) {}
      return orig.apply(this, arguments);
    };
  });
  console.log("WAVE-SINK-MONGO:: driver instrumented");
} catch (e) { console.log("WAVE-SINK-MONGO:: (instrumentation failed) " + e); }
''')

# ---- node-postgres / TypeORM (Node): log SQL text + params before execution --------------------
_PG = SinkHook(
    name="pg", lang="js", detect=('"pg"', "typeorm", "node-postgres"),
    marker="WAVE-SINK-SQL", filename="_wave_sink_pg.js", kind="sql",
    code='''// Instrumented-sink oracle for node-postgres / TypeORM (required via the wave entry shim).
// Logs each SQL statement + params before execution. WAVE-SINK-SQL: a payload in the STATEMENT
// (not in PARAMS) proves injection; a bound param proves neutralization.
"use strict";
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
        console.log("WAVE-SINK-SQL:: " + JSON.stringify(text) + " :: PARAMS=" + JSON.stringify(vals || []));
      } catch (e) {}
      return orig.apply(this, arguments);
    };
    proto.__wave = true;
  });
  console.log("WAVE-SINK-SQL:: pg driver instrumented");
} catch (e) { console.log("WAVE-SINK-SQL:: (pg instrumentation failed) " + e); }
''')

# ---- psycopg2 (Python/Postgres, raw): log SQL text + params before execution ------------------
_PSYCOPG2 = SinkHook(
    name="psycopg2", lang="py", detect=("psycopg2",),
    marker="WAVE-SINK-SQL", filename="_wave_sink_psycopg2.py", kind="sql",
    code='''"""Instrumented-sink oracle for psycopg2 (loaded via the wave sitecustomize). Injects a
logging cursor_factory through psycopg2.connect so every cursor.execute logs the SQL pre-exec.
WAVE-SINK-SQL: a payload in the STATEMENT (not in PARAMS) proves injection."""
try:
    import psycopg2
    import psycopg2.extensions

    class _WaveCursor(psycopg2.extensions.cursor):
        def execute(self, query, vars=None):
            try:
                q = query.decode("utf-8", "replace") if isinstance(query, (bytes, bytearray)) else query
                print("WAVE-SINK-SQL:: " + repr(q) + " :: PARAMS=" + repr(vars), flush=True)
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
    print("WAVE-SINK-SQL:: psycopg2 instrumented", flush=True)
except Exception as _e:
    print("WAVE-SINK-SQL:: (psycopg2 instrumentation failed) %r" % _e, flush=True)
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
try {
  const _eval = global.eval;
  global.eval = function (code) {
    try { console.log("WAVE-SINK-EVAL:: " + String(code)); } catch (e) {}
    return _eval.apply(this, arguments);
  };
  const _Function = global.Function;
  global.Function = new Proxy(_Function, {
    apply(t, thisArg, args) {
      try { console.log("WAVE-SINK-EVAL:: Function(" + args.join(",") + ")"); } catch (e) {}
      return Reflect.apply(t, thisArg, args);
    },
    construct(t, args, nt) {
      try { console.log("WAVE-SINK-EVAL:: newFunction(" + args.join(",") + ")"); } catch (e) {}
      return Reflect.construct(t, args, nt);
    }
  });
  console.log("WAVE-SINK-EVAL:: eval instrumented");
} catch (e) { console.log("WAVE-SINK-EVAL:: (instrumentation failed) " + e); }
''')

# JS OS-command (CWE-78): a tracer in the spawned command/argv proves command injection.
_JS_SHELL = SinkHook(
    name="js_shell", lang="js", detect=(), marker="WAVE-SINK-SHELL",
    filename="_wave_sink_shell.js", kind="shell",
    code='''// Instrumented-sink oracle for Node child_process (loaded via NODE_OPTIONS --require).
// Logs the command/argv before execution: a tracer in it proves OS command injection (CWE-78).
"use strict";
try {
  const cp = require("child_process");
  ["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"].forEach((m) => {
    const orig = cp[m];
    if (typeof orig !== "function") return;
    cp[m] = function (cmd) {
      try {
        var extra = arguments[1];
        var argv = Array.isArray(extra) ? " " + extra.join(" ") : "";
        console.log("WAVE-SINK-SHELL:: " + m + " " + String(cmd) + argv);
      } catch (e) {}
      return orig.apply(this, arguments);
    };
  });
  console.log("WAVE-SINK-SHELL:: child_process instrumented");
} catch (e) { console.log("WAVE-SINK-SHELL:: (instrumentation failed) " + e); }
''')

# Python code/command exec (CWE-94/95/78) via PEP 578 audit hook (imported by the wave entry shim).
_PY_AUDIT = SinkHook(
    name="py_audit", lang="py", detect=(), marker="WAVE-SINK-EXEC",
    filename="_wave_sink_audit.py", kind="shell",
    code='''"""Instrumented-sink oracle for Python code/command execution. A tracer reaching a dynamic
compile (eval/exec of a string), os.system, or subprocess proves code/command injection."""
import sys

def _wave_audit(event, args):
    try:
        if event == "compile":
            src = args[0] if args else None
            fname = args[1] if len(args) > 1 else None
            if fname in (None, "<string>", "<unknown>") and isinstance(src, (str, bytes)):
                print("WAVE-SINK-EXEC:: compile " + repr(src)[:500], flush=True)
        elif event in ("os.system", "subprocess.Popen"):
            print("WAVE-SINK-EXEC:: " + event + " " + repr(args)[:500], flush=True)
    except Exception:
        pass

try:
    sys.addaudithook(_wave_audit)
    print("WAVE-SINK-EXEC:: audit hook installed", flush=True)
except Exception as _e:
    print("WAVE-SINK-EXEC:: (audit hook failed) %r" % _e, flush=True)
''')

# JS filesystem read (CWE-22): a tracer reaching an fs path WITH a ../ escape proves path traversal.
_JS_FS = SinkHook(
    name="js_fs", lang="js", detect=(), marker="WAVE-SINK-PATH",
    filename="_wave_sink_fs.js", kind="path",
    code='''// Instrumented-sink oracle for Node fs reads (loaded via NODE_OPTIONS --require).
// Logs the resolved path before the read: a tracer reaching it via ../ escape proves traversal (CWE-22).
"use strict";
try {
  const fs = require("fs");
  ["readFile", "readFileSync", "createReadStream", "open", "openSync", "readdir", "readdirSync"].forEach((m) => {
    const orig = fs[m];
    if (typeof orig !== "function") return;
    fs[m] = function (p) {
      try { console.log("WAVE-SINK-PATH:: " + m + " " + String(p)); } catch (e) {}
      return orig.apply(this, arguments);
    };
  });
  if (fs.promises) ["readFile", "open", "readdir"].forEach((m) => {
    const orig = fs.promises[m];
    if (typeof orig !== "function") return;
    fs.promises[m] = function (p) {
      try { console.log("WAVE-SINK-PATH:: promises." + m + " " + String(p)); } catch (e) {}
      return orig.apply(this, arguments);
    };
  });
  console.log("WAVE-SINK-PATH:: fs instrumented");
} catch (e) { console.log("WAVE-SINK-PATH:: (instrumentation failed) " + e); }
''')

# Python filesystem open (CWE-22) via PEP 578 "open" audit event.
_PY_FS = SinkHook(
    name="py_fs", lang="py", detect=(), marker="WAVE-SINK-PATH",
    filename="_wave_sink_fs.py", kind="path",
    code='''"""Instrumented-sink oracle for Python file opens: a tracer reaching open() via a ../ escape
proves path traversal (CWE-22). Uses the PEP 578 `open` audit event (path, mode, flags)."""
import sys

def _wave_fs_audit(event, args):
    try:
        if event == "open" and args:
            print("WAVE-SINK-PATH:: open " + repr(args[0])[:400], flush=True)
    except Exception:
        pass

try:
    sys.addaudithook(_wave_fs_audit)
    print("WAVE-SINK-PATH:: open audit installed", flush=True)
except Exception as _e:
    print("WAVE-SINK-PATH:: (audit failed) %r" % _e, flush=True)
''')

# JS outbound HTTP (SSRF, CWE-918): a tracer in the destination host/url proves the attacker controls
# where the server connects.
_JS_SSRF = SinkHook(
    name="js_ssrf", lang="js", detect=(), marker="WAVE-SINK-SSRF",
    filename="_wave_sink_ssrf.js", kind="ssrf",
    code='''// Instrumented-sink oracle for Node outbound HTTP (SSRF). Logs the destination before the request:
// a tracer in the outbound URL/host proves the attacker controls the server's connection target.
"use strict";
try {
  const http = require("http"), https = require("https");
  function wrap(mod, name) {
    const orig = mod.request;
    if (typeof orig !== "function") return;
    mod.request = function (a) {
      try {
        var u = (typeof a === "string") ? a
              : (a && (a.href || ((a.protocol || "http:") + "//" + (a.hostname || a.host || "") + (a.path || "")))) || "";
        console.log("WAVE-SINK-SSRF:: " + name + " " + String(u));
      } catch (e) {}
      return orig.apply(this, arguments);
    };
  }
  wrap(http, "http"); wrap(https, "https");
  if (typeof global.fetch === "function") {
    const of = global.fetch;
    global.fetch = function (u) {
      try { console.log("WAVE-SINK-SSRF:: fetch " + String(u && u.url ? u.url : u)); } catch (e) {}
      return of.apply(this, arguments);
    };
  }
  console.log("WAVE-SINK-SSRF:: outbound-http instrumented");
} catch (e) { console.log("WAVE-SINK-SSRF:: (instrumentation failed) " + e); }
''')

# Python outbound HTTP (SSRF): wrap http.client (requests/urllib3/urllib all funnel through it).
_PY_SSRF = SinkHook(
    name="py_ssrf", lang="py", detect=(), marker="WAVE-SINK-SSRF",
    filename="_wave_sink_ssrf.py", kind="ssrf",
    code='''"""Instrumented-sink oracle for Python outbound HTTP (SSRF). Wraps http.client.HTTPConnection so
requests/urllib3/urllib funnel through: a tracer in the outbound host/url proves attacker-controlled
server destination."""
try:
    import http.client as _h
    _orig = _h.HTTPConnection.putrequest
    def _wave_putrequest(self, method, url, *a, **k):
        try:
            print("WAVE-SINK-SSRF:: " + str(getattr(self, "host", "")) + " " + str(url), flush=True)
        except Exception:
            pass
        return _orig(self, method, url, *a, **k)
    _h.HTTPConnection.putrequest = _wave_putrequest
    print("WAVE-SINK-SSRF:: outbound-http instrumented", flush=True)
except Exception as _e:
    print("WAVE-SINK-SSRF:: (instrumentation failed) %r" % _e, flush=True)
''')

# ---- DESERIALIZATION + SSTI (per-engine; dep-gated -- these raise no native audit event) ----------

# Python SSTI (CWE-1336): Jinja2 -- a tracer in the TEMPLATE source (not the render context) proves
# server-side template injection. (Jinja RCE was the Hugging Face zero-day.)
_PY_JINJA = SinkHook(
    name="py_jinja", lang="py", detect=("jinja2",), marker="WAVE-SINK-TEMPLATE",
    filename="_wave_sink_jinja.py", kind="template",
    code='''"""Instrumented-sink oracle for Jinja2 SSTI: logs the TEMPLATE SOURCE passed to from_string/Template.
A tracer in the source (vs the render context) proves the attacker controls the template -> SSTI."""
try:
    import jinja2
    _fs = jinja2.Environment.from_string
    def _wave_from_string(self, source, *a, **k):
        try: print("WAVE-SINK-TEMPLATE:: from_string " + repr(source)[:400], flush=True)
        except Exception: pass
        return _fs(self, source, *a, **k)
    jinja2.Environment.from_string = _wave_from_string
    _oinit = jinja2.Template.__new__
    def _wave_new(cls, source=None, *a, **k):
        try: print("WAVE-SINK-TEMPLATE:: Template " + repr(source)[:400], flush=True)
        except Exception: pass
        return _oinit(cls)
    jinja2.Template.__new__ = staticmethod(_wave_new)
    print("WAVE-SINK-TEMPLATE:: jinja2 instrumented", flush=True)
except Exception as _e:
    print("WAVE-SINK-TEMPLATE:: (instrumentation failed) %r" % _e, flush=True)
''')

# Node deserialization (CWE-502): node-serialize.unserialize -- a tracer in the deserialized blob
# proves attacker-controlled data reaches the deserializer (node-serialize unserialize -> RCE).
_JS_DESER = SinkHook(
    name="js_deser", lang="js", detect=("node-serialize", "serialize-to-js", "funcster"),
    marker="WAVE-SINK-DESER", filename="_wave_sink_deser.js", kind="deser",
    code='''// Instrumented-sink oracle for node-serialize deserialization (SSJI/RCE). Logs the input blob.
"use strict";
try {
  const ns = require("node-serialize");
  const orig = ns.unserialize;
  if (typeof orig === "function") {
    ns.unserialize = function (s) {
      try { console.log("WAVE-SINK-DESER:: unserialize " + String(s).slice(0, 400)); } catch (e) {}
      return orig.apply(this, arguments);
    };
  }
  console.log("WAVE-SINK-DESER:: node-serialize instrumented");
} catch (e) { console.log("WAVE-SINK-DESER:: (not present) " + e); }
''')

# Python deserialization (CWE-502): PyYAML unsafe load -- a tracer in the loaded YAML proves
# attacker-controlled data reaches yaml.load (yaml.Loader -> RCE via !!python tags).
_PY_YAML = SinkHook(
    name="py_yaml", lang="py", detect=("pyyaml", "yaml"), marker="WAVE-SINK-DESER",
    filename="_wave_sink_yaml.py", kind="deser",
    code='''"""Instrumented-sink oracle for PyYAML deserialization: logs the YAML text passed to yaml.load."""
try:
    import yaml
    _load = yaml.load
    def _wave_load(stream, *a, **k):
        try: print("WAVE-SINK-DESER:: yaml.load " + repr(stream)[:400], flush=True)
        except Exception: pass
        return _load(stream, *a, **k)
    yaml.load = _wave_load
    print("WAVE-SINK-DESER:: pyyaml instrumented", flush=True)
except Exception as _e:
    print("WAVE-SINK-DESER:: (instrumentation failed) %r" % _e, flush=True)
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
