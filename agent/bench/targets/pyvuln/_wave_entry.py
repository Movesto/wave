"""wave entry shim: load sink hooks + disable reloaders, then run the app as __main__."""
import sys, runpy
import _wave_sink_sqlalchemy
import _wave_sink_audit
import _wave_sink_fs
import _wave_sink_ssrf
import _wave_sink_jinja
try:
    import flask
    _o = flask.Flask.run
    flask.Flask.run = lambda self, *a, **k: _o(self, *a, **{**k, "use_reloader": False})
except Exception:
    pass
runpy.run_path(sys.argv[1] if len(sys.argv) > 1 else "app.py", run_name="__main__")
