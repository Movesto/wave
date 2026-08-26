"""Instrumented-sink oracle for Jinja2 SSTI: logs the TEMPLATE SOURCE passed to from_string/Template.
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
