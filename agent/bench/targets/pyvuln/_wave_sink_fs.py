"""Instrumented-sink oracle for Python file opens: a tracer reaching open() via a ../ escape
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
