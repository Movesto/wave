"""Instrumented-sink oracle for Python code/command execution. A tracer reaching a dynamic
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
