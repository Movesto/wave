"""Instrumented-sink oracle for Python outbound HTTP (SSRF). Wraps http.client.HTTPConnection so
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
