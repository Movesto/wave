"""DOM / XSS oracle -- the browser-side sensor.

XSS executes in the browser, so no backend sink hook fires. We render the app's response in headless
Chromium (with the attacker's session) and detect whether the injected tracer actually EXECUTED --
mere reflection in a safe context (text/attribute) does NOT fire and is correctly not proven. That
execution witness is what makes this sound (Tier-1), same idea as the instrumented sink.

Runs as a serialized sub-phase: Chromium is heavy, so ideally the 14B is offloaded while it renders
(master_plan §5.6); for the MVP it runs alongside (system-RAM cost only -- the browser is not on the
GPU). Playwright is imported lazily so the package loads even when it isn't installed.
"""
from urllib.parse import urlparse

# Injected before any page script: capture script-execution signals carrying the tracer.
_INIT = """
window.__WAVE_XSS__ = [];
for (const fn of ['alert','confirm','prompt']) {
  try { const o = window[fn];
        window[fn] = function(x){ try{ window.__WAVE_XSS__.push(fn+':'+String(x)); }catch(e){} return o&&o.call?undefined:undefined; };
  } catch(e){}
}
window.waveXSS = function(x){ try{ window.__WAVE_XSS__.push('waveXSS:'+String(x)); }catch(e){} };
"""


def _cookies_from(headers, url):
    ck = (headers or {}).get("Cookie") or (headers or {}).get("cookie")
    if not ck:
        return []
    host = urlparse(url).hostname or "localhost"
    out = []
    for part in ck.split(";"):
        if "=" in part:
            n, v = part.strip().split("=", 1)
            out.append({"name": n, "value": v, "domain": host, "path": "/"})
    return out


def available():
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        return False


def prove_xss(url, headers, marker, timeout=8000, html=None):
    """Render `url` (or raw `html`) in headless Chromium with the attacker's cookies; PROVEN if the
    tracer executed in the DOM (alert/confirm/prompt/waveXSS carrying the marker)."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        return {"status": "not-proven", "cwe": "CWE-79", "notes": f"playwright unavailable: {e}"}
    captured = []
    try:
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-gpu"])
            ctx = b.new_context(ignore_https_errors=True)
            ctx.add_init_script(_INIT)
            cks = _cookies_from(headers, url)
            if cks:
                try: ctx.add_cookies(cks)
                except Exception: pass
            page = ctx.new_page()
            page.on("dialog", lambda d: (captured.append("dialog:" + d.message), d.dismiss()))
            try:
                if html is not None:
                    page.set_content(html, wait_until="load", timeout=timeout)
                else:
                    page.goto(url, wait_until="load", timeout=timeout)
                page.wait_for_timeout(500)
                captured += page.evaluate("window.__WAVE_XSS__ || []")
            except Exception:
                pass
            b.close()
    except Exception as e:
        return {"status": "not-proven", "cwe": "CWE-79", "notes": f"browser error: {str(e)[:120]}"}
    hits = [c for c in captured if marker in str(c)]
    if hits:
        return {"status": "proven", "cwe": "CWE-79", "oracle": "dom",
                "payload": marker, "request": url,
                "evidence": f"tracer executed in the rendered DOM: {str(hits[0])[:140]}"}
    return {"status": "not-proven", "cwe": "CWE-79",
            "notes": f"tracer did not execute ({len(captured)} exec events observed, none with marker)"}
