"""Behavioral recon -- browser-as-structured-eyes (§18 #5).

The model has no vision; its equivalent of a human "watching the app" is the headless browser's
STRUCTURED output, which is richer than a screenshot for exploitation. This crawls the RUNNING app and
returns the LIVE attack surface:
  - forms   : method + action + input field names (the real input surface, incl. JS-rendered)
  - links   : same-origin hrefs (routes the static extractor may miss on client-rendered pages)
  - egress  : external hosts a page contacts (the "how it handles internal vs external" signal)

Unlike static route extraction (which reads server decorators), this sees what the app ACTUALLY
renders and calls. Primary value is Mode 2 (black-box, no code); in grey-box it augments the route
table so the missing-controls / IDOR / injection stages see forms and links too. Playwright is
imported lazily so the package loads without it.
"""
from urllib.parse import urljoin, urlparse

from . import routes as routes_mod


def recon(rt, seeds=("/",), max_pages=10):
    """Crawl from `seeds`; return {"routes": [Route...], "forms": [...], "egress": [hosts...]}."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        return {"routes": [], "forms": [], "egress": [], "error": f"playwright unavailable: {e}"}
    base = rt.base_url.rstrip("/")
    host = urlparse(base).hostname
    seen, forms, links, egress, form_keys = set(), [], set(), set(), set()
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-gpu"])
        ctx = b.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        page.on("request", lambda r: _note_egress(r.url, host, egress))
        queue = list(seeds)
        while queue and len(seen) < max_pages:
            path = queue.pop(0)
            if path in seen:
                continue
            seen.add(path)
            try:
                page.goto(base + path, wait_until="load", timeout=8000)
                page.wait_for_timeout(200)
            except Exception:
                continue
            for f in page.query_selector_all("form"):
                action = f.get_attribute("action") or path
                method = (f.get_attribute("method") or "GET").upper()
                fields = [i.get_attribute("name")
                          for i in f.query_selector_all("input, textarea, select")
                          if i.get_attribute("name")]
                fpath = urlparse(urljoin(base + path, action)).path
                key = (method, fpath, tuple(fields))
                if key not in form_keys:                 # dedup: same form found on many crawled pages
                    form_keys.add(key)
                    forms.append({"method": method, "path": fpath, "fields": fields})
            for a in page.query_selector_all("a[href]"):
                u = urljoin(base + path, a.get_attribute("href") or "")
                if urlparse(u).hostname == host and urlparse(u).path:
                    lp = urlparse(u).path
                    links.add(lp)
                    if lp not in seen:
                        queue.append(lp)
        b.close()

    disc = [routes_mod.Route(f["method"], f["path"], "<browser-recon>", "") for f in forms]
    disc += [routes_mod.Route("GET", lp, "<browser-recon>", "") for lp in sorted(links)]
    return {"routes": disc, "forms": forms, "egress": sorted(h for h in egress if h)}


def _note_egress(url, host, egress):
    try:
        h = urlparse(url).hostname
        if h and h != host:
            egress.add(h)
    except Exception:
        pass
