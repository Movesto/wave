"""The model's eyes on the world -- a LIVE web lookup, opt-in via --online.

The box is otherwise fully local. This is the one place it reaches out, and only when the model is UNSURE
(an unfamiliar API/library/framework, or a third-party service like AWS whose behaviour it must understand
to judge a flow). Two tools:
  web_search(query) -> FIND: DuckDuckGo's keyless HTML endpoint -> ranked title/snippet/URL lines.
  web_read(url)     -> READ ONE page DEEPLY, a tiered chain that degrades gracefully:
                       (1) Jina Reader (r.jina.ai) -- keyless, renders JS + returns clean markdown, zero
                           install (the reliable default);
                       (2) crawl4ai -- richer, if it (and its browser) happen to be installed locally;
                       (3) a lightweight requests+strip fallback -- last resort, no deps beyond requests.
ANY failure (no network, blocked, parse miss, missing dep) degrades to '' so the loop just proceeds on what
the model already knows. Nothing here decides a verdict; it only supplies context -- the proof still comes
from the deterministic oracle / observed effect, never from a web result.
"""
import html as _html
import re

_DDG = "https://html.duckduckgo.com/html/"
# DDG HTML: <a class="result__a" href="URL">TITLE</a> ... <a class="result__snippet" ...>SNIPPET</a>
_RESULT = re.compile(r'result__a[^>]*href="(.*?)"[^>]*>(.*?)</a>.*?result__snippet[^>]*>(.*?)</a>', re.S)
_TAG = re.compile(r"<[^>]+>")
_UDDG = re.compile(r"uddg=([^&]+)")


def _clean(s):
    return _html.unescape(_TAG.sub("", s or "")).strip()


def _real_url(href):
    """DDG wraps result links as /l/?uddg=<percent-encoded-url>; unwrap to the real target."""
    m = _UDDG.search(href or "")
    if m:
        from urllib.parse import unquote
        return unquote(m.group(1))
    return _html.unescape(href or "")


def web_search(query, max_results=4, timeout=10):
    """Ranked results (title, URL, snippet) for `query`; '' on any failure / no network / no match. The URL
    lets the model then web_read() the most promising page."""
    if not query or not query.strip():
        return ""
    try:
        import requests
    except ImportError:
        return ""
    try:
        r = requests.post(_DDG, data={"q": query.strip()},
                          headers={"User-Agent": "Mozilla/5.0 (wave-auditor)"}, timeout=timeout)
        r.raise_for_status()
    except Exception:
        return ""
    out = []
    for m in _RESULT.finditer(r.text):
        url, title, snip = _real_url(m.group(1)), _clean(m.group(2)), _clean(m.group(3))
        if title and snip:
            out.append(f"- {title}\n  {url}\n  {snip}")
        if len(out) >= max_results:
            break
    return "\n".join(out)


_JINA = "https://r.jina.ai/"
# markers of a bot-wall / captcha page Jina sometimes returns instead of the content -> treat as a miss
_BOT_WALL = ("just a moment", "cf-browser-verification", "enable javascript and cookies",
             "attention required! | cloudflare", "captcha-delivery")


def _read_jina(url, timeout):
    """Deep-read via Jina Reader -> clean markdown. Keyless, no local browser. '' on any failure/bot-wall."""
    try:
        import requests
    except ImportError:
        return ""
    try:
        r = requests.get(_JINA + url, headers={"User-Agent": "Mozilla/5.0 (wave-auditor)",
                                               "Accept": "text/markdown, text/plain, */*"},
                         timeout=timeout)
        r.raise_for_status()
    except Exception:
        return ""
    text = (r.text or "")[:5_000_000]                        # cap before any processing
    if any(m in text.lower() for m in _BOT_WALL):
        return ""
    return text


def _read_crawl4ai(url, timeout):
    """Deep-read via crawl4ai -> clean markdown. Returns '' if crawl4ai / its browser isn't available."""
    import asyncio
    try:
        from crawl4ai import AsyncWebCrawler
    except Exception:
        return ""

    async def _run():
        async with AsyncWebCrawler(verbose=False) as crawler:
            res = await crawler.arun(url=url)
            return (getattr(res, "markdown", None) or getattr(res, "cleaned_html", "") or "")

    try:
        return asyncio.run(asyncio.wait_for(_run(), timeout=timeout))
    except Exception:
        return ""


def _read_fallback(url, timeout):
    """Lightweight fallback: fetch + strip tags. Used when crawl4ai isn't installed."""
    try:
        import requests
    except ImportError:
        return ""
    try:
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0 (wave-auditor)"}, timeout=timeout)
        r.raise_for_status()
    except Exception:
        return ""
    body = re.sub(r"(?is)<(script|style|nav|footer|header)[^>]*>.*?</\1>", " ", r.text)
    return _clean(body)


def web_read(url, max_chars=6000, timeout=25):
    """Read ONE page deeply -> clean text/markdown, truncated to max_chars. Tries Jina Reader (keyless,
    default), then crawl4ai (if installed), then a requests+strip fallback; '' on any failure. For
    understanding an unfamiliar API / third-party service (AWS, a lib) the model must reason about --
    richer than a search snippet."""
    if not url or not url.strip().lower().startswith(("http://", "https://")):
        return ""
    u = url.strip()
    text = _read_jina(u, timeout) or _read_crawl4ai(u, timeout) or _read_fallback(u, timeout)
    text = re.sub(r"\n{3,}", "\n\n", text or "").strip()
    return text[:max_chars]
