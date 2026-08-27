"""The model's eyes on the world -- a LIVE web lookup, opt-in via --online.

The box is otherwise fully local. This is the one place it reaches out, and only when the Reader
forms a hypothesis it is UNSURE about (an unfamiliar API, library, or framework behaviour): the model
asks a question, we look it up, and the evidence goes back to the brain before it finalizes. Kept
deliberately small -- DuckDuckGo's keyless HTML endpoint, regex-parsed snippets, a hard timeout, and
ANY failure (no network, blocked, parse miss) degrades to '' so the loop simply proceeds on what the
model already knows. Nothing here decides a verdict; it only supplies context. The proof still comes
from the deterministic oracle, never from a search result.
"""
import html as _html
import re

_DDG = "https://html.duckduckgo.com/html/"
# DDG HTML: <a class="result__a" ...>TITLE</a> ... <a class="result__snippet" ...>SNIPPET</a>
_RESULT = re.compile(r'result__a[^>]*>(.*?)</a>.*?result__snippet[^>]*>(.*?)</a>', re.S)
_TAG = re.compile(r"<[^>]+>")


def _clean(s):
    return _html.unescape(_TAG.sub("", s or "")).strip()


def web_search(query, max_results=3, timeout=10):
    """Compact text digest of the top results for `query`; '' on any failure / no network / no match."""
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
        title, snip = _clean(m.group(1)), _clean(m.group(2))
        if title and snip:
            out.append(f"- {title}: {snip}")
        if len(out) >= max_results:
            break
    return "\n".join(out)
