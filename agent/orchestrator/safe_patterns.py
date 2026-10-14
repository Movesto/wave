"""Known-safe deterministic pre-filter (sast-improvements-v2 #3).

Before the detector spends a model call (and later prove budget) falsifying a finding, clear the textbook
SAFE shapes deterministically: a parameterized/bound query, an argv-array exec with no shell, a fetch
behind an SSRF guard, a contained filesystem path. On OpenWA the model burned 8-16 "investigate" runs per
item re-deriving exactly these ("TypeORM binds params", "spawn argv-array", "ssrf-guard wraps the fetch").

Discipline: this **clears only, never confirms** (plan §4). A clear is a deterministic refute, so the
dangerous direction is a FALSE clear (a missed bug). Each recognizer therefore requires a positive SAFE
signal AND the ABSENCE of the matching danger signal (interpolation / shell / NoSQL operator / traversal).
It inspects a source WINDOW around the sink (the detector's slice); unknown classes return None (fall
through to the model).
"""
from __future__ import annotations

import re


def _cmd(w):
    """OS command: an argv-array exec (spawn/execFile/subprocess([...])/exec.Command) with NO shell."""
    argv = re.search(r"\b(?:spawn|execFile|spawnSync|execFileSync)\s*\(|"
                     r"subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(\s*\[|"
                     r"exec\.Command\s*\(|ProcessBuilder\s*\(", w)
    shell = re.search(r"shell\s*[:=]\s*(?:true|True)|/bin/(?:sh|bash)\b|\bos\.system\s*\(|\bos\.popen\s*\(|"
                      r"`[^`]*\$\{|child_process\.exec\s*\(|\bexec\s*\(\s*[`'\"]", w)
    return "argv-array exec, no shell" if (argv and not shell) else None


def _path(w):
    """Path traversal: a containment check near the sink (resolve/realpath + prefix, or basename)."""
    contain = re.search(
        r"realpath|path\.resolve[\s\S]{0,140}?(?:startsWith|\.relative\s*\(|indexOf)|"
        r"\bbasename\s*\(|normalize[\s\S]{0,100}?startsWith|"
        r"startsWith\s*\(\s*\w*(?:base|root|dir|allowed)|"
        r"\.\.\s*(?:reject|throw|denied|forbidden)|sanitiz\w*[\s\S]{0,40}?path", w, re.I)
    return "path containment check (resolve/realpath + prefix, or basename)" if contain else None


# SQL built by interpolation/concatenation -> NOT safe (the danger signal that vetoes a clear)
_SQL_INTERP = re.compile(r"f['\"][^'\"]*\{|['\"]\s*\+\s*\w|\$\{[^}]*\}|%\s*\(|\.format\s*\(|\bconcat\b|\|\|\s*\w",
                         re.I)
_SQL_BOUND = re.compile(r":\w+\b|\bsetParameter\b|\bsetParameters\b|\bbindParam\b|\$queryRaw\b|parameteriz|"
                        r"placeholder|\?\s*[,)]|\$\d+\b|execute\s*\(\s*[^,\n]+,\s*[\[(]", re.I)


def _sqli(w):
    """SQL injection: a bound/parameterized query AND no string interpolation building the SQL."""
    return ("parameterized / bound query (no interpolation)"
            if (_SQL_BOUND.search(w) and not _SQL_INTERP.search(w)) else None)


def _nosqli(w):
    """NoSQL injection: a relational-ORM `{ where: ... }` / `{ select: ... }` query with NO Mongo operator."""
    rel = re.search(r"\.find(?:One)?\s*\(\s*\{\s*(?:where|select)\b|\.(?:findUnique|findFirst)\s*\(", w)
    mongo = re.search(r"\$where|\$ne\b|\$gt\b|\$lt\b|\$regex|\$in\b|\$or\b", w)
    return "relational ORM query ({where:}), no NoSQL operator" if (rel and not mongo) else None


_SSRF_GUARD = re.compile(
    r"\bssrf\b|withSafeFetch|resolveSafeFetchTarget|isPrivate|assertPublic|validateUrl|"
    r"allow(?:ed)?[_-]?(?:hosts?|list|origins?)|block(?:ed)?[_-]?(?:hosts?|list)|"
    r"127\.0\.0\.1|169\.254|net\.isIP|private[_-]?(?:ip|range|network)", re.I)


def _ssrf(w):
    """SSRF: the outbound fetch is behind a guard / host allow-list / private-range block."""
    return "fetch behind an SSRF guard / host allow-list" if _SSRF_GUARD.search(w) else None


_RECOGNIZERS = {"cmd": _cmd, "path": _path, "sqli": _sqli, "nosqli": _nosqli, "ssrf": _ssrf}


def clears(cls, window):
    """Return a short reason string if a known-safe pattern deterministically clears this finding, else None.
    `window` is source around the sink. Never raises -> a bad input just falls through to the model."""
    try:
        fn = _RECOGNIZERS.get((cls or "").lower().strip())
        return fn(window or "") if fn else None
    except Exception:
        return None
