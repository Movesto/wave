"""Variant hunting (sast-improvement plan 3): after a CONFIRMED finding, search the repo for OTHER
occurrences of the same sink CLASS/shape and queue them for proof. A real bug is rarely alone -- the same
unsafe pattern tends to recur across handlers/files. Deterministic: reuses the codemap sink patterns
(repomap) to find siblings; the proof stage still decides each one, so a variant is only a CANDIDATE,
never an auto-confirm. Visible only when a scan actually confirmed something to hunt from.
"""
from __future__ import annotations

from pathlib import Path

from . import repomap

_SKIP = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "vendor", "target", ".next"}
_EXT_LANG = {".py": "python", ".js": "js", ".ts": "js", ".jsx": "js", ".tsx": "js", ".mjs": "js", ".cjs": "js"}


def _patterns(cls, lang):
    """The codemap sink regex(es) for a class in a language (py/js). Pure (reuses repomap's tables)."""
    cls = (cls or "").lower()
    table = (repomap._SINKS_PY if lang == "python" else repomap._SINKS_JS) + repomap._SINKS_COMMON
    return [rx for name, rx in table if name.lower() == cls]


def find(confirmed, target, seen=(), cap=25):
    """New candidate dicts for repo lines matching a CONFIRMED finding's sink class/shape, excluding
    locations already examined (`seen` = set of (relfile, line, class)). Each is a believed-grade lead
    (confidence low) for the proof stage to settle."""
    classes = {str(f.get("class") or "").lower() for f in (confirmed or []) if f.get("class")}
    classes.discard("")
    if not classes:
        return []
    seen_set = set(seen)
    out = []
    root = Path(target)
    files = [root] if root.is_file() else root.rglob("*")
    for f in files:
        if len(out) >= cap:
            break
        lang = _EXT_LANG.get(f.suffix.lower())
        if not lang or any(s in f.parts for s in _SKIP):
            continue
        pats = {c: p for c, p in ((c, _patterns(c, lang)) for c in classes) if p}
        if not pats:
            continue
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        rel = repomap._rel(target, str(f))
        for i, line in enumerate(lines, 1):
            for cls, rxs in pats.items():
                if any(rx.search(line) for rx in rxs):
                    key = (rel, i, cls)
                    if key in seen_set:
                        continue
                    seen_set.add(key)
                    out.append({"file": rel, "line": i, "class": cls, "sink": line.strip()[:140],
                                "input": "", "confidence": "low", "variant": True})
                    if len(out) >= cap:
                        return out
                    break                                    # one class per line is enough
    return out
