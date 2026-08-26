"""SAST front-end (Phase 1 of the pipeline): static candidate discovery.

The plan's "find what to look at" engine. Reuses the VALIDATED deterministic detector
(scanner/flag.py — taint + flow-free patterns, precision-first, recall confirmed in Phase 0 on
VAmPI/NodeGoat/brokencrystals) and shapes its raw hits into ranked, de-duplicated Candidates the
dynamic loop consumes. Adds the pieces that make the SAST *complete*:
  - route_hint      : the HTTP route reaching each sink (SAST->DAST bridge; orchestrator/routes.py)
  - slice           : the enclosing function source (feeds the model translate/patch + exploit)
  - xflow resolution: follow a controller->service handoff to the callee's real sink (local_retrieve)
  - handler params  : route-handler parameters seeded as taint sources (framework source coverage)
  - --diff          : incremental scan of only git-changed files

Precision-first: injection/exec classes the dynamic oracle can PROVE rank first; authorization/logic
bugs (IDOR/BOLA) are intentionally NOT chased here — that is the DAST differential oracle's job.
Deterministic: no model, no heuristic fusion.
"""
import re
import sys
import json
import subprocess
import tempfile
import os
from pathlib import Path

from ..detector import flag                            # validated detector
from ..detector.local_retrieve import resolve_local    # cross-file callee body
from ..detector.resolve import extract_def             # def-block extractor (py + js/ts)
from .models import Candidate
from . import routes as routes_mod

PROVABLE = {
    "CWE-89",   # SQL injection            -> instrumented DB driver
    "CWE-943",  # NoSQL injection          -> instrumented DB driver
    "CWE-78",   # command injection        -> shell interceptor
    "CWE-94", "CWE-95",  # code injection / eval -> exec interceptor
    "CWE-79",   # XSS                       -> template/response interceptor
    "CWE-22",   # path traversal           -> fs interceptor
    "CWE-918",  # SSRF                      -> outbound interceptor
    "CWE-502",  # deserialization          -> deserializer interceptor
    "CWE-1321", # prototype pollution      -> object-proto probe
    "CWE-1336", # server-side template injection -> template render interceptor
    "CWE-1333", # ReDoS (regex on user input)    -> behavioral timing oracle
}
_DETECTOR_RANK = {"taint": 2, "pattern": 1, "xflow": 1}
_XFLOW_METH = re.compile(r"->\s*\w+\.(\w+)\(")


def _normalize_detector(c):
    if c.detector == "pattern":
        return "pattern"
    if c.sink == "xflow" or c.family == "cross-file handoff":
        return "xflow"
    return "taint"


def _changed_files(target, ref):
    try:
        r = subprocess.run(["git", "-C", str(target), "diff", "--name-only", ref],
                           capture_output=True, text=True, timeout=30)
        return {str((Path(target) / l.strip()).resolve()) for l in r.stdout.splitlines() if l.strip()}
    except Exception:
        return None


def _read(cache, path):
    if path not in cache:
        try:
            cache[path] = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            cache[path] = ""
    return cache[path]


def _js_enclosing(code, line):
    """Enclosing function source for a JS/TS candidate LINE (handles arrow-assigned methods that
    have no clean name -> unit '<module>'). Brace-match on a comment-blanked copy (so `{}` inside
    comments don't skew the count) but return the ORIGINAL lines."""
    blanked = flag._blank_comments(code, "js").splitlines()
    orig = code.splitlines()
    i = min(line - 1, len(blanked) - 1)
    hdr = re.compile(r"=>\s*\{|\bfunction\b|[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{")
    ctrl = re.compile(r"^\s*(if|for|while|switch|catch|else|do|return)\b")   # not a function header
    start = next((j for j in range(i, -1, -1)
                  if hdr.search(blanked[j]) and not ctrl.match(blanked[j])), None)
    if start is None:
        return ""
    depth, started, buf = 0, False, []
    for k in range(start, len(blanked)):
        buf.append(orig[k])
        depth += blanked[k].count("{") - blanked[k].count("}")
        if "{" in blanked[k]:
            started = True
        if started and depth <= 0:
            break
    return "\n".join(buf)


def _slice_for(cache, path, unit, line, lang):
    code = _read(cache, path)
    if unit and unit != "<module>":
        s = extract_def(code, unit)
        if s:
            return s
    if lang == "js":                                   # arrow-property methods / unnamed units
        return _js_enclosing(code, line)
    return ""


def _resolve_xflow(root, cand, cache):
    """Follow `tainted -> recv.method(...)` to the callee body and look for a concrete sink there.
    Returns (cwe, family, sink, slice, resolved_from) or None."""
    m = _XFLOW_METH.search(cand.sink)
    if not m:
        return None
    method = m.group(1)
    hit = resolve_local(str(root), method, exclude_path=cand.file)
    if not hit:
        return None
    snippet = hit["snippet"]
    suffix = Path(hit["path"]).suffix or ".js"
    tmp = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8") as f:
            f.write(snippet)
            tmp = f.name
        sub = [c for c in flag.scan_file(tmp) if c.cwe in PROVABLE]
    except Exception:
        sub = []
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    if not sub:
        return None
    s = sub[0]
    return (s.cwe, s.family, s.sink, snippet[:1600], f"{method} -> {hit['path']}")


# A FAST, non-reasoning code model does the discovery review (it answers directly -- no 800-token
# <think> per file, which is what made a reasoning model a ~35-min scan). The 14B reasoning model is
# reserved for the harder exploit-craft + patch. Override via WAVE_REVIEW_MODEL.
REVIEW_MODEL_ID = os.environ.get("WAVE_REVIEW_MODEL", "Qwen/Qwen2.5-7B-Instruct")


def discover(target, model_driven=False, diff_ref=None):
    """Return ranked, de-duplicated Candidates for `target`.

    model_driven: deterministic perception picks the flag-hit files, a fast code MODEL reads each and
    DECIDES what's vulnerable; the downstream oracle proves it (killing false positives).
    otherwise: the fast regex taint+pattern path (for the standalone `discover` CLI).
    """
    if model_driven:
        return _model_discover(target)
    return _deterministic_discover(target, diff_ref=diff_ref)


def _deterministic_discover(target, diff_ref=None):
    """Fast regex taint + pattern discovery (perception-only fallback, no model)."""
    root = Path(target)
    routes = routes_mod.extract_routes(target)
    handlers = routes_mod.handler_functions(routes)
    changed = _changed_files(target, diff_ref) if diff_ref else None

    raw = []
    for f in flag.gather(str(target)):
        if changed is not None and str(f.resolve()) not in changed:
            continue
        raw += flag.scan_file(f, handlers=handlers)

    cache, seen, cands = {}, set(), []
    for c in raw:
        key = (c.file, c.line, c.cwe)
        if key in seen:
            continue
        seen.add(key)
        det = _normalize_detector(c)
        cwe, family, sink, resolved_from = c.cwe, c.family, c.sink, ""
        lang = flag.EXT_LANG.get(Path(c.file).suffix.lower(), "")
        slice_src = _slice_for(cache, c.file, c.unit, c.line, lang)

        if det == "xflow":                                  # try to resolve to a concrete callee sink
            res = _resolve_xflow(root, c, cache)
            if res:
                cwe, family, sink, slice_src, resolved_from = res
                det = "taint"                               # now a concrete, resolved sink

        provable = cwe in PROVABLE
        rank = (10 if provable else 0) + _DETECTOR_RANK.get(det, 1) + (1 if resolved_from else 0)
        cands.append(Candidate(
            file=c.file, unit=c.unit, line=c.line, cwe=cwe, family=family,
            detector=det, sink=sink, provable=provable, rank=rank,
            route_hint=routes_mod.route_for(routes, c.file, c.unit),
            slice=slice_src, resolved_from=resolved_from,
        ))
    cands.sort(key=lambda x: (-x.rank, x.file, x.line))
    return cands


_REVIEW_SYS = (
    "You are a security auditor reviewing ONE source file. Identify REAL, reachable vulnerabilities "
    "where untrusted input reaches a dangerous sink: SQL/NoSQL injection, command or code (eval) "
    "injection, path traversal, SSRF, XSS, insecure deserialization. For each vulnerability output an "
    "object {function, line, cwe, sink, reason}: `cwe` like 'CWE-89'; `line` = the 1-based line number "
    "of the sink (the file is shown line-numbered); `sink` = the vulnerable code; `function` = the "
    "enclosing function/method name; `reason` = one short phrase. Report only genuine issues -- a "
    "parameterized query or a validated input is NOT a vulnerability. Output ONLY a JSON array "
    "(empty [] if none). No prose.")


def _norm_cwe(s):
    m = re.search(r"CWE[-_ ]?(\d+)", str(s or ""), re.I)
    return f"CWE-{m.group(1)}" if m else ""


def _attack_surface_files(target, cap=15):
    """Deterministic PERCEPTION: which files the model should read = the files the cheap pre-filter
    found ANY candidate in. Only these (not every route handler) -- a file with no flagged sink has
    nothing to review, and reviewing it is what made a full scan a ~35-min grind."""
    files, seen = [], set()
    for f in flag.gather(str(target)):
        try:
            if flag.scan_file(f):
                p = str(f)
                if p not in seen:
                    seen.add(p); files.append(p)
        except Exception:
            pass
    return files[:cap]


def _parse_vulns(txt):
    after = (txt or "").split("</think>")[-1]
    m = (re.search(r"```(?:json)?\s*(\[.*?\])\s*```", after, re.S)
         or re.search(r"(\[\s*\{.*\}\s*\])", after, re.S)
         or re.search(r"(\[\s*\{.*\}\s*\])", txt or "", re.S))
    if not m:
        return []
    try:
        arr = json.loads(m.group(1))
    except Exception:
        return []
    return [v for v in arr if isinstance(v, dict) and v.get("cwe")]


def model_review(model, path, code):
    """The MODEL reads a line-numbered file (full context, so it can tell a parameterized/validated
    use from a real vuln) and reports its vulnerabilities. Tight token budget: a vuln list is short,
    and this is what keeps a scan fast."""
    numbered = "\n".join(f"{i+1}: {l}" for i, l in enumerate(code.splitlines()[:400]))
    txt = model.generate(_REVIEW_SYS, f"File: {path}\n```\n{numbered}\n```",
                         max_new_tokens=800, temperature=0.2)
    return _parse_vulns(txt)


def _model_discover(target):
    """Model-driven discovery: perception picks the flag-hit files, a FAST code model reads each (FULL
    file context, so it can clear a parameterized/validated use a bare slice can't) and DECIDES the
    vulns; the oracle proves later. Loads its own fast review model and unloads it (so the 14B can
    then load for exploit/patch without VRAM contention)."""
    from .model import Model
    routes = routes_mod.extract_routes(target)
    files = _attack_surface_files(target)
    review = Model(REVIEW_MODEL_ID)
    cache, seen, cands = {}, set(), []
    try:
        for f in files:
            code = _read(cache, f)
            _review_into(review, f, code, routes, cache, seen, cands)
    finally:
        review.unload()
    cands.sort(key=lambda x: (-x.rank, x.file))
    return cands


def _review_into(model, f, code, routes, cache, seen, cands):
    lang = flag.EXT_LANG.get(Path(f).suffix.lower(), "")
    for v in model_review(model, f, code):
        cwe = _norm_cwe(v.get("cwe"))
        if not cwe:
            continue
        unit = str(v.get("function") or "?")
        try:
            line = int(v.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        key = (f, cwe, unit)
        if key in seen:
            continue
        seen.add(key)
        provable = cwe in PROVABLE
        cands.append(Candidate(
            file=f, unit=unit, line=line, cwe=cwe, family=str(v.get("reason") or "")[:70],
            detector="model", sink=str(v.get("sink") or "")[:120], provable=provable,
            rank=(10 if provable else 0) + 3,
            route_hint=routes_mod.route_for(routes, f, unit),
            slice=_slice_for(cache, f, unit, line, lang)))


def summarize(cands):
    from collections import Counter
    return {
        "total": len(cands),
        "provable": sum(c.provable for c in cands),
        "resolved": sum(bool(c.resolved_from) for c in cands),
        "routed": sum(bool(c.route_hint) for c in cands),
        "by_cwe": dict(Counter(c.cwe for c in cands)),
        "by_detector": dict(Counter(c.detector for c in cands)),
    }
