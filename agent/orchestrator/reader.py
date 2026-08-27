"""Phase 4 of the investigation loop: the READER. The model reads prioritized source files and forms
ITS OWN hypotheses -- closing the gap that discovery was purely deterministic (pattern/taint). This
plays to the model's STRENGTH (single-file reasoning on visible code) and lets it find shapes the
patterns miss. Deterministic discovery is demoted to a fast SEED pass (a hint, not the truth).

A Reader hypothesis is `believed` (the model's reading, never a finding) and becomes a Candidate that
flows through the SAME confirmation ladder (Rung 0 static -> Rung 1 micro-exec -> Rung 2 runtime) as
any seed candidate. Triage + budget are explicit: read the highest-security-surface files first, up to
a budget -- a real auditor does not read every file.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Candidate

_SKIP = {"node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build", "test", "tests",
         "migrations", "vendor", "site-packages"}
_EXTS = {".py", ".js", ".ts", ".mjs"}
# security-surface signals -> a file's "worth reading first" score
_SURFACE = re.compile(
    r"request|req\.|@app\.|@router\.|@bp\.|route\(|\.get\(|\.post\(|execute\(|cursor|subprocess|"
    r"os\.system|Popen|\bopen\(|requests\.|urllib|eval\(|exec\(|pickle|yaml\.load|Template|render|"
    r"send_file|FileResponse|redirect|jwt|password|secret|token|admin|query\(", re.I)
_PROVABLE_CWES = {"CWE-89", "CWE-78", "CWE-94", "CWE-95", "CWE-22", "CWE-918", "CWE-1336", "CWE-79",
                  "CWE-502", "CWE-943", "CWE-77", "CWE-90", "CWE-611"}

_READ_SYS = (
    "You are a security auditor READING one source file. Find places where UNTRUSTED INPUT (a request "
    "param/body/header/path, or an argument that carries one) reaches a DANGEROUS OPERATION -- SQL, "
    "shell/exec, a file path, an outbound URL, a template render, or deserialization -- WITHOUT adequate "
    "neutralization (parameterization, escaping, an allow-list). Report only REAL, reachable issues; a "
    "parameterized query or an escaped value is NOT an issue. Output ONLY a JSON array (empty [] if "
    'none), each item: {"line": <int>, "function": "<name>", "cwe": "CWE-XX", "class": "<short>", '
    '"input": "<the untrusted source>", "sink": "<the dangerous call>", "why": "<one line>"}. No prose. '
    "Keep any reasoning BRIEF, then output the JSON array promptly -- do not overthink.")


def _parse_hyps(txt):
    """Robust extraction of hypothesis objects from an R1 output (which buries the answer after a long
    <think>). Prefer the post-</think> array; fall back to the whole output; then to individual objects
    (so a cut-off array still yields its complete items)."""
    txt = txt or ""
    for scope in (txt.split("</think>")[-1], txt):
        m = re.search(r"(\[.*\])", scope, re.S)
        if m:
            try:
                arr = json.loads(m.group(1))
                if isinstance(arr, list):
                    hs = [d for d in arr if isinstance(d, dict) and d.get("cwe") and d.get("line")]
                    if hs:
                        return hs
            except Exception:
                pass
    hs = []
    for om in re.finditer(r'\{[^{}]*"cwe"[^{}]*\}', txt, re.S):
        try:
            d = json.loads(om.group(0))
            if d.get("cwe") and d.get("line"):
                hs.append(d)
        except Exception:
            pass
    return hs


def _iter_files(target):
    p = Path(target)
    if p.is_file():
        yield p
        return
    for f in p.rglob("*"):
        if (f.suffix.lower() in _EXTS and not any(s in f.parts for s in _SKIP)
                and not f.name.startswith("_wave_")):      # skip wave's own injected sink-hook artifacts
            yield f


def prioritize_files(target, seed_candidates=(), budget=8):
    """Rank source files by security-surface density (boosted if the seed pass flagged them); top N."""
    seeded = {str(Path(c.file).resolve()) for c in seed_candidates}
    scored = []
    for f in _iter_files(target):
        try:
            src = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(src) > 200_000:                          # skip giant/generated files
            continue
        score = len(_SURFACE.findall(src))
        if str(f.resolve()) in seeded:
            score += 50                                 # the seed pass already smelled something here
        if score:
            scored.append((score, f))
    scored.sort(key=lambda t: t[0], reverse=True)
    return [f for _s, f in scored[:budget]]


def _numbered(src, limit=520):
    lines = src.splitlines()[:limit]
    return "\n".join(f"{i + 1}: {ln}" for i, ln in enumerate(lines))


def read_file(model, path):
    """Model reads one file -> (short summary, [hypothesis dicts])."""
    try:
        src = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "", []
    txt = model.generate(_READ_SYS, f"FILE {Path(path).name}\n\n{_numbered(src)}",
                         max_new_tokens=3600, temperature=0.2)   # R1 needs room to think THEN emit the array
    hyps = _parse_hyps(txt)
    return f"read {Path(path).name}: {len(hyps)} hypothesis(es)", hyps


def _to_candidate(path, h, routes):
    fn = str(h.get("function") or "<unit>")
    route_hint = ""
    for r in routes:
        if r.function and r.function == fn:
            route_hint = f"{r.method} {r.path}"
            break
    cwe = str(h.get("cwe"))
    try:
        line = int(h.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    return Candidate(file=str(path), unit=f"{fn} (reader)", line=line, cwe=cwe,
                     family=str(h.get("class") or "model-read hypothesis"), detector="reader",
                     sink=str(h.get("sink") or ""), provable=cwe in _PROVABLE_CWES, rank=42,
                     route_hint=route_hint, slice=str(h.get("why") or ""))


def read(model, target, seed_candidates=(), routes=(), budget=8):
    """Read the top-priority files; return (reader Candidates, [(file, summary, hypotheses)])."""
    files = prioritize_files(target, seed_candidates, budget)
    cands, report = [], []
    for f in files:
        summary, hyps = read_file(model, f)
        report.append((str(f), summary, hyps))
        for h in hyps:
            cands.append(_to_candidate(f, h, routes))
    return cands, report


# ---- Iterative revisit: follow leads via the import graph (the Architect, lightweight) ----------------
_IMPORT = re.compile(r"^\s*(?:import|from)\s+([\w.]+)|require\(['\"]([^'\"]+)['\"]\)", re.M)


def _imported_stems(src):
    stems = set()
    for m in _IMPORT.finditer(src or ""):
        mod = (m.group(1) or m.group(2) or "").replace("./", "").replace("../", "")
        stems.add(mod.split("/")[-1].split(".")[0])
    return {s for s in stems if s}


def _neighbors(target, hot_files):
    """Files that IMPORT a hot file, or are IMPORTED BY one -- the import-graph neighbourhood of a lead."""
    hot = [Path(f) for f in hot_files]
    hot_stems = {p.stem for p in hot}
    hot_imports = set()
    for p in hot:
        try:
            hot_imports |= _imported_stems(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass
    out = set()
    for f in _iter_files(target):
        if f in hot:
            continue
        try:
            src = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if (_imported_stems(src) & hot_stems) or (f.stem in hot_imports):
            out.add(f)
    return out


def read_iterative(model, target, seed_candidates=(), routes=(), budget=10, per_round=4, max_rounds=3):
    """Read in ROUNDS, following leads: after a round, the import-neighbours of files that yielded a
    hypothesis are read next. TERMINATES on diminishing returns (a round finds nothing), max_rounds, or
    the budget (total files read). Returns (reader Candidates, [(file, summary, hypotheses)])."""
    ranked = prioritize_files(target, seed_candidates, budget=budget * 4)
    read_set, cands, report, rounds = set(), [], [], 0
    queue = list(ranked)
    while queue and rounds < max_rounds and len(read_set) < budget:
        rounds += 1
        batch = [f for f in queue if str(f) not in read_set][:per_round]
        batch = batch[:max(0, budget - len(read_set))]
        if not batch:
            break
        hot = []
        for f in batch:
            read_set.add(str(f))
            summary, hyps = read_file(model, f)
            report.append((str(f), summary, hyps))
            for h in hyps:
                cands.append(_to_candidate(f, h, routes))
            if hyps:
                hot.append(f)
        if not hot:                                     # diminishing returns: a whole round found nothing
            break
        nbrs = [f for f in _neighbors(target, hot) if str(f) not in read_set]   # follow the leads first
        rest = [f for f in ranked if str(f) not in read_set and f not in nbrs]
        queue = nbrs + rest
    return cands, report
