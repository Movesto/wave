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
from .search import web_search

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
    '"input": "<the untrusted source>", "sink": "<the dangerous call>", "why": "<one line>", '
    '"confidence": "high"|"low"}. Set "confidence":"low" ONLY when you cannot tell if it is exploitable '
    "because you don't recognize an API, a library, or a framework's behaviour; then also add "
    '"search":"<a concrete web query that would resolve your doubt>". Otherwise "confidence":"high". '
    "No prose. Keep any reasoning BRIEF, then output the JSON array promptly -- do not overthink.")

_CLARIFY_SYS = (
    "You earlier flagged a POSSIBLE vulnerability but were UNSURE. Below is your hypothesis and WEB "
    "SEARCH results about the thing you were unsure of. Using ONLY this evidence plus the hypothesis, "
    "decide whether it is a REAL, reachable vulnerability. Output ONLY JSON, nothing else: the SAME "
    'hypothesis object with an updated "confidence" ("high" if the evidence confirms it is exploitable, '
    'else "low") and a corrected "why"; OR the literal [] if the evidence shows it is NOT a vulnerability '
    "(safe/auto-escaping API, framework neutralizes it, etc.). No prose.")


def _clarify(model, h, snippets):
    """One grounded follow-up: feed the low-confidence hypothesis + web results back to the model.
    Returns the revised hypothesis dict, or None if the model retracts it (evidence says it is safe)."""
    user = (f"HYPOTHESIS: {json.dumps(h)}\n\nWEB SEARCH for {h.get('search') or '(sink behaviour)'!r}:\n"
            f"{snippets}\n\nDecide now.")
    txt = model.generate(_CLARIFY_SYS, user, max_new_tokens=700, temperature=0.2)
    after = (txt or "").split("</think>")[-1]
    if re.search(r"(?<!\w)\[\s*\]", after):             # explicit retraction -> drop the hypothesis
        return None
    m = re.search(r"\{.*\}", after, re.S) or re.search(r"\{.*\}", txt or "", re.S)
    if not m:
        return h                                        # unparseable -> keep the original, unchanged
    try:
        d = json.loads(m.group(0))
        if isinstance(d, dict) and d.get("cwe"):
            return d
    except Exception:
        pass
    return h


_TRIAGE_QUERY_SYS = (
    "A micro-execution of one handler was INCONCLUSIVE -- it neither proved nor cleared a suspected "
    "vulnerability, likely because you don't know how a specific API/library/framework behaves at the "
    "sink. Decide what to look up. Keep any reasoning BRIEF, then output ONLY a JSON object: "
    '{"query":"<a concrete web search query that would resolve your doubt about whether this is '
    'exploitable>"}. No prose after the JSON.')

_TRIAGE_JUDGE_SYS = (
    "You are judging whether a suspected vulnerability is REAL. Below: the code, the INCONCLUSIVE "
    "micro-execution result, and WEB SEARCH results about the API/behaviour you were unsure of. Decide "
    'using ONLY this evidence plus the code. Output ONLY JSON: {"verdict":"vulnerable"|"safe"|"unknown",'
    '"why":"<one line>"}. "vulnerable" = the evidence shows this untrusted input can reach a dangerous '
    'operation unsafely; "safe" = the API/framework neutralizes it or it is not reachable; "unknown" = '
    "the evidence is insufficient to tell. No prose.")


def _extract_query(txt, fallback):
    """Pull the search query out of an R1 reply (which buries the answer after a long <think>).
    Prefer a {"query": ...} object; fall back to a deterministic query so a rambling/empty reply
    still searches something sensible rather than dumping reasoning text into the search box."""
    after = (txt or "").split("</think>")[-1]
    for scope in (after, txt or ""):
        m = re.search(r'\{[^{}]*"query"[^{}]*\}', scope, re.S)
        if m:
            try:
                q = json.loads(m.group(0)).get("query")
                if q and str(q).strip():
                    return str(q).strip()[:200]
            except Exception:
                pass
    return fallback


def triage_unknown(model, candidate, micro_reason, budget_box):
    """Search-assisted triage of a micro-exec UNKNOWN: the model asks what it doesn't understand about
    THIS piece, we look it up, and it judges. Returns {"verdict","why","query"} with verdict in
    vulnerable|safe|unknown. NEVER a proof -- it can only refute a lead or flag it for review; the
    oracle still owns confirmation. Spends one web search + two short model turns from the shared box."""
    out = {"verdict": "unknown", "why": micro_reason, "query": ""}
    if budget_box is None or budget_box[0] <= 0:
        return out
    budget_box[0] -= 1
    code = (candidate.slice or candidate.sink or "")[:1600]
    ctx = (f"CWE: {candidate.cwe}   SINK: {candidate.sink}\n"
           f"MICRO-EXEC RESULT (inconclusive): {micro_reason}\n\nCODE:\n{code}")
    fallback_q = f"{candidate.cwe} {candidate.sink} exploitable"
    q = _extract_query(model.generate(_TRIAGE_QUERY_SYS, ctx, max_new_tokens=700, temperature=0.2),
                       fallback_q)
    out["query"] = q
    print(f"[rung1]   ? unknown ({candidate.cwe} {candidate.unit}) -> web search: {q!r}", flush=True)
    snippets = web_search(q)
    if not snippets:
        print("[rung1]     (no results / offline) -- staying a lead for review", flush=True)
        return out
    judge = model.generate(_TRIAGE_JUDGE_SYS, f"{ctx}\n\nWEB SEARCH for {q!r}:\n{snippets}\n\nDecide now.",
                           max_new_tokens=500, temperature=0.2)
    after = (judge or "").split("</think>")[-1]
    m = re.search(r"\{.*\}", after, re.S)
    if m:
        try:
            d = json.loads(m.group(0))
            v = str(d.get("verdict", "")).lower()
            if v in ("vulnerable", "safe", "unknown"):
                out["verdict"], out["why"] = v, str(d.get("why") or micro_reason)
        except Exception:
            pass
    print(f"[rung1]     -> {out['verdict']}: {out['why']}", flush=True)
    return out


def _resolve_doubts(model, hyps, budget_box):
    """For each LOW-confidence hypothesis (up to the shared search budget), spend one web-search +
    clarify turn. Mutates the list in place: revises confirmed ones, drops retracted ones."""
    kept = []
    for h in hyps:
        low = str(h.get("confidence", "")).lower() == "low" or bool(h.get("search"))
        if not (low and budget_box[0] > 0):
            kept.append(h)
            continue
        budget_box[0] -= 1
        q = h.get("search") or f"{h.get('cwe')} {h.get('sink')} exploitable"
        print(f"[reader]   ? unsure ({h.get('cwe')} {h.get('sink')}) -> web search: {q!r}", flush=True)
        ctx = web_search(q)
        if not ctx:
            print("[reader]     (no search results / offline) -- keeping as low-confidence lead", flush=True)
            kept.append(h)
            continue
        revised = _clarify(model, h, ctx)
        if revised is None:
            print("[reader]     -> evidence says SAFE, hypothesis dropped", flush=True)
            continue
        print(f"[reader]     -> confidence now {str(revised.get('confidence', '?'))}", flush=True)
        kept.append(revised)
    return kept


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


# This GPU wedges (stuck CUDA kernel, 100% util at ~60W) on LONG generate() sequences -- verified: a
# ~320-line file hangs, ~150 lines is safe. So read a file in <=_MAX_CHUNKS windows of _WINDOW lines
# rather than one big prompt (preserves coverage of large files without the wedge). _READ_TOKENS gives
# R1 enough room to finish its <think> AND emit the JSON (too few -> the array is cut off = 0 hyps).
_WINDOW = 150
_MAX_CHUNKS = 2
_READ_TOKENS = 3000


def _windows(src, window=_WINDOW, max_chunks=_MAX_CHUNKS):
    """Line-numbered windows (1-based numbers preserved so a hypothesis's `line` stays correct)."""
    lines = src.splitlines()
    out = []
    for start in range(0, min(len(lines), window * max_chunks), window):
        chunk = lines[start:start + window]
        out.append((start + 1, "\n".join(f"{start + i + 1}: {ln}" for i, ln in enumerate(chunk))))
    return out or [(1, "")]


def read_file(model, path, search_budget=None):
    """Model reads one file -> (short summary, [hypothesis dicts]). Long files are read in windows to
    dodge the long-sequence GPU wedge. If `search_budget` is a [remaining] box and --online is on,
    low-confidence hypotheses spend a web-search + clarify turn."""
    try:
        src = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "", []
    wins = _windows(src)
    hyps = []
    for start_line, body in wins:
        tag = f"FILE {Path(path).name}" + (f" (lines {start_line}-{start_line + _WINDOW - 1})" if len(wins) > 1 else "")
        txt = model.generate(_READ_SYS, f"{tag}\n\n{body}", max_new_tokens=_READ_TOKENS, temperature=0.2)
        w_hyps = _parse_hyps(txt)
        if search_budget is not None and search_budget[0] > 0:
            w_hyps = _resolve_doubts(model, w_hyps, search_budget)
        hyps.extend(w_hyps)
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


def read(model, target, seed_candidates=(), routes=(), budget=8, online=False, search_budget=4):
    """Read the top-`budget` security-surface files LINEARLY (no lead-following, no early stop) -- the
    whole-repo pass. Returns (reader Candidates, [(file, summary, hypotheses)])."""
    files = prioritize_files(target, seed_candidates, budget)
    sb = [search_budget] if online else None
    cands, report = [], []
    for i, f in enumerate(files, 1):
        print(f"[reader] reading {Path(f).name} ({i}/{len(files)}) ...", flush=True)
        summary, hyps = read_file(model, f, search_budget=sb)
        print(f"[reader]   -> {len(hyps)} hypothesis(es)", flush=True)
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


def read_iterative(model, target, seed_candidates=(), routes=(), budget=10, per_round=4, max_rounds=3,
                   online=False, search_budget=4):
    """Read in ROUNDS, following leads: after a round, the import-neighbours of files that yielded a
    hypothesis are read next. TERMINATES on diminishing returns (a round finds nothing), max_rounds, or
    the budget (total files read). Returns (reader Candidates, [(file, summary, hypotheses)]).
    With `online`, low-confidence hypotheses spend up to `search_budget` web-search + clarify turns."""
    ranked = prioritize_files(target, seed_candidates, budget=budget * 4)
    sb = [search_budget] if online else None
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
            print(f"[reader] round {rounds}: reading {Path(f).name} "
                  f"({len(read_set) + 1}/{budget}) ...", flush=True)
            read_set.add(str(f))
            summary, hyps = read_file(model, f, search_budget=sb)
            print(f"[reader]   -> {len(hyps)} hypothesis(es)", flush=True)
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
