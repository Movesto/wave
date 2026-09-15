"""Stage 1b -- the NOTEBOOK: comprehension as a pentester's persistent notes.

The old ledger asked one model to summarize a whole-repo digest it couldn't hold (and a small/cloud model
would mislabel files). Instead the STRONG local model reads ONE pinned file at a time -- seeded with that
file's map pins -- and writes a durable NOTE: what the file does, the untrusted inputs, the dangerous ops,
and which exploit CLASSES to try first. Like a pentester jotting findings to return to when planning the
attack. Notes persist to wave_notebook.jsonl (+ a readable wave_notebook.md), so:

  - context never has to hold the whole repo (each call = one file, windowed around its pins);
  - the run is RESUMABLE -- re-running skips files already noted, so a monorepo can be worked in passes;
  - Stage 2/3 come back to the notes to hypothesize + choose an exploit class.

Also emits a DETERMINISTIC ledger index (entry points + auth + ranked targets + class hints) straight from
the map -- zero model, so it cannot hallucinate a file or a route. The model's effort goes entirely into
per-file depth grounded in the real source, never a whole-repo summary.

Model is the local detection model (Qwen) via ollama's native endpoint (num_ctx + format:json honored).
No cloud, no separate comprehension model.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .repomap import _rel

_WINDOW = 150            # matches reader.py: >~320-line single prompts wedge the GPU; 150 is safe
_MAX_WINDOWS = 3         # cap calls per file (each window = one generate call)
_TOKENS = 3000           # room for a brief <think> + the JSON note

_NOTE_SYS = (
    "You are a penetration tester taking NOTES on ONE source file, to return to later when planning "
    "exploits. The repo map has already flagged candidate sinks/routes in this file (shown as HINTS); "
    "confirm or DISMISS each against the actual code. Record ONLY reachable issues -- a parameterized "
    "query, an escaped value, or a constant is NOT a finding. ALSO look for BROKEN ACCESS CONTROL / IDOR "
    "(class 'authz'): a handler that reads or writes a resource by an id/owner from the request but never "
    "checks the resource belongs to the CALLER (no ownership/role check) -- these have NO injection sink, so "
    "the map won't hint them; you must spot them. ALSO flag a CRASH / DoS (class 'other'): an unchecked "
    "operation on attacker-controlled input that panics or throws -- a Rust `.unwrap()`/`.expect()` or index "
    "on a request value, a parse with no error handling, an unchecked cast/slice -- these have no injection "
    "sink either, so you must spot them. Output ONE JSON object, nothing else:\n"
    '{"purpose": "<what this file/module does, one line>", '
    '"untrusted_inputs": "<request params/body/headers/args an external caller controls, or none>", '
    '"findings": [{"line": <int>, "function": "<name>", "class": "<sqli|nosqli|cmd|eval|path|ssrf|xss|'
    'deser|redirect|authz|other>", "sink": "<the dangerous call>", "input": "<the untrusted source that '
    'reaches it, or unclear>", "why": "<one line>", "confidence": "high"|"low"}], '
    '"classes_to_try_first": ["<class>", ...], '
    '"cross_file": "<other modules/functions this depends on that matter for exploitation, or none>"}\n'
    "Keep reasoning brief, then output the JSON.")


# ---- deterministic ledger index (no model) -----------------------------------------------------------

_AUTH_ADMIN = re.compile(r"adminuser|get_admin_user|\bis_admin\b|isadmin|require_admin|requireadmin|"
                         r"adminguard|roles\s*\(\s*['\"]admin", re.I)
# NB: match auth DEPENDENCIES, not the login form -- OAuth2PasswordRequestForm is the /login input, not a
# guard, so don't match bare "oauth2" (it would tag the unauthenticated /login as protected).
_AUTH_USER = re.compile(r"currentuser|get_current_user|isloggedin|require_auth|requireauth|"
                        r"login_required|useguards|jwtauthguard|authguard|oauth2passwordbearer|"
                        r"depends\s*\([^)]*(user|auth|current|token|session)", re.I)


def _auth_from(text):
    """Auth from the route line + handler signature/decorators. admin > user > none. The framework puts
    the check in DIFFERENT places: Express/Nest in the route line (isLoggedIn/@UseGuards), FastAPI in the
    handler params (Depends(get_current_user), CurrentUser/AdminUser annotated types) -- so we scan both."""
    if _AUTH_ADMIN.search(text):
        return "admin"
    if _AUTH_USER.search(text):
        return "session"
    return "none"


def _handler_for(finfo, route_line):
    """The handler function a route decorator sits on -- the def within a few lines below the [ROUTE]
    pin. Its signature carries the auth dependency the decorator line doesn't."""
    cands = list(finfo.functions)
    for c in finfo.classes:
        cands.extend(c.methods)
    best = None
    for f in cands:
        if 0 <= (f.line - route_line) <= 6 and (best is None or f.line < best.line):
            best = f
    return best


_AUTH_ORDER = {"none": 0, "session": 1, "jwt/session": 1, "admin": 2, "unknown": 3, "-": 4}


def ledger_index(cmap, root, per_file, pinned):
    """Attack-surface index derived STRAIGHT from the map -- deterministic, cannot hallucinate.
    entry_points = every [ROUTE] with a heuristic auth tag (from the route line AND its handler's
    signature); ranked_targets = pinned files (pin-density-ordered) with their classes + most-open auth."""
    entry_points, ranked = [], []
    for p in pinned:
        routes, sinks, _dyn = per_file[p]
        rel = _rel(root, p)
        finfo = cmap.files.get(p) if cmap else None
        file_auth = None
        for ln, _, code in routes:
            handler = _handler_for(finfo, ln) if finfo else None
            if handler is not None:
                auth = _auth_from(code + " " + (handler.sig or "") + " " + " ".join(handler.decorators))
            else:
                auth = _auth_from(code) if (_AUTH_ADMIN.search(code) or _AUTH_USER.search(code)) else "unknown"
            entry_points.append({"route": code, "file": rel, "line": ln, "auth": auth})
            if file_auth is None or _AUTH_ORDER.get(auth, 3) < _AUTH_ORDER.get(file_auth, 3):
                file_auth = auth
        classes = []
        for _ln, label, _code in sinks:
            if label not in classes:
                classes.append(label)
        ranked.append({"file": rel, "classes_first": classes, "routes": len(routes),
                       "sinks": len(sinks), "auth": file_auth or "-"})
    return {"entry_points": entry_points, "ranked_targets": ranked}


# ---- model-driven target SELECTION (large repos: pick the files worth deep-reading) -----------------

_SELECT_SYS = (
    "You are a lead penetration tester triaging a LARGE codebase before a deep review. Below is the "
    "attack-surface INDEX: candidate files with their route count, sink count, the injection CLASSES "
    "flagged in each, and the most-open AUTH on their routes. Choose the up-to-N files MOST worth a deep "
    "read -- where untrusted input most plausibly reaches a dangerous sink, or that form an exploit chain "
    "(entry -> handler -> sink). Strongly prefer UNAUTH (auth:none) request-reachable routes and dangerous "
    "classes (cmd/eval/sqli/ssrf/deser/path) over low-value ones (a lone redirect, an admin-only static "
    "query). Output ONLY a JSON array, ranked most-promising first, at most N items, each: "
    '{"file": "<exact path from the index>", "reason": "<one line why it is worth deep-reading>"}. '
    "Use ONLY paths that appear in the index.")


def _index_text(idx, cap=300):
    """Compact index for the selection model: one line per ranked file. Capped to the top `cap` (already
    density-ordered) so even a monorepo's index fits the window."""
    out = []
    for t in idx["ranked_targets"][:cap]:
        cls = ",".join(t["classes_first"]) or "-"
        out.append(f"{t['file']}  routes={t['routes']} sinks={t['sinks']} auth={t['auth']}  classes={cls}")
    extra = len(idx["ranked_targets"]) - cap
    if extra > 0:
        out.append(f"... (+{extra} lower-density files omitted)")
    return "\n".join(out)


def select_targets(model, root, per_file, pinned, budget, index=None):
    """The model reads the compact index and picks up to `budget` files worth deep-reading. Returns a list
    of {file, path, reason} in the model's ranked order; falls back to pin-density order on any failure."""
    idx = index or ledger_index(None, root, per_file, pinned)  # cmap only needed for auth; index may be passed
    rel_to_path = {_rel(root, p): p for p in pinned}
    user = f"N = {budget}\n\nATTACK-SURFACE INDEX ({len(pinned)} candidate files):\n{_index_text(idx)}"
    picks = []
    try:
        txt = model.generate(_SELECT_SYS, user, max_new_tokens=2000, temperature=0.0, think=False,
                             json_mode=True)
        after = (txt or "").split("</think>")[-1]
        i, j = after.find("["), after.rfind("]")
        arr = json.loads(after[i:j + 1]) if 0 <= i < j else []
        seen = set()
        for it in arr:
            f = str(it.get("file", "")).replace("\\", "/") if isinstance(it, dict) else ""
            if f in rel_to_path and f not in seen:
                seen.add(f)
                picks.append({"file": f, "path": rel_to_path[f], "reason": str(it.get("reason", ""))})
            if len(picks) >= budget:
                break
    except Exception:
        picks = []
    if not picks:                                          # model failed -> density order (existing behaviour)
        picks = [{"file": _rel(root, p), "path": p, "reason": "(pin-density fallback)"}
                 for p in pinned[:budget]]
    return picks


# ---- the per-file notes (model) ----------------------------------------------------------------------

def _windows_for(src, focus_lines, window=_WINDOW, max_windows=_MAX_WINDOWS):
    """Line-numbered windows that COVER the pinned lines (not just the file head) so a sink at L307 is
    actually in view. Falls back to the head when there are no pins. Each window is one generate call."""
    lines = src.splitlines()
    n = len(lines)
    if focus_lines:                                          # pinned: windows COVER the pin lines
        starts = sorted({((fl - 1) // window) * window for fl in focus_lines if 1 <= fl <= n})
        starts = (starts or [0])[:max_windows]
    else:                                                    # no pins (all-files read): cover head-to-tail, capped
        nwin = max(1, (n + window - 1) // window)
        starts = [i * window for i in range(min(nwin, max_windows))]
    out = []
    for s in starts:
        chunk = lines[s:s + window]
        out.append((s + 1, "\n".join(f"{s + i + 1}: {ln}" for i, ln in enumerate(chunk))))
    return out or [(1, "")]


def _hint_block(per_file_entry):
    routes, sinks, dyn = per_file_entry
    out = []
    for ln, _, code in routes:
        out.append(f"   [ROUTE] {code}  L{ln}")
    for ln, label, code in sinks:
        out.append(f"   [SINK:{label}] {code}  L{ln}")
    for ln, kind, code in dyn:
        out.append(f"   [DYN:{kind}] {code}  L{ln}")
    return "\n".join(out) or "   (none)"


def _parse_note(txt):
    after = (txt or "").split("</think>")[-1]
    for scope in (after, txt or ""):
        i, j = scope.find("{"), scope.rfind("}")
        if 0 <= i < j:
            try:
                d = json.loads(scope[i:j + 1])
                if isinstance(d, dict):
                    return d
            except Exception:
                pass
    return {}


def read_note(model, root, path, per_file_entry):
    """The model reads one pinned file (windowed around its pins, seeded with the map hints) -> a note."""
    try:
        src = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    routes, sinks, dyn = per_file_entry
    focus = [ln for ln, _, _ in routes] + [ln for ln, _, _ in sinks] + [ln for ln, _, _ in dyn]
    hints = _hint_block(per_file_entry)
    rel = _rel(root, path)
    note = {"file": rel, "purpose": "", "untrusted_inputs": "", "findings": [],
            "classes_to_try_first": [], "cross_file": ""}
    wins = _windows_for(src, focus)
    for start, body in wins:
        span = f" (lines {start}-{start + _WINDOW - 1})" if len(wins) > 1 else ""
        user = (f"FILE {rel}{span}\nMAP HINTS (confirm or dismiss against the code):\n{hints}\n\n"
                f"SOURCE:\n{body}")
        txt = model.generate(_NOTE_SYS, user, max_new_tokens=_TOKENS, temperature=0.0, think=False,
                             json_mode=True)
        d = _parse_note(txt)
        if not d:
            continue
        note["purpose"] = note["purpose"] or str(d.get("purpose") or "")
        note["untrusted_inputs"] = note["untrusted_inputs"] or str(d.get("untrusted_inputs") or "")
        note["cross_file"] = note["cross_file"] or str(d.get("cross_file") or "")
        for f in (d.get("findings") or []):
            if isinstance(f, dict):
                note["findings"].append(f)
        for c in (d.get("classes_to_try_first") or []):
            if c and c not in note["classes_to_try_first"]:
                note["classes_to_try_first"].append(c)
    # Ground the hint: keep only classes that an actual finding carries (drops the "dumped the whole
    # taxonomy on a clean file" glitch). If findings exist but none matched, fall back to their classes.
    fclasses = []
    for f in note["findings"]:
        c = str(f.get("class", "")).lower()
        if c and c not in fclasses:
            fclasses.append(c)
    kept = [c for c in note["classes_to_try_first"] if str(c).lower() in fclasses]
    note["classes_to_try_first"] = (kept or fclasses)[:5]
    return note


def _render_md(root, notes):
    out = [f"# wave notebook — {Path(root).name}", "",
           "Per-file pentester notes (grounded in reading each pinned file). Findings are `believed` "
           "leads for Stage 2/3 to hypothesize + prove -- never verdicts.", ""]
    for nt in notes:
        out.append(f"## {nt['file']}")
        if nt.get("purpose"):
            out.append(f"- purpose: {nt['purpose']}")
        if nt.get("untrusted_inputs"):
            out.append(f"- untrusted inputs: {nt['untrusted_inputs']}")
        if nt.get("classes_to_try_first"):
            out.append(f"- try first: {', '.join(nt['classes_to_try_first'])}")
        if nt.get("cross_file"):
            out.append(f"- cross-file: {nt['cross_file']}")
        for f in nt.get("findings", []):
            out.append(f"  - L{f.get('line','?')} [{f.get('class','?')}/{f.get('confidence','?')}] "
                       f"{f.get('sink','')} <- {f.get('input','?')}  ({f.get('why','')})")
        out.append("")
    return "\n".join(out)


def read_notes(model, root, per_file, pinned, budget=20, out_dir=None, resume=True, targets=None):
    """Read files into persistent notes. `targets` (an ordered list of absolute paths, e.g. from
    select_targets) overrides the default top-`budget` pin-density order. Appends each note to
    wave_notebook.jsonl as it is produced (durable + resumable: a re-run skips files already noted), then
    renders wave_notebook.md. Returns (notes, paths)."""
    out_dir = Path(out_dir or root)
    jsonl = out_dir / "wave_notebook.jsonl"
    done = {}
    if resume and jsonl.exists():
        for line in jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                d = json.loads(line)
                done[d["file"]] = d
            except Exception:
                pass
    targets = list(targets) if targets is not None else pinned[:budget]
    with jsonl.open("a", encoding="utf-8") as fh:
        for i, path in enumerate(targets, 1):
            rel = _rel(root, path)
            if rel in done:
                print(f"[notebook] {i}/{len(targets)} skip (already noted) {rel}", flush=True)
                continue
            print(f"[notebook] {i}/{len(targets)} reading {rel} ...", flush=True)
            note = read_note(model, root, path, per_file[path])
            if note is None:
                continue
            fh.write(json.dumps(note) + "\n")
            fh.flush()
            done[rel] = note
            print(f"[notebook]   -> {len(note['findings'])} finding(s); "
                  f"try {note['classes_to_try_first'] or '-'}", flush=True)
    notes = [done[_rel(root, p)] for p in pinned if _rel(root, p) in done]
    md = _render_md(root, notes)
    (out_dir / "wave_notebook.md").write_text(md, encoding="utf-8")
    return notes, {"jsonl": str(jsonl), "md": str(out_dir / "wave_notebook.md")}
