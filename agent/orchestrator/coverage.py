"""Stage 1a -- COVERAGE REVIEW: the second (audit) model reads the WHOLE-map context and negotiates with
the harness about attack surface the deterministic pins MISSED.

The pin pipeline is pattern-match ONLY: regex `scan_pins` pins every file -> reachability ranks -> top-N go
to the notebook, which reads ONE file at a time and only confirms/dismisses. Nothing ever asks the question
"is a CORE part of this project missing from the pinned set?" -- a library-wrapped sink whose call line the
dictionary never encoded (the Langflow MCP-stdio RCE), a convention route the `_ROUTE` table doesn't know, a
feature whose risk no regex captures. A fixed vocabulary can only find what someone pre-listed. This stage
closes that WITHOUT a new regex:

  - the audit model (WAVE_AUDIT_MODEL -- GLM; local fallback) sees the DIGEST (what WAS pinned) + a project
    SKELETON (dir tree + per-dir imports + purpose = what the project IS) -- the whole-repo context the
    notebook never gets because it reads one file at a time;
  - it ASKS about files/features it believes are attack surface but aren't pinned;
  - the HARNESS answers DETERMINISTICALLY why each was in/out (`explain_inclusion` -- pure lookup over the
    very gates that excluded it, so it CANNOT lie): included / below-top-N / demoted / no-pattern / not-source;
  - the model REACTS to each explanation and, over a few turns, CONFIRMS which to promote; the harness
    PROMOTES a promotable file to a HINT pin and adds it to the notebook read set.

SAFETY INVARIANT: a promotion only adds a file to READ -- never a verdict. Confirmation still runs the
deterministic prove/oracle path downstream. A hallucinated nomination is structurally bounded: a path that
isn't in the codemap resolves to `not-source` and is NOT promotable, so it costs nothing. Comprehension
only, exactly like eyes.py -- this stage NEVER decides whether anything is vulnerable.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from .eyes import _json_block
from .repomap import _rel

# --- reason codes the harness returns for any path ------------------------------------------------------
INCLUDED = "included"          # already in the top-N read set
BELOW_TOPN = "below-top-n"     # pinned + kept, but ranked below the budget cutoff
DEMOTED = "demoted"            # dropped on a partial scan (low-priority: test/fixture/infra/script/root-tools)
NO_PATTERN = "no-pattern"      # in the codemap, but no route / no sink / no capability import matched
NOT_SOURCE = "not-source"      # not parsed as source (unknown path / unsupported language / not a file)

_PROMOTABLE = {BELOW_TOPN, DEMOTED, NO_PATTERN}   # real files the model can argue back into the read set

_MAX_TURNS = 6                 # hard cap on the negotiation so a chatty model can't run away
_MAX_ASK_PER_TURN = 12         # questions answered per turn
_MAX_PROMOTIONS = 25           # ceiling on files the review can add (protects the notebook budget)
_SKELETON_DIRS = 120           # cap directories rendered into the skeleton
_IMPORTS_PER_DIR = 14          # cap imports summarised per directory


def make_audit_model(primary):
    """The decorrelated second model (WAVE_AUDIT_MODEL) that drives the review, reusing prove's wiring so
    there is ONE audit-model convention. Returns the primary unchanged when WAVE_AUDIT_MODEL is unset --
    the review then runs on the local model (enhancement, not dependency, exactly like the Eyes)."""
    from .prove import _auditor_model
    return _auditor_model(primary)


# ----------------------------------------------------------------------------------------------------------
#  THE HONEST HARNESS ANSWER
# ----------------------------------------------------------------------------------------------------------

def explain_inclusion(path, cmap, per_file, ranked_pinned, dropped, budget):
    """Why was `path` in or out of the read set? Pure lookup over the same machinery that decided it -- no
    model, no judgement, so it cannot misreport. Returns {reason, promotable, detail, rank, total}."""
    rank_of = {p: i for i, p in enumerate(ranked_pinned)}
    total = len(ranked_pinned)
    if path in rank_of:
        rank = rank_of[path]
        if budget and rank >= budget:
            return {"reason": BELOW_TOPN, "promotable": True, "rank": rank, "total": total,
                    "detail": f"pinned but ranked #{rank + 1} of {total}; the notebook reads the top {budget}"}
        return {"reason": INCLUDED, "promotable": False, "rank": rank, "total": total,
                "detail": f"already selected (rank #{rank + 1} of {total})"}
    if path in set(dropped):
        return {"reason": DEMOTED, "promotable": True, "rank": None, "total": total,
                "detail": "dropped on this partial scan -- a low-priority path (test/fixture/infra/script/"
                          "dockerfile/root-tools). Use --all-files to include such files everywhere"}
    finfo = cmap.files.get(path)
    if finfo is None:
        return {"reason": NOT_SOURCE, "promotable": False, "rank": None, "total": total,
                "detail": "not in the code map -- not a recognised source file (unknown path, unsupported "
                          "language, or a parse failure)"}
    # In the code map, neither selected nor dropped -> nothing pinned it.
    try:
        from . import select as _select
        _prio, sig = _select.file_priority(cmap, per_file, path)
    except Exception:
        sig = {}
    bits = []
    if sig.get("frontend"):
        bits.append("classified as frontend/browser code (server-only sink classes don't apply)")
    if sig.get("lowpri"):
        bits.append("a low-priority path")
    extra = (" -- " + "; ".join(bits)) if bits else ""
    return {"reason": NO_PATTERN, "promotable": True, "rank": None, "total": total,
            "detail": "in the code map but UNPINNED -- no route, no sink in the 9-class dictionary, and no "
                      "risky-capability import matched" + extra}


# ----------------------------------------------------------------------------------------------------------
#  WHOLE-MAP CONTEXT the model never otherwise sees
# ----------------------------------------------------------------------------------------------------------

def _skeleton(cmap, root, pinned):
    """A compact, per-DIRECTORY map of the project: for each dir, how many files, how many already pinned,
    languages, and the union of imports -- so the model can spot a feature dir (e.g. components/tools/ that
    `import mcp`) whose surface isn't pinned, then ASK about it. Per-dir aggregation keeps a 25k-file
    monorepo inside the context budget; the model drills into any path through the negotiation."""
    pinset = set(pinned)
    dirs = {}
    for p, fi in cmap.files.items():
        d = os.path.dirname(_rel(root, p)) or "."
        slot = dirs.setdefault(d, {"n": 0, "pinned": 0, "langs": set(), "imports": set()})
        slot["n"] += 1
        if p in pinset:
            slot["pinned"] += 1
        if getattr(fi, "lang", None):
            slot["langs"].add(fi.lang)
        for imp in (getattr(fi, "imports", None) or ())[:_IMPORTS_PER_DIR]:
            slot["imports"].add(str(imp)[:48])
    ordered = sorted(dirs.items(), key=lambda kv: (-(kv[1]["n"] - kv[1]["pinned"]), kv[0]))
    lines = ["# project skeleton (per-directory) -- pinned vs total, languages, imports", ""]
    for d, s in ordered[:_SKELETON_DIRS]:
        imps = ", ".join(sorted(s["imports"])[:_IMPORTS_PER_DIR])
        langs = "/".join(sorted(s["langs"]))
        lines.append(f"{d}/   {s['pinned']}/{s['n']} pinned   [{langs}]" + (f"   imports: {imps}" if imps else ""))
    if len(ordered) > _SKELETON_DIRS:
        lines.append(f"... {len(ordered) - _SKELETON_DIRS} more directories (ask by path)")
    return "\n".join(lines)


def _resolve(cmap, root, query):
    """Map a model's nomination -- a path OR a feature keyword -- to real code-map paths. An exact/suffix
    path match wins; otherwise treat it as a substring over paths AND over each file's imports (so 'mcp'
    finds the file that `import mcp` even with no sink line)."""
    q = str(query or "").strip().replace("\\", "/").lower()
    if not q:
        return []
    exact = [p for p in cmap.files if _rel(root, p).replace("\\", "/").lower() == q
             or p.replace("\\", "/").lower().endswith(q)]
    if exact:
        return exact[:8]
    hits = []
    for p, fi in cmap.files.items():
        rel = _rel(root, p).replace("\\", "/").lower()
        if q in rel:
            hits.append(p)
            continue
        if any(q in str(imp).lower() for imp in (getattr(fi, "imports", None) or ())):
            hits.append(p)
    return hits[:8]


# ----------------------------------------------------------------------------------------------------------
#  THE NEGOTIATION
# ----------------------------------------------------------------------------------------------------------

_SYS = (
    "You are a COVERAGE AUDITOR for a security scanner. A deterministic regex pass has already pinned the "
    "attack surface it recognises; a downstream verifier will deep-read ONLY the pinned files. Regexes can "
    "only find what was pre-listed, so your ONE job is to catch CORE attack surface the pins MISSED: a file "
    "that wraps a dangerous capability through a library (process/remote exec, XML, LDAP, deserialisation, "
    "SSRF, templating), a convention-based route handler, an auth/permission layer -- parts central to what "
    "THIS project does. You do NOT decide whether anything is vulnerable; a separate tool proves that. You "
    "only point at files that should be READ.\n"
    "Each turn, reply with ONE JSON object and nothing else:\n"
    '{"ask": ["<path or feature keyword>", ...], "confirm_promote": ["<path the harness called promotable>", '
    '...], "done": <true|false>}\n'
    "- Put files/features you want explained in `ask`. The harness replies with WHY each was included or "
    "excluded (it cannot lie -- it is reading its own decision).\n"
    "- After you see an explanation, if you still believe an EXCLUDED file is real attack surface, put its "
    "exact path in `confirm_promote` NEXT turn to have it read. Only paths the harness marked promotable "
    "can be promoted.\n"
    "- Set `done`: true when you have no more gaps to raise. Be decisive -- raise only genuine core surface, "
    "not every file."
)


def _answer(asks, cmap, root, per_file, ranked_pinned, dropped, budget, log):
    """Resolve + explain each nomination. Returns (reply_text, {path: info} for promotable paths seen)."""
    reply, promotable_seen = [], {}
    for q in asks[:_MAX_ASK_PER_TURN]:
        paths = _resolve(cmap, root, q)
        if not paths:
            reply.append(f"- '{q}': no file in the code map matches that path or feature.")
            log.append({"ask": q, "resolved": [], "reason": "no-match"})
            continue
        for p in paths:
            info = explain_inclusion(p, cmap, per_file, ranked_pinned, dropped, budget)
            rel = _rel(root, p)
            tag = "PROMOTABLE" if info["promotable"] else info["reason"]
            reply.append(f"- {rel}: [{info['reason']}] {info['detail']}"
                         + (f"  (you may confirm_promote '{rel}')" if info["promotable"] else ""))
            log.append({"ask": q, "resolved": rel, "reason": info["reason"],
                        "promotable": info["promotable"]})
            if info["promotable"]:
                promotable_seen[p] = info
                promotable_seen[rel] = info   # let the model confirm by rel path too
    return "\n".join(reply) if reply else "(nothing to explain)", promotable_seen


def review(primary, root, cmap, per_file, ranked_pinned, dropped, budget, out_dir=None):
    """Run the coverage negotiation. Returns (promoted_paths, log). Writes wave_coverage.md. Promotions are
    HINTS for the notebook read set -- never findings. Safe no-op (returns []) when no audit model / on any
    model failure: the deterministic pipeline is unchanged."""
    audit = make_audit_model(primary)
    log, promoted = [], []
    if audit is None:
        return promoted, log

    skeleton = _skeleton(cmap, root, ranked_pinned)
    pinned_rel = [_rel(root, p) for p in ranked_pinned[:budget]]
    convo = (
        f"{skeleton}\n\n# already pinned (the surface that WILL be read), top {len(pinned_rel)}:\n"
        + "\n".join(f"- {r}" for r in pinned_rel)
        + "\n\nReview the skeleton. Which CORE attack surface of this project is NOT in the pinned list? "
        "Ask about any path or feature; I will tell you why it was in or out."
    )
    # the full per-file detail (wave_map.md) exists on disk for the model's reference if a client reads it
    promotable_pool = {}
    for turn in range(_MAX_TURNS):
        try:
            raw = audit.generate(_SYS, convo, max_new_tokens=1800, temperature=0.2,
                                 think=False, json_mode=True)
        except Exception as e:
            log.append({"turn": turn, "error": str(e)[:160]})
            break
        data = _json_block(raw) or {}
        asks = [a for a in (data.get("ask") or []) if isinstance(a, str)]
        confirms = [c for c in (data.get("confirm_promote") or []) if isinstance(c, str)]

        # promote anything the model confirmed that the harness earlier (or now) called promotable
        for c in confirms:
            for cand in ([c] + _resolve(cmap, root, c)):
                info = promotable_pool.get(cand)
                if info is None and cand in cmap.files:
                    info = explain_inclusion(cand, cmap, per_file, ranked_pinned, dropped, budget)
                real = cand if cand in cmap.files else None
                if real is None:
                    # confirm may be a rel path -> resolve to the real key
                    rp = _resolve(cmap, root, c)
                    real = rp[0] if rp else None
                if real and info and info.get("promotable") and real not in promoted:
                    if len(promoted) >= _MAX_PROMOTIONS:
                        break
                    promoted.append(real)
                    log.append({"turn": turn, "promoted": _rel(root, real),
                                "reason": info["reason"]})
                    break

        if data.get("done") or (not asks and not confirms):
            break
        reply, seen = _answer(asks, cmap, root, per_file, ranked_pinned, dropped, budget, log)
        promotable_pool.update(seen)
        convo = ("Previous context stands. HARNESS explanations:\n" + reply
                 + "\n\nConfirm any still-missing EXCLUDED file in `confirm_promote`, raise new gaps in "
                   "`ask`, or set done:true.")

    _write_log(Path(out_dir or root) / "wave_coverage.md", root, promoted, log, cmap)
    return promoted, log


def _write_log(path, root, promoted, log, cmap):
    lines = ["# wave coverage review", "",
             "The audit model reviewed the whole-map skeleton against the pinned surface and negotiated with "
             "the harness about missed attack surface. Promotions below were ADDED to the read set as hints "
             "(not findings -- confirmation still runs the deterministic prove path).", "",
             f"## promoted into the read set ({len(promoted)})"]
    if promoted:
        for p in promoted:
            lines.append(f"- {_rel(root, p)}")
    else:
        lines.append("- (none -- the pinned surface covered the project's core)")
    lines += ["", "## negotiation log"]
    for e in log:
        lines.append("- " + json.dumps(e, ensure_ascii=False))
    try:
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError:
        pass
