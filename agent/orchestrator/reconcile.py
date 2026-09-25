"""Stage 5 -- Review & Reconcile (Phase 1: deterministic).

Every finding up to here was judged in ISOLATION (Stage 3 proves one candidate at a time, the report merely
collates). Nothing does a final "pentester read" over the whole set, so the same sink flagged twice under two
class labels can land two contradictory verdicts (the netdata `netdata-updater.sh:1508` case: `anomalous_state`
+ `not_exploitable`). This pass dedups by location+sink and reconciles contradictions deterministically.

THE ONE RULE (see agent/docs/stage5_review_reconcile_plan.md sec 3): reconciliation may merge, re-prioritize
and annotate -- it may NEVER overturn a tool-witnessed verdict with reasoning, and it never DELETES a finding
(a merge unions the evidence; the full audit trail is written to wave_reconcile.jsonl). Phase 1 is fully
deterministic (no model), so it adds no bias surface. Phases 2 (model reconcile) and 3 (look-alike recall) are
separate, later, and gated by the same rule.
"""
from __future__ import annotations

import json
from pathlib import Path

# attention precedence, highest first: taking the highest-attention verdict in a merged group AUTOMATICALLY
# enforces the guardrail -- a witnessed confirmed/anomalous can never be dropped below by a reasoned verdict.
_ATTENTION = ["confirmed", "anomalous_state", "blocked", "believed", "not_exploitable", "refuted"]
_RANK = {v: i for i, v in enumerate(_ATTENTION)}


def _attention(verdict):
    return _RANK.get(verdict, len(_ATTENTION))          # unknown verdicts sort last (least attention)


def _norm_sink(sink):
    """A stable key for 'the same sink': drop trailing shell combinators (`|| fatal`, `&& x`, a trailing `;`)
    and collapse whitespace, so `. "$(...)/.install-type"` and `. "$(...)/.install-type" || fatal` match.
    Pipes are KEPT (they're often integral to the sink, e.g. `wget ... 2>&1 | grep Location`)."""
    s = sink or ""
    for sep in (" || ", " && "):
        i = s.find(sep)
        if i > 0:
            s = s[:i]
    s = s.rstrip().rstrip(";").rstrip()
    return " ".join(s.split())


def _loc_key(f):
    """Where the finding lives: (file, enclosing-unit) when a unit is known, else (file, exact-line) for
    unit-less files (shell scripts). Uses the record's OWN fields -- no repo re-parse needed."""
    unit = (f.get("unit") or "").strip()
    return (f.get("file", ""), unit) if unit else (f.get("file", ""), f"L{f.get('line', '')}")


def _merge_key(f):
    return (_loc_key(f), _norm_sink(f.get("sink", "")))


def _specific_class(a, b):
    """Prefer a real class/cwe over the uncategorized 'other'/empty when merging (1508: cmd beats other)."""
    return a if (a and a.lower() != "other") else b


def _merge_group(items):
    """Collapse findings that share (location, normalized-sink) into ONE, honoring the precedence+guardrail.
    Returns (merged_finding, action) where action is None (single, unchanged), 'dedup' (same verdict) or
    'contradiction' (differing verdicts reconciled by precedence)."""
    if len(items) == 1:
        return items[0], None
    ordered = sorted(items, key=lambda f: _attention(f.get("verdict", "believed")))
    base = dict(ordered[0])                              # highest-attention member is the base
    verdicts = [f.get("verdict", "believed") for f in items]
    distinct = list(dict.fromkeys(verdicts))
    # prefer a specific class/cwe over 'other'/empty
    for f in ordered:
        base["class"] = _specific_class(base.get("class", ""), f.get("class", ""))
        base["cwe"] = base.get("cwe") or f.get("cwe", "")
    # union the evidence + reasoning of the OTHER members so nothing is hidden by the merge
    others = [f for f in ordered[1:]]
    extra_ev = [e for e in (f.get("evidence") or "" for f in others) if e]
    if extra_ev:
        base["evidence"] = ((base.get("evidence") or "") + "  |  also observed: " + " ; ".join(extra_ev)).strip()
    note = (f"[reconciled] {len(items)} candidates at this location merged"
            + (f"; verdicts seen: {', '.join(distinct)} -> kept '{base.get('verdict')}' "
               f"(highest-attention; a witnessed verdict is never dropped for a reasoned one)"
               if len(distinct) > 1 else " (duplicates)"))
    # carry the dropped members' reasoning so a human can see WHY they differed
    other_whys = [f"{f.get('verdict')}: {(f.get('why') or '')[:160]}" for f in others if f.get("why")]
    if other_whys:
        note += "  ||  other reads -> " + "  ;  ".join(other_whys)
    base["why"] = ((base.get("why") or "") + "  " + note).strip()
    base["reconciled_from"] = len(items)
    return base, ("contradiction" if len(distinct) > 1 else "dedup")


def reconcile(findings):
    """Deterministic dedup + contradiction reconciliation. Returns (reconciled_findings, actions_log)."""
    groups = {}
    order = []
    for f in findings:
        k = _merge_key(f)
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(f)
    out, log = [], []
    for k in order:
        merged, action = _merge_group(groups[k])
        out.append(merged)
        if action:
            (loc, sink) = k
            log.append({"action": action, "file": loc[0], "where": loc[1], "sink": sink,
                        "count": len(groups[k]),
                        "verdicts": [g.get("verdict", "believed") for g in groups[k]],
                        "kept": merged.get("verdict"),
                        "reason": ("differing verdicts on the same sink reconciled by precedence "
                                   "(witnessed never dropped for reasoned)" if action == "contradiction"
                                   else "identical duplicate findings collapsed")})
    return out, log


# ----- Phase 2 (bounded model reconcile) + Phase 3 (cross-file look-alike recall) -----
# THE GUARDRAIL (doc sec 3): the model may reconcile among REASONED verdicts, annotate, or request a tool
# RE-INVESTIGATION -- it can NEVER change a WITNESSED verdict by reasoning. Enforced here, not just prompted.
_WITNESSED = {"confirmed", "anomalous_state"}       # observation-backed -> prose-immutable
_REASONED = {"believed", "not_exploitable"}         # the model's to reconcile, with the safe direction

import re as _re


def _callee(sink):
    """A canonical call target for look-alike clustering: the name being called at the sink (execSync, curl,
    posix_spawn, open, ...). Fuzzy on purpose -- a loose cluster only means the model looks at unrelated code
    and says 'these differ, keep both', which the guardrail makes harmless."""
    s = _norm_sink(sink)
    m = _re.search(r'([A-Za-z_][\w.:]*)\s*\(', s)            # token right before the first '('
    if m:
        return m.group(1).split(".")[-1].split("::")[-1].lower()
    s2 = _re.sub(r'[${}"\'`]', "", s)                        # shell: first bare word
    toks = _re.findall(r'[A-Za-z_][\w-]*', s2)
    return (toks[0].lower() if toks else s[:24].lower())


def _signature(f):
    return (str(f.get("class", "")).lower(), _callee(f.get("sink", "")))


def _clusters(findings):
    """Cross-file look-alike clusters worth a reconcile call: same (class, callee) signature, >1 member, and
    DIVERGENT verdicts (a mix that includes a witnessed-vs-dismissed disagreement is exactly the interesting
    case). Ranked by the highest attention in the cluster (so the budget spends on the sharpest conflicts)."""
    sig = {}
    for f in findings:
        sig.setdefault(_signature(f), []).append(f)
    out = []
    for members in sig.values():
        if len(members) < 2:
            continue
        verdicts = {m.get("verdict", "believed") for m in members}
        if len(verdicts) > 1:                               # a disagreement to reconcile
            out.append(members)
    out.sort(key=lambda ms: min(_attention(m.get("verdict", "believed")) for m in ms))
    return out


_RECONCILE_SYS = (
    "You are reconciling security findings that target STRUCTURALLY SIMILAR code but received DIFFERENT "
    "verdicts. Explain the real difference (usually reachability / who controls the input / execution "
    "context), or say which is wrong. STRICT RULES: (1) You may NOT change a WITNESSED verdict ('confirmed' "
    "or 'anomalous_state') by reasoning -- if you believe a look-alike was WRONGLY DISMISSED, request "
    "'reinvestigate' for it (only a tool re-run can change a witnessed result). (2) You MAY 'reclassify' "
    "between the two REASONED verdicts 'believed' and 'not_exploitable', but only WITH a concrete cited reason, "
    "and when unsure keep 'believed'. (3) Never invent findings. Return ONE json object: "
    '{"explanation":"...","actions":[{"ref":"<file:line>","action":"keep|annotate|reinvestigate|reclassify",'
    '"verdict":"believed|not_exploitable (only for reclassify)","reason":"..."}]}'
)


def _reconcile_cluster(model, target, cluster):
    """One focused, evidence-anchored reconcile call over a single look-alike cluster. Returns parsed actions
    (list) or []. Only the cluster + its code windows are shown -- never the whole report (bounds bias)."""
    from . import briefs
    parts = []
    for f in cluster:
        ref = f"{f.get('file')}:{f.get('line')}"
        win = briefs._code_window(str(Path(target) / f.get("file", "")), int(f.get("line") or 0), ctx=14)
        parts.append(f"### {ref}  [class={f.get('class')} verdict={f.get('verdict')}]\n"
                     f"sink: {f.get('sink', '')}\nwhy: {(f.get('why') or '')[:240]}\ncode:\n{win}")
    user = ("These findings look structurally similar but got different verdicts. Reconcile them per the "
            "rules.\n\n" + "\n\n".join(parts))
    try:
        raw = model.generate(_RECONCILE_SYS, user, max_new_tokens=1200)
    except Exception:
        return []
    for scope in ((raw or "").split("</think>")[-1], raw or ""):
        m = _re.search(r'\{.*\}', scope, _re.S)
        if m:
            try:
                d = json.loads(m.group(0))
                acts = d.get("actions")
                return acts if isinstance(acts, list) else []
            except Exception:
                continue
    return []


def _apply_cluster_actions(actions, by_ref, log, reinvest):
    """Apply model actions under the guardrail: reclassify ONLY reasoned<->reasoned; witnessed verdicts are
    prose-immutable (a reclassify aimed at one is REJECTED and logged); reinvestigate collects a key; annotate
    appends the reason to `why`. Nothing is deleted."""
    for a in actions or []:
        if not isinstance(a, dict):
            continue
        ref = str(a.get("ref", "")).strip()
        f = by_ref.get(ref)
        if f is None:
            continue
        act = str(a.get("action", "")).lower()
        reason = str(a.get("reason", ""))[:240]
        cur = f.get("verdict", "believed")
        if act == "reclassify":
            new = str(a.get("verdict", "")).lower()
            if cur in _WITNESSED:
                log.append({"action": "rejected-reclassify", "ref": ref,
                            "reason": f"cannot reason away a witnessed '{cur}' -- request reinvestigate instead"})
            elif cur in _REASONED and new in _REASONED and reason:
                f["verdict"] = new
                f["why"] = ((f.get("why") or "") + f"  [reconcile: {cur}->{new}] {reason}").strip()
                log.append({"action": "reclassify", "ref": ref, "from": cur, "to": new, "reason": reason})
            # otherwise (unsafe/unsupported) -> ignore, safe direction keeps the current reasoned verdict
        elif act == "reinvestigate":
            reinvest.append((f.get("file", ""), int(f.get("line") or 0), str(f.get("class") or "other").lower()))
            log.append({"action": "reinvestigate-queued", "ref": ref, "reason": reason})
        elif act == "annotate" and reason:
            f["why"] = ((f.get("why") or "") + f"  [reconcile note] {reason}").strip()
            log.append({"action": "annotate", "ref": ref, "reason": reason})


def _model_reconcile(model, target, findings, budget, do_reinvestigate, online, jobs=1):
    """Phase 2+3: cluster look-alikes, run a bounded per-cluster reconcile call, then (optionally) re-prove the
    findings the model flagged. Returns (findings, log). A tool re-prove is the only path that changes a
    witnessed verdict. `jobs`>1 runs the per-cluster reconcile CALLS concurrently (cloud model); actions are
    APPLIED on the main thread."""
    from .parallel import fan_out, is_cloud_model
    log = []
    by_ref = {f"{f.get('file')}:{f.get('line')}": f for f in findings}
    reinvest = []                                            # (file, line, class) keys the model asks to re-prove
    clusters = _clusters(findings)[:budget]
    if jobs > 1 and not is_cloud_model(model):
        jobs = 1

    def _compute(cl, i):
        try:
            return cl, _reconcile_cluster(model, target, cl)   # model call -> actions (parallel-safe)
        except Exception:
            return cl, []

    def _commit(cl, result, i):                             # apply actions on the MAIN thread (mutates shared state)
        _cl, actions = result
        log.append({"action": "cluster", "signature": list(_signature(cl[0])),
                    "refs": [f"{m.get('file')}:{m.get('line')}" for m in cl],
                    "verdicts": [m.get("verdict") for m in cl]})
        _apply_cluster_actions(actions, by_ref, log, reinvest)
    fan_out(clusters, _compute, _commit, jobs)
    # dedup the re-investigate queue; a witnessed 'confirmed' is already settled, so never re-prove it
    todo, seen = [], set()
    for (f, ln, cls) in reinvest:
        k = (f, ln, cls)
        rf = by_ref.get(f"{f}:{ln}")
        if k in seen or (rf and rf.get("verdict") == "confirmed"):
            continue
        seen.add(k)
        if rf is not None:
            todo.append(rf)
    if do_reinvestigate and todo:
        from . import prove
        todo = todo[:budget]
        print(f"[reconcile] re-investigating {len(todo)} flagged finding(s) ...", flush=True)
        updated = prove.reprove(model, target, todo, online=online)
        upd = {(u["file"], int(u["line"]), u["class"]): u for u in updated}
        for i, f in enumerate(findings):
            k = (f.get("file", ""), int(f.get("line") or 0), str(f.get("class") or "other").lower())
            if k in upd:
                log.append({"action": "reinvestigated", "ref": f"{f.get('file')}:{f.get('line')}",
                            "from": f.get("verdict"), "to": upd[k].get("verdict")})
                findings[i] = upd[k]
    return findings, log


def _load(path):
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def run(target, findings_path=None, out_dir=None, model=None, budget=6, reinvestigate=True, online=False, jobs=1):
    """Stage 5 driver. Phase 1 (always): load wave_findings.jsonl, dedup + resolve contradictions. Phases 2/3
    (when `model` is given): cluster cross-file look-alikes, run a bounded per-cluster reconcile call, and
    re-prove the findings the model flags (recall). Writes reconciled findings in place + wave_reconcile.jsonl
    (audit log). Deterministic phase is idempotent. Returns (reconciled, log)."""
    base = Path(out_dir) if out_dir else Path(findings_path).parent if findings_path else Path(target)
    fpath = Path(findings_path) if findings_path else base / "wave_findings.jsonl"
    findings = _load(fpath)
    n_in = len(findings)
    reconciled, log = reconcile(findings)                    # Phase 1 -- deterministic
    if model is not None:                                    # Phases 2/3 -- bounded, guardrailed
        reconciled, mlog = _model_reconcile(model, target, reconciled, budget, reinvestigate, online, jobs=jobs)
        log += mlog
        if any(e.get("action") == "reinvestigated" for e in mlog):
            reconciled, dlog2 = reconcile(reconciled)        # re-dedup: re-proved verdicts may have shifted
            log += dlog2
    fpath.write_text("\n".join(json.dumps(r) for r in reconciled) + ("\n" if reconciled else ""),
                     encoding="utf-8")
    (base / "wave_reconcile.jsonl").write_text("\n".join(json.dumps(e) for e in log) + ("\n" if log else ""),
                                               encoding="utf-8")
    contradictions = sum(1 for e in log if e["action"] == "contradiction")
    clusters = sum(1 for e in log if e["action"] == "cluster")
    reproved = sum(1 for e in log if e["action"] == "reinvestigated")
    print(f"[reconcile] {n_in} -> {len(reconciled)} findings ({contradictions} contradiction(s) resolved"
          + (f", {clusters} look-alike cluster(s), {reproved} re-investigated" if model is not None else "")
          + ")", flush=True)
    return reconciled, log
