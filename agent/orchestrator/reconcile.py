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


def run(target, findings_path=None, out_dir=None):
    """Stage 5 driver: load wave_findings.jsonl, reconcile in place, write wave_reconcile.jsonl (audit log).
    Idempotent -- re-running on already-merged findings is a no-op. Returns (reconciled, log)."""
    base = Path(out_dir) if out_dir else Path(findings_path).parent if findings_path else Path(target)
    fpath = Path(findings_path) if findings_path else base / "wave_findings.jsonl"
    findings = _load(fpath)
    reconciled, log = reconcile(findings)
    # write reconciled findings back in place (originals preserved in casefile.json); write the audit log
    fpath.write_text("\n".join(json.dumps(r) for r in reconciled) + ("\n" if reconciled else ""),
                     encoding="utf-8")
    (base / "wave_reconcile.jsonl").write_text("\n".join(json.dumps(e) for e in log) + ("\n" if log else ""),
                                               encoding="utf-8")
    merged = sum(1 for e in log)
    contradictions = sum(1 for e in log if e["action"] == "contradiction")
    print(f"[reconcile] {len(findings)} -> {len(reconciled)} findings "
          f"({merged} merge(s), {contradictions} contradiction(s) resolved)", flush=True)
    return reconciled, log
