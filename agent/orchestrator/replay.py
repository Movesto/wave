"""Proof replay -- re-verify previously CONFIRMED findings, turning them into a security regression suite.

Every confirmed finding was proven by actually running an exploit. This re-runs the proof ladder on those
same findings (via prove.reprove -- the one machinery allowed to change a witnessed verdict) and reports,
per finding, whether the exploit STILL fires (still-vulnerable) or no longer does (resolved). Run it in CI
after changes: if a known vuln is still/again exploitable you know immediately; if a fix landed, it shows
`resolved`.

Deterministic for canary-provable findings (rung1, no model); model-driven otherwise (needs a model, like the
prove stage).
"""
from __future__ import annotations

import json
from pathlib import Path


def load_confirmed(target, out_dir=None):
    """The previously-CONFIRMED findings (last verdict per location) from wave_findings.jsonl."""
    p = Path(out_dir or target) / "wave_findings.jsonl"
    if not p.exists():
        return []
    last = {}
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        last[(d.get("file"), d.get("line"), d.get("class"))] = d
    return [d for d in last.values() if d.get("verdict") == "confirmed"]


def _status(now):
    """Map a re-proof verdict to a replay outcome."""
    if now == "confirmed":
        return "still-vulnerable"
    if now in ("refuted", "not_exploitable"):
        return "resolved"
    return "changed"                                          # anomalous_state / believed / blocked / unknown


def run(model, target, online=False, max_steps=8, cmap=None):
    """Re-verify every confirmed finding. Returns (results, summary). Each result:
    {file,line,class,cwe,was:'confirmed',now:<verdict>,status}."""
    confirmed = load_confirmed(target)
    if not confirmed:
        return [], {"confirmed": 0, "still_vulnerable": 0, "resolved": 0, "changed": 0}
    from . import prove
    updated = prove.reprove(model, target, confirmed, gate=True, online=online, max_steps=max_steps, cmap=cmap)
    by_key = {(u.get("file"), u.get("line"), u.get("class")): u for u in updated}
    results = []
    for c in confirmed:
        u = by_key.get((c.get("file"), c.get("line"), c.get("class")), {})
        now = u.get("verdict", "unknown")
        results.append({"file": c.get("file"), "line": c.get("line"), "class": c.get("class"),
                        "cwe": c.get("cwe", ""), "was": "confirmed", "now": now, "status": _status(now),
                        "evidence": (u.get("evidence") or "")[:120]})
    summary = {"confirmed": len(confirmed),
               "still_vulnerable": sum(1 for r in results if r["status"] == "still-vulnerable"),
               "resolved": sum(1 for r in results if r["status"] == "resolved"),
               "changed": sum(1 for r in results if r["status"] == "changed")}
    return results, summary


def render(results, summary=None):
    if not results:
        return "## Proof replay\n\nNo confirmed findings to replay.\n"
    s = summary or {}
    lines = [f"## Proof replay  ({len(results)} confirmed findings re-verified)", "",
             f"still-vulnerable: {s.get('still_vulnerable', 0)}  ·  resolved: {s.get('resolved', 0)}  ·  "
             f"changed: {s.get('changed', 0)}", ""]
    icon = {"still-vulnerable": "❌", "resolved": "✅", "changed": "⚠️"}
    for r in sorted(results, key=lambda x: x["status"]):
        lines.append(f"- {icon.get(r['status'], '')} **{r['status']}** {r['cwe'] or r['class']} "
                     f"{r['file']}:{r['line']}  (was confirmed → now {r['now']})")
    return "\n".join(lines) + "\n"
