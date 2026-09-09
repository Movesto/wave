"""Render the pipeline's results into a human-readable report.

The raw artifacts (wave_findings.jsonl / casefile.json) are for the machine + resume. This turns them into a
`wave_report.md` a person can actually read: what the model PROVED, what needs review, what it cleared, and
the unproven leads -- each with the model's own conclusion + the cited evidence, and the fix if one was
certified. Written into a `wave_results/` folder in the target repo.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

_ORDER = ["confirmed", "anomalous_state", "believed", "blocked", "refuted"]
_HEAD = {
    "confirmed": "## ✅ Confirmed vulnerabilities  — tool-witnessed, exploitable",
    "anomalous_state": "## ⚠️  Needs human review  — an observed effect, but a judgment call",
    "believed": "## \U0001f50d Unproven leads  — reasoned, not witnessed (review)",
    "blocked": "## ⛔ Blocked  — could not be run/provisioned",
    "refuted": "## ✓ Cleared as safe  — the model ran it and it held",
}


def _load(p):
    p = Path(p)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def _last(findings):
    seen = {}
    for r in findings:
        seen[(r.get("file"), r.get("line"), r.get("class"))] = r
    return list(seen.values())


def _sev_key(r):
    conf = 1 if str(r.get("confidence", "")).lower() == "high" else 0
    return (conf, str(r.get("cwe", "")))


def generate(target, out_dir=None, model="", patches_path=None):
    """Read the run's artifacts under `target` and write wave_results/wave_report.md. Returns its path."""
    target = Path(target)
    src = Path(out_dir) if out_dir else target
    findings = _last(_load(src / "wave_findings.jsonl"))
    patches = {(p.get("file"), p.get("line")): p for p in _load(patches_path or (src / "wave_patches.jsonl"))}

    by = {v: [] for v in _ORDER}
    for r in findings:
        by.setdefault(r.get("verdict", "believed"), by.setdefault("believed", [])).append(r)

    n = {k: len(v) for k, v in by.items()}
    lines = [f"# wave report — {target.name}",
             f"*generated {time.strftime('%Y-%m-%d %H:%M')}" + (f" · model `{model}`" if model else "") + "*",
             "",
             "## Summary",
             f"- **{n.get('confirmed', 0)} confirmed** (proven exploitable)",
             f"- **{n.get('anomalous_state', 0)} need review** (observed effect, human judgment)",
             f"- {n.get('believed', 0)} unproven leads · {n.get('blocked', 0)} blocked · "
             f"{n.get('refuted', 0)} cleared as safe",
             f"- {sum(1 for p in patches.values() if p.get('status') == 'fixed')} fixed "
             f"(Stage 4 patch, exploit demonstrably no longer fires)",
             ""]

    for v in _ORDER:
        items = by.get(v) or []
        if not items:
            continue
        lines.append(_HEAD[v] + f"  [{len(items)}]")
        lines.append("")
        for r in sorted(items, key=_sev_key, reverse=True):
            cwe = r.get("cwe") or r.get("class", "")
            loc = f"{r.get('file')}:{r.get('line')}"
            unit = f"  `{r.get('unit')}`" if r.get("unit") else ""
            lines.append(f"### [{cwe}] {r.get('class', '')} — {loc}{unit}")
            if r.get("sink"):
                lines.append(f"- **sink:** `{r['sink']}`")
            ev = r.get("evidence") or ""
            why = r.get("why") or ""
            if v == "confirmed" and ev:
                lines.append(f"- **what the model proved:** {ev}")
            elif v == "anomalous_state":
                lines.append(f"- **what the model observed:** {ev or why}")
            elif why or ev:
                lines.append(f"- **the model's read:** {why or ev}")
            if r.get("reachability"):
                lines.append(f"- **reachability:** {r['reachability']}")
            if r.get("oracle"):
                lines.append(f"- **how:** {r['oracle']}")
            pat = patches.get((r.get("file"), r.get("line")))
            if pat:
                st = pat.get("status", "")
                tag = {"fixed": "✅ fixed", "patch-unverified": "❓ patch unverified",
                       "patch-rejected": "❌ patch rejected"}.get(st, st)
                lines.append(f"- **fix (Stage 4):** {tag}"
                             + (f" — {pat.get('gate_a_note', '')[:80]}" if pat.get("gate_a_note") else ""))
                if st == "fixed" and pat.get("patch"):
                    snippet = "\n".join(pat["patch"].splitlines()[:12])
                    lines.append("\n```\n" + snippet + "\n```")
            lines.append("")

    if not findings:
        lines.append("_No findings reached the proof stage. See wave_candidates.jsonl / wave_notebook.md for "
                     "what was detected, or the run log for where it stopped._\n")

    dest = src / "wave_results"
    dest.mkdir(parents=True, exist_ok=True)
    report = dest / "wave_report.md"
    report.write_text("\n".join(lines), encoding="utf-8")
    # a self-contained copy of the machine artifacts next to the report
    for name in ("wave_findings.jsonl", "wave_patches.jsonl", "casefile.json"):
        s = src / name
        if s.exists():
            try:
                (dest / name).write_text(s.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
            except OSError:
                pass
    return report
