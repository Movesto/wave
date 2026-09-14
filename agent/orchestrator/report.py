"""Render the pipeline's results into a human-readable report.

The raw artifacts (wave_findings.jsonl / casefile.json) are for the machine + resume. This turns them into a
report a person can actually read: what the model PROVED, what needs review, what it cleared, and
the unproven leads -- each with the model's own conclusion + the cited evidence, and the fix if one was
certified. It always states a bottom line (including the error/blocked reason when nothing was proven) and
points to the other wave_* files. Written as `WAVE_REPORT.md` at the repo root (the one file to open;
uppercase so it sorts to the top among the wave_* artifacts), with a self-contained copy of the report +
machine artifacts under `wave_results/`.
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
    n_fixed = sum(1 for p in patches.values() if p.get("status") == "fixed")
    lines = [f"# wave report — {target.name}",
             f"*generated {time.strftime('%Y-%m-%d %H:%M')}" + (f" · model `{model}`" if model else "") + "*",
             "",
             "> **This is the one file to read.** It lists what the model found, the proof or reasoning behind"
             " each, and any fix it produced. The other `wave_*` files (repo map, per-file notes, raw"
             " candidates) are the working detail — they're listed at the bottom.",
             "",
             "## Summary",
             f"- **{n.get('confirmed', 0)} confirmed** (proven exploitable)",
             f"- **{n.get('anomalous_state', 0)} need review** (observed effect, human judgment)",
             f"- {n.get('believed', 0)} unproven leads · {n.get('blocked', 0)} blocked · "
             f"{n.get('refuted', 0)} cleared as safe",
             f"- {n_fixed} fixed (Stage 4 patch, exploit demonstrably no longer fires)",
             ""]
    # one plain-language line on what the run amounts to, so the top of the file always says what happened
    if n.get("confirmed"):
        lines.append(f"**Bottom line:** {n['confirmed']} confirmed vulnerabilit"
                     f"{'y' if n['confirmed'] == 1 else 'ies'}"
                     + (f", {n_fixed} with a verified fix" if n_fixed else "") + " — see below.")
    elif n.get("anomalous_state"):
        lines.append(f"**Bottom line:** nothing auto-confirmed, but {n['anomalous_state']} finding(s) need a "
                     "human call (an effect was observed but exploitability is a judgment).")
    elif n.get("blocked") and not (n.get("believed") or n.get("refuted")):
        lines.append("**Bottom line:** the run could not complete its checks — every candidate was **blocked** "
                     "(could not be run/provisioned). See the Blocked section for the exact reason each gave.")
    elif findings:
        lines.append("**Bottom line:** no vulnerability was proven; the leads below were either unwitnessed or "
                     "cleared as safe.")
    lines.append("")

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
        # explain WHERE the pipeline stopped so an empty report is still actionable, not a dead end
        cand = _load(src / "wave_candidates.jsonl")
        note = _load(src / "wave_notebook.jsonl")
        if cand:
            lines.append(f"_Detection found {len(cand)} candidate(s) but none reached a proof verdict — the "
                         "proof stage was interrupted, timed out, or the model produced no conclusion. Re-run "
                         "`wave prove <repo>` (it resumes), or see wave_candidates.jsonl for what was flagged._\n")
        elif note:
            lines.append(f"_The model took {len(note)} per-file note(s) but flagged nothing to prove. See "
                         "wave_notebook.md for what it read, or widen coverage (`wave eyes <repo> --notes`)._\n")
        else:
            lines.append("_Nothing was detected. The run likely stopped before reading the code (a config, "
                         "connectivity, or provisioning error) — check the run log / terminal output, and that "
                         "`wave config show` points at a reachable model._\n")

    # ---- where the rest of the detail lives, so this one file lets the user follow the whole trail ----
    catalog = [("wave_map.md", "full repo structure map (every file's functions/routes/sinks)"),
               ("wave_notebook.md", "the model's per-file security notes"),
               ("wave_candidates.jsonl", "detector survivors handed to the proof stage"),
               ("wave_findings.jsonl", "machine-readable findings (source for this report)"),
               ("casefile.json", "full proof transcripts (what the model ran + observed)")]
    present = [(nm, desc) for nm, desc in catalog if (src / nm).exists()]
    if present:
        lines.append("## Where the detail lives")
        for nm, desc in present:
            lines.append(f"- `{nm}` — {desc}")
        lines.append("")

    # PRIMARY, easy-to-find report at the repo root (uppercase sorts to the top among the wave_* files)
    report = src / "WAVE_REPORT.md"
    report.write_text("\n".join(lines), encoding="utf-8")
    # a self-contained bundle under wave_results/ (the report + copies of the machine artifacts)
    dest = src / "wave_results"
    dest.mkdir(parents=True, exist_ok=True)
    try:
        (dest / "wave_report.md").write_text("\n".join(lines), encoding="utf-8")
    except OSError:
        pass
    for name in ("wave_findings.jsonl", "wave_patches.jsonl", "casefile.json"):
        s = src / name
        if s.exists():
            try:
                (dest / name).write_text(s.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
            except OSError:
                pass
    return report
