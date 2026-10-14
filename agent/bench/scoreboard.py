"""Scoreboard -- the stage FUNNEL for a wave run, scored against MANIFEST ground truth (plan §2).

Keep a change only if the scoreboard improves; otherwise revert it. This reads a target's `wave_*.jsonl`
outputs (produced by `wave all <target>`) plus the deterministic sink pins, and reports, per CWE class,
how far each real bug got:

    Real bugs (ground truth) -> Pinned -> In notebook -> Survived detect -> Reached prove -> Confirmed
    + Confirmed on SAFE TWINS (must be 0 -- any confirm there is a false positive)

Deterministic, no model -- it only READS the run's artifacts, so it is cheap and unit-testable. Matching is
by CWE (the MANIFEST ground truth is CWE-level), via the finding's `cwe` or, failing that, its coarse
`class` mapped through cwe_info. Usage:

    python -m agent.bench.scoreboard                 # score every bench target that has outputs
    python -m agent.bench.scoreboard pyvuln safeapp  # named targets
    python -m agent.bench.scoreboard --target <dir>  # an arbitrary scanned repo with a MANIFEST.json
"""
from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path

from agent.orchestrator import cwe_info

BENCH = Path(__file__).resolve().parent / "targets"

# the funnel rows, in order; each is a stage a real bug must survive
STAGES = ["pinned", "notebook", "survived", "reached_prove", "confirmed"]
_CONFIRMED_VERDICTS = {"confirmed"}


def _class_to_cwe(cls):
    return cwe_info._CLASS_CWE.get((cls or "").lower().strip())


def _cwe_of(rec):
    """A finding's CWE -- its explicit `cwe`, else its coarse `class` mapped to a representative CWE."""
    c = (rec.get("cwe") or "").upper().strip()
    if c.startswith("CWE-"):
        return c
    return _class_to_cwe(rec.get("class") or rec.get("cls") or "")


def _read_jsonl(path):
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def _flat_findings(records):
    """notebook.jsonl lines are {file, findings:[...]}; candidate/finding lines are flat. Normalize to a
    flat list of finding dicts (carry the file down from a notebook note)."""
    out = []
    for r in records:
        if isinstance(r, dict) and isinstance(r.get("findings"), list):
            for f in r["findings"]:
                if isinstance(f, dict):
                    out.append({**f, "file": f.get("file", r.get("file", ""))})
        elif isinstance(r, dict):
            out.append(r)
    return out


def _cwes(records):
    return {c for c in (_cwe_of(f) for f in _flat_findings(records)) if c}


def _pinned_cwes(target):
    """The CWE classes the DETERMINISTIC detector pins in the repo (the recall floor) -- built locally from
    the codemap, no model. Returns None if the codemap can't be built (so the row renders as '-')."""
    try:
        from agent.orchestrator import codemap, repomap
        cmap = codemap.build(str(target))
    except Exception:
        return None
    out = set()
    for _p, finfo in cmap.files.items():
        try:
            _routes, sinks, _dyn = repomap.scan_pins(finfo)
        except Exception:
            continue
        for (_ln, label, _code) in sinks:
            c = _class_to_cwe(label)
            if c:
                out.add(c)
    return out


def score_target(tdir, pins=True):
    """Return the funnel for one target dir containing MANIFEST.json + wave_*.jsonl."""
    tdir = Path(tdir)
    man = json.loads((tdir / "MANIFEST.json").read_text(encoding="utf-8"))
    is_safe = bool(man.get("safe"))
    truth = {str(v.get("cwe", "")).upper().strip() for v in man.get("vulns", []) if v.get("cwe")}

    notebook = _cwes(_read_jsonl(tdir / "wave_notebook.jsonl"))
    survived = _cwes(_read_jsonl(tdir / "wave_candidates.jsonl"))
    findings = _flat_findings(_read_jsonl(tdir / "wave_findings.jsonl"))
    reached = {c for c in (_cwe_of(f) for f in findings) if c}
    confirmed = {_cwe_of(f) for f in findings
                 if str(f.get("verdict", "")).lower() in _CONFIRMED_VERDICTS and _cwe_of(f)}
    pinned = _pinned_cwes(tdir) if pins else None

    stage_sets = {"pinned": pinned, "notebook": notebook, "survived": survived,
                  "reached_prove": reached, "confirmed": confirmed}
    # recall per stage = how many ground-truth CWEs reached it (None stage -> not measured)
    funnel = {s: (None if stage_sets[s] is None else len(truth & stage_sets[s])) for s in STAGES}
    # false positives: a CONFIRMED finding whose CWE is not a real bug (on a safe twin, ANY confirm is a FP)
    fp_confirmed = len([f for f in findings
                        if str(f.get("verdict", "")).lower() in _CONFIRMED_VERDICTS
                        and (is_safe or (_cwe_of(f) not in truth))])
    return {"name": man.get("name", tdir.name), "safe": is_safe, "real": len(truth),
            "truth": sorted(truth), "funnel": funnel, "fp_confirmed": fp_confirmed,
            "has_outputs": (tdir / "wave_findings.jsonl").exists() or (tdir / "wave_notebook.jsonl").exists()}


def funnel_table(results, model="", prompt_version=""):
    """Render the stage-funnel table across targets (vuln targets first, safe twins last)."""
    head = f"# wave scoreboard — {date.today().isoformat()}"
    if model:
        head += f" · model `{model}`"
    if prompt_version:
        head += f" · prompt `{prompt_version}`"
    cols = ["target", "real", "pinned", "notebook", "survived", "reached", "confirmed", "FP-confirmed"]
    lines = [head, "", "| " + " | ".join(cols) + " |", "|" + "|".join(["---"] * len(cols)) + "|"]

    def _cell(v):
        return "-" if v is None else str(v)

    vuln = [r for r in results if not r["safe"]]
    safe = [r for r in results if r["safe"]]
    for r in vuln + safe:
        f = r["funnel"]
        name = r["name"] + (" (safe)" if r["safe"] else "")
        if not r["has_outputs"]:
            lines.append(f"| {name} | {r['real']} | _no run outputs — run `wave all` first_ |||||||")
            continue
        lines.append("| " + " | ".join([
            name, str(r["real"]), _cell(f["pinned"]), _cell(f["notebook"]), _cell(f["survived"]),
            _cell(f["reached_prove"]), _cell(f["confirmed"]), str(r["fp_confirmed"])]) + " |")

    # aggregate recall / safe-twin FP
    scored = [r for r in vuln if r["has_outputs"]]
    real_total = sum(r["real"] for r in scored)
    conf_total = sum((r["funnel"]["confirmed"] or 0) for r in scored)
    safe_fp = sum(r["fp_confirmed"] for r in safe if r["has_outputs"])
    if real_total:
        lines += ["", f"**Recall (confirmed / real):** {conf_total}/{real_total} "
                      f"= {conf_total / real_total:.0%}",
                  f"**Safe-twin false confirms (must be 0):** {safe_fp}"]
    return "\n".join(lines) + "\n"


def flaky(findings_a, findings_b):
    """Findings whose CONFIRMED-ness flips between two runs (same (file,line,class) key). A flip = a weak,
    non-reproducible verdict. Returns the list of flipped keys."""
    def _conf_map(recs):
        m = {}
        for f in _flat_findings(recs):
            key = (f.get("file", ""), f.get("line", 0), str(f.get("class", "")).lower())
            m[key] = str(f.get("verdict", "")).lower() in _CONFIRMED_VERDICTS
        return m

    a, b = _conf_map(findings_a), _conf_map(findings_b)
    return sorted(k for k in (a.keys() & b.keys()) if a[k] != b[k])


def main(argv=None):
    ap = argparse.ArgumentParser(description="wave scoreboard: stage funnel vs MANIFEST ground truth")
    ap.add_argument("targets", nargs="*", help="bench target name(s); default = all bench targets")
    ap.add_argument("--target", help="an arbitrary scanned repo dir (must contain MANIFEST.json)")
    ap.add_argument("--no-pins", action="store_true", help="skip the deterministic 'pinned' column (faster)")
    ap.add_argument("--model", default="", help="record the model id in the header")
    ap.add_argument("--out", help="write the table here (default: stdout)")
    args = ap.parse_args(argv)

    dirs = []
    if args.target:
        dirs.append(Path(args.target))
    elif args.targets:
        dirs += [BENCH / t for t in args.targets]
    else:
        dirs += [p for p in sorted(BENCH.iterdir()) if (p / "MANIFEST.json").exists()]

    results = []
    for d in dirs:
        if not (d / "MANIFEST.json").exists():
            print(f"skip {d}: no MANIFEST.json")
            continue
        results.append(score_target(d, pins=not args.no_pins))
    table = funnel_table(results, model=args.model)
    if args.out:
        Path(args.out).write_text(table, encoding="utf-8")
        print(f"scoreboard -> {args.out}")
    else:
        print(table)


if __name__ == "__main__":
    main()
