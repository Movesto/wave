"""Benchmark harness -- run the loop on a controlled target and score findings vs MANIFEST ground
truth. Controlled targets boot cleanly and expose one discoverable vuln per class, so every oracle
gets full-loop end-to-end coverage + a measured recall/precision number.

  python -m agent.bench.bench            # default target: pyvuln
  python -m agent.bench.bench pyvuln --fix
"""
import argparse
import json
import time
from pathlib import Path

from agent.orchestrator import state

BENCH = Path(__file__).resolve().parent / "targets"


def run_target(tdir, fix=False):
    man = json.loads((tdir / "MANIFEST.json").read_text(encoding="utf-8"))
    truth = {v["cwe"] for v in man["vulns"]}
    t0 = time.time()
    res = state.run_loop(str(tdir), fix=fix, dynamic=True)   # the bench measures the FULL capability (boot + all oracles)
    dt = time.time() - t0
    findings = res["findings"]
    found = {f.candidate.cwe for f in findings}
    case = res.get("case")
    if case is not None:                                   # the Case File IS the investigation report (plan §7)
        case.save(tdir / "casefile.json")
        print("\n" + case.report())
    print(f"\n{'=' * 68}\nTARGET {man['name']}  ({man['stack']})   [{dt:.0f}s]")

    if man.get("safe") or not truth:                       # SECURE control -> any finding is a FALSE POSITIVE
        fp = len(findings)
        prec = 1.0 if fp == 0 else 0.0
        print(f"  SAFE control: expected 0 vulns, found {fp} -> {'PASS (0 FP)' if fp == 0 else 'FAIL'}  precision={prec:.0%}")
        for f in findings:
            print(f"    [FALSE POSITIVE] {f.candidate.cwe} {f.candidate.loc()} -- {f.notes}")
        print(f"  summary: {res['summary']}")
        return {"name": man["name"], "safe": True, "false_positives": fp, "precision": prec, "secs": dt}

    hit, extra, missed = truth & found, found - truth, truth - found
    recall = len(hit) / len(truth) if truth else 0.0
    prec = len(hit) / len(found) if found else 1.0
    notes_by = {}
    for f in findings:
        notes_by.setdefault(f.candidate.cwe, f.notes)
    print(f"  truth={len(truth)}  proven-classes={len(found)}  recall={recall:.0%}  precision={prec:.0%}")
    for v in man["vulns"]:
        proven = v["cwe"] in found
        mark = "PROVEN" if proven else " MISS "
        tag = f"   [{notes_by.get(v['cwe'], '')}]" if proven else ""
        print(f"    [{mark}] {v['cwe']:9} {v['route']:16} {v['desc']}{tag}")
    if extra:
        print(f"  extra classes proven (not in manifest): {sorted(extra)}")
    print(f"  summary: {res['summary']}")
    return {"name": man["name"], "recall": recall, "precision": prec,
            "hit": sorted(hit), "missed": sorted(missed), "extra": sorted(extra), "secs": dt}


def _score_line(r):
    if r.get("safe"):
        return f"SCORE {r['name']}: {r['false_positives']} false positives, precision {r['precision']:.0%}, {r['secs']:.0f}s"
    line = f"SCORE {r['name']}: recall {r['recall']:.0%}, precision {r['precision']:.0%}, {r['secs']:.0f}s"
    return line + (f"  missed: {r['missed']}" if r["missed"] else "")


def _all_targets():
    """Every target dir with a MANIFEST, controls (safe / no vulns) last so the scorecard reads vuln-first."""
    def is_control(d):
        m = json.loads((d / "MANIFEST.json").read_text(encoding="utf-8"))
        return m.get("safe", False) or not m.get("vulns")
    return sorted((d for d in BENCH.iterdir() if (d / "MANIFEST.json").is_file()),
                  key=lambda d: (is_control(d), d.name))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default="pyvuln", help="a target name, or 'all' for the full sweep")
    ap.add_argument("--fix", action="store_true")
    a = ap.parse_args()

    if a.target in ("all", "sweep"):                    # one scorecard -- each target in its OWN process
        _sweep(fix=a.fix)
        return

    print("\n" + _score_line(run_target(BENCH / a.target, fix=a.fix)))


def _sweep(fix=False, per_target_timeout=600):
    """Run every target in a FRESH subprocess. Isolation is deliberate: doing 6 model load/unload
    cycles in one process wedges this GPU (cudaErrorIllegalAddress); a fresh CUDA context per target
    plus a per-target timeout means one hang can't take down the sweep."""
    import re
    import subprocess
    import sys

    rows = []
    for t in _all_targets():
        print(f"\n{'#' * 68}\n# {t.name}\n{'#' * 68}", flush=True)
        try:
            p = subprocess.run([sys.executable, "-u", "-m", "agent.bench.bench", t.name] + (["--fix"] if fix else []),
                               capture_output=True, text=True, timeout=per_target_timeout,
                               cwd=str(Path(__file__).resolve().parents[2]))
            out = p.stdout + p.stderr
            score = next((ln for ln in out.splitlines() if ln.startswith("SCORE ")), None)
        except subprocess.TimeoutExpired:
            score = None
        if score:
            print(score, flush=True)
            rec = re.search(r"recall (\d+)%", score)
            prec = re.search(r"precision (\d+)%", score)
            fp = re.search(r"(\d+) false positive", score)
            rows.append({"name": t.name, "recall": int(rec.group(1)) if rec else None,
                         "precision": int(prec.group(1)) if prec else None,
                         "fp": int(fp.group(1)) if fp else None})
        else:
            print(f"  {t.name}: NO SCORE (timeout/wedge after {per_target_timeout}s)", flush=True)
            rows.append({"name": t.name, "recall": None, "precision": None, "fp": None, "wedged": True})
        subprocess.run(["docker", "ps", "-aq", "--filter", "name=wave"], capture_output=True, text=True)  # best-effort

    print(f"\n{'=' * 68}\nSWEEP SCORECARD")
    for r in rows:
        if r.get("wedged"):
            print(f"  {r['name']:12} WEDGED / no score")
        elif r["fp"] is not None:
            print(f"  {r['name']:12} control: {r['fp']} false positive(s), precision {r['precision']}%")
        else:
            print(f"  {r['name']:12} recall {r['recall']}%  precision {r['precision']}%")
    recs = [r["recall"] for r in rows if r["recall"] is not None]
    precs = [r["precision"] for r in rows if r["precision"] is not None and r["fp"] is None]
    fps = sum(r["fp"] for r in rows if r["fp"] is not None)
    wedged = [r["name"] for r in rows if r.get("wedged")]
    print(f"  {'-' * 64}")
    print(f"  vuln targets: mean recall {sum(recs) / len(recs):.0f}%, mean precision "
          f"{sum(precs) / len(precs):.0f}%  |  controls: {fps} FP" + (f"  |  WEDGED: {wedged}" if wedged else ""))


if __name__ == "__main__":
    main()
