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
    res = state.run_loop(str(tdir), fix=fix)
    dt = time.time() - t0
    findings = res["findings"]
    found = {f.candidate.cwe for f in findings}
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default="pyvuln")
    ap.add_argument("--fix", action="store_true")
    a = ap.parse_args()
    r = run_target(BENCH / a.target, fix=a.fix)
    if r.get("safe"):
        print(f"\nSCORE {r['name']}: {r['false_positives']} false positives, precision {r['precision']:.0%}, {r['secs']:.0f}s")
    else:
        print(f"\nSCORE {r['name']}: recall {r['recall']:.0%}, precision {r['precision']:.0%}, {r['secs']:.0f}s")
        if r["missed"]:
            print(f"  missed: {r['missed']}")


if __name__ == "__main__":
    main()
