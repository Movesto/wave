"""Orchestrator entry point.

  python -m orchestrator.run discover <target> [--json] [--diff <git-ref>]

More stages (provision, auth, exploit, oracle, remediate) land as the loop is built out.
"""
import argparse
import json
from dataclasses import asdict

from . import discover as disc
from . import state as st


def cmd_loop(args):
    res = st.run_loop(args.target, host_port=args.port, strikes=args.strikes, fix=args.fix,
                      model_discover=args.model_discover)
    s = res["summary"]
    print(f"\n=== LOOP on {args.target} ===")
    print(f"  candidates={s['candidates']} provable={s['provable']} "
          f"PROVEN={s['proven']} fixed={s.get('fixed', 0)} deferred={s['deferred']}\n")
    for f in res["findings"]:
        tag = "FIXED" if f.status == "fixed" else "PROVEN"
        print(f"  [{tag} {f.candidate.cwe}] {f.candidate.loc()}")
        print(f"      payload: {f.payload}   ({f.notes})")
        print(f"      sink: {f.evidence}")
        if args.fix:
            print(f"      Gate A (exploit blocked at sink): {f.gate_a or '-'}")
            print(f"      Gate B (functional smoke):        {f.gate_b or '-'}")
            if f.patch:
                print("      --- model patch (preview) ---")
                for pl in f.patch.splitlines()[:8]:
                    print(f"      | {pl}")
    for c, why in res["deferred"]:
        print(f"  [DEFER  {c.cwe}] {c.loc()} -- {why}")


def cmd_discover(args):
    cands = disc.discover(args.target, diff_ref=args.diff)
    if args.json:
        print(json.dumps([asdict(c) for c in cands], indent=2))
        return
    s = disc.summarize(cands)
    print(f"SAST discovery on {args.target}")
    print(f"  {s['total']} candidates | {s['provable']} provable | {s['routed']} routed | "
          f"{s['resolved']} xflow-resolved")
    print(f"  by-cwe={s['by_cwe']}  by-detector={s['by_detector']}\n")
    for c in cands:
        star = "*" if c.provable else " "
        route = f"  <{c.route_hint}>" if c.route_hint else ""
        res = f"  [resolved: {c.resolved_from}]" if c.resolved_from else ""
        print(f" {star} [{c.cwe:<8} {c.detector:<7}] {c.loc()}{route}{res}")
        print(f"      {c.sink}")


def main():
    ap = argparse.ArgumentParser(prog="orchestrator")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("discover", help="SAST front-end: static candidate discovery")
    d.add_argument("target")
    d.add_argument("--json", action="store_true")
    d.add_argument("--diff", metavar="GIT_REF", default=None,
                   help="only scan files changed vs this git ref (incremental SAST)")
    d.set_defaults(func=cmd_discover)

    lp = sub.add_parser("loop", help="detect + prove: discover -> provision -> exploit -> oracle")
    lp.add_argument("target")
    lp.add_argument("--port", type=int, default=None, help="host port for the booted app")
    lp.add_argument("--strikes", type=int, default=1, help="re-fire N times for determinism")
    lp.add_argument("--fix", action="store_true", help="generate a patch + dual-gate (loads the 14B)")
    lp.add_argument("--model-discover", action="store_true",
                    help="use the fast review model for discovery (default: deterministic patterns)")
    lp.set_defaults(func=cmd_loop)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
