"""Orchestrator entry point.

  python -m orchestrator.run discover <target> [--json] [--diff <git-ref>]

More stages (provision, auth, exploit, oracle, remediate) land as the loop is built out.
"""
import argparse
import json
import sys
from dataclasses import asdict

# The model can emit non-cp1252 Unicode (e.g. a non-breaking hyphen U+2011); a bare print() of it to a
# Windows cp1252 console raises UnicodeEncodeError and kills the whole run. Force UTF-8 (replace on any
# stray char) so a model's output can never crash the loop.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from . import discover as disc
from . import state as st


def cmd_loop(args):
    res = st.run_loop(args.target, host_port=args.port, strikes=args.strikes, fix=args.fix,
                      model_discover=args.model_discover, use_reader=args.reader or args.reader_all,
                      audit_deps=not args.no_deps, budget=args.budget, dynamic=args.dynamic,
                      online=args.online, reader_budget=args.reader_budget, reader_all=args.reader_all,
                      investigate=args.investigate, investigate_budget=args.investigate_budget)
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
    case = res.get("case")                                  # the full investigation report (Case File)
    if case is not None:
        import os
        out = os.path.join(str(args.target), "casefile.json")
        try:
            case.save(out)
            print(f"\n[case file saved -> {out}]")
        except OSError:
            pass
        print("\n" + case.report())


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


def cmd_eyes(args):
    from . import repomap
    from . import eyes as eyesmod
    res = repomap.build_map(args.target, out=args.out)
    s = res["stats"]
    print(f"repo map -> {res['map_path']}")
    print(f"  code files={s['files']} pinned={s['pinned_files']} functions={s['functions']} "
          f"classes={s['classes']} routes={s['routes']} sink-pins={s['sink_pins']}")
    print(f"  infra/config files={s['infra_files']} infra-pins={s['infra_pins']} "
          f"map={s['map_chars']} chars  ledger-digest={s['digest_chars']} chars")
    if not args.ledger:
        print("  (view the map above; add --ledger to run the model over it)")
        return
    local = None
    if not args.no_local:
        from .model import Model
        local = Model()
    led = eyesmod.build_ledger(res["digest"], local_model=local, use_glm=not args.no_glm)
    if args.json:
        print(json.dumps({k: v for k, v in led.items() if v}, indent=2))
        return
    print(f"\nATTACK-SURFACE LEDGER (via {led['via']}{', TRUNCATED map' if led['truncated'] else ''})")
    print(f"  entry points ({len(led['entry_points'])}):")
    for e in led["entry_points"]:
        print(f"    - {e.get('name','?')}  [auth:{e.get('auth','?')}]  {e.get('file','')}  <- {e.get('input','')}")
    print(f"  high-risk ops ({len(led['high_risk_ops'])}):")
    for o in led["high_risk_ops"]:
        print(f"    - {o.get('op','?')}  {o.get('file','')}  ({o.get('why','')})")
    print(f"  ranked targets ({len(led['ranked_targets'])}):")
    for t in led["ranked_targets"]:
        print(f"    - {t.get('file','?')}  first={t.get('classes_first',[])}  ({t.get('reason','')})")
    if led.get("notes"):
        print("\n  (model returned prose, not JSON -- unstructured analysis follows)\n")
        print("  " + led["notes"].replace("\n", "\n  "))


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
    lp.add_argument("--reader", action="store_true",
                    help="Phase 4: the model READS prioritized files and forms its own hypotheses")
    lp.add_argument("--reader-budget", type=int, default=6, metavar="N",
                    help="how many files the Reader reads (default 6, lead-following); >12 switches to "
                         "a LINEAR whole-repo pass over the top-N security-surface files (slow on this GPU)")
    lp.add_argument("--reader-all", action="store_true",
                    help="the model reads EVERY source file in the repo (not just the security-surface "
                         "ones) -- a true full-repo scan; slowest, one model read per file")
    lp.add_argument("--investigate", action="store_true",
                    help="the model RUNS code in a sandbox to prove/refute micro-exec unknowns (any "
                         "language) -- the general tool-use prover; confirms only with an observed effect")
    lp.add_argument("--investigate-budget", type=int, default=3, metavar="N",
                    help="max unsettled candidates the investigator works per run (default 3; each is "
                         "several model turns + sandbox runs)")
    lp.add_argument("--online", action="store_true",
                    help="allow the Reader to WEB-SEARCH when a hypothesis is low-confidence "
                         "(sends queries off-box; off by default -- the system is otherwise local)")
    lp.add_argument("--no-deps", action="store_true",
                    help="skip the dependency-vulnerability audit (Phase 6 reporter)")
    lp.add_argument("--budget", type=int, default=80,
                    help="Editor budget: max candidates to work this run (default 80)")
    lp.add_argument("--dynamic", action="store_true",
                    help="boot the WHOLE app for Rung-2 + business-logic/IDOR differentials "
                         "(default: run-by-piece micro-exec only, no whole-app boot)")
    lp.set_defaults(func=cmd_loop)

    e = sub.add_parser("eyes", help="Stage 1: build the detailed whole-repo MAP; optionally the model ledger")
    e.add_argument("target")
    e.add_argument("--out", default=None, help="where to write the map (default <target>/wave_map.md)")
    e.add_argument("--ledger", action="store_true",
                   help="also run the model over the map -> Attack-Surface Ledger (loads a model)")
    e.add_argument("--json", action="store_true", help="print the ledger as JSON")
    e.add_argument("--no-glm", action="store_true", help="skip GLM comprehension; local model only")
    e.add_argument("--no-local", action="store_true",
                   help="don't load the local model (GLM only; ledger empty if GLM is down)")
    e.set_defaults(func=cmd_eyes)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
