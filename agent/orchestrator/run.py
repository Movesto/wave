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


def _steer(picks, pinned, target):
    """Live steering of the model's proposed deep-read list: Enter=go, drop N,M, add <substr>, list, quit."""
    import re as _re

    from .repomap import _rel
    while True:
        try:
            cmd = input("\n> [Enter]=go / drop 3,5 / add <substr> / list / quit: ").strip()
        except EOFError:
            return picks
        if not cmd:
            return picks
        if cmd == "quit":
            raise SystemExit("notebook aborted by user")
        if cmd == "list":
            pass
        elif cmd.startswith("drop"):
            idxs = {int(x) for x in _re.findall(r"\d+", cmd)}
            picks = [pk for n, pk in enumerate(picks, 1) if n not in idxs]
        elif cmd.startswith("add "):
            sub = cmd[4:].strip()
            have = {pk["path"] for pk in picks}
            for p in pinned:
                rel = _rel(target, p)
                if sub in rel and p not in have:
                    picks.append({"file": rel, "path": p, "reason": "(added by user)"})
        else:
            print("  (unrecognized — Enter to go, or: drop N,M | add <substr> | list | quit)")
            continue
        for n, pk in enumerate(picks, 1):
            print(f"  {n:>2} {pk['file']}  — {pk['reason'][:80]}")
    return picks


def cmd_eyes(args):
    from . import repomap, notebook
    res = repomap.build_map(args.target, out=args.out)
    s = res["stats"]
    print(f"repo map -> {res['map_path']}")
    print(f"  code files={s['files']} pinned={s['pinned_files']} functions={s['functions']} "
          f"classes={s['classes']} routes={s['routes']} sink-pins={s['sink_pins']}")
    print(f"  infra/config files={s['infra_files']} infra-pins={s['infra_pins']} map={s['map_chars']} chars")

    # Deterministic ledger index -- derived straight from the map, no model, cannot hallucinate.
    idx = notebook.ledger_index(res["cmap"], args.target, res["per_file"], res["pinned"])
    print(f"\nATTACK-SURFACE INDEX (deterministic)")
    print(f"  entry points ({len(idx['entry_points'])}):")
    for e in idx["entry_points"][:40]:
        print(f"    - [auth:{e['auth']}]  {e['file']}:{e['line']}  {e['route'][:90]}")
    if len(idx["entry_points"]) > 40:
        print(f"    ... +{len(idx['entry_points']) - 40} more")
    print(f"  ranked targets ({len(idx['ranked_targets'])}):")
    for t in idx["ranked_targets"][:40]:
        print(f"    - {t['file']}  routes={t['routes']} sinks={t['sinks']}  classes={t['classes_first']}")
    if len(idx["ranked_targets"]) > 40:
        print(f"    ... +{len(idx['ranked_targets']) - 40} more")

    if not args.notes:
        print("\n  (add --notes to have the model read each pinned file into the persistent notebook)")
        return

    from .model import Model
    model = Model()
    out_dir = str(__import__("pathlib").Path(args.out).parent) if args.out else None
    pinned, per_file, budget = res["pinned"], res["per_file"], args.notes_budget

    targets = None                                         # None -> read all pinned (density order)
    if len(pinned) > budget:                               # large repo: let the model pick what to deep-read
        print(f"\nSELECTION: {len(pinned)} pinned files > budget {budget} — model picks the "
              f"{budget} worth deep-reading ...")
        picks = notebook.select_targets(model, args.target, per_file, pinned, budget, index=idx)
        print(f"\nProposed ({len(picks)} of {len(pinned)} pinned):")
        for n, pk in enumerate(picks, 1):
            print(f"  {n:>2} {pk['file']}  — {pk['reason'][:80]}")
        if args.interactive:
            picks = _steer(picks, pinned, args.target)
        targets = [pk["path"] for pk in picks]

    n_read = len(targets) if targets is not None else min(len(pinned), budget)
    print(f"\nNOTEBOOK: reading {n_read} files (persisted + resumable)")
    notes, paths = notebook.read_notes(model, args.target, per_file, pinned, budget=budget,
                                       out_dir=out_dir, targets=targets)
    total = sum(len(n["findings"]) for n in notes)
    print(f"\nnotebook -> {paths['md']}  ({len(notes)} files noted, {total} findings)")


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

    e = sub.add_parser("eyes", help="Stage 1: whole-repo MAP + deterministic index; optionally the notebook")
    e.add_argument("target")
    e.add_argument("--out", default=None, help="where to write the map (default <target>/wave_map.md)")
    e.add_argument("--notes", action="store_true",
                   help="the local model reads each pinned file into a persistent notebook "
                        "(wave_notebook.jsonl/.md) -- resumable; loads the model")
    e.add_argument("--notes-budget", type=int, default=20, metavar="N",
                   help="how many files the notebook reads (default 20); when pinned files exceed this, "
                        "the model SELECTS the N worth deep-reading instead of taking the densest N")
    e.add_argument("--interactive", action="store_true",
                   help="when the model selects targets on a large repo, pause to let you steer the list "
                        "(drop/add) before deep-reading; without it, auto-proceeds")
    e.set_defaults(func=cmd_eyes)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
