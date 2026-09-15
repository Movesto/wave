"""Orchestrator entry point.

  python -m orchestrator.run discover <target> [--json] [--diff <git-ref>]

More stages (provision, auth, exploit, oracle, remediate) land as the loop is built out.
"""
import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

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


def cmd_detect(args):
    from pathlib import Path

    from . import detector
    from .model import Model
    out_dir = str(Path(args.notebook).parent) if args.notebook else args.target
    model = Model()
    survivors, refuted, paths = detector.run(model, args.target, notebook_path=args.notebook,
                                             budget=args.budget, out_dir=out_dir)
    print(f"\nDETECTOR (clean-room falsification): {len(survivors)} survived, {len(refuted)} refuted")
    print(f"\nSURVIVORS -> {paths['candidates']}  (Stage 3 worklist, most-severe first):")
    for r in survivors:
        print(f"  * [{r['class']}/{r['confidence']}] {r['file']}:{r['line']}  {r['sink'][:70]}")
    if refuted:
        print(f"\nREFUTED ({len(refuted)}) -- scan for a wrong clear (a false refute = a missed bug):")
        for r in refuted:
            print(f"  - [{r['class']}] {r['file']}:{r['line']}  — {r['reason'][:80]}")


def cmd_prove(args):
    from pathlib import Path

    from . import prove
    from .model import Model
    out_dir = str(Path(args.candidates).parent) if args.candidates else args.target
    model = Model()
    by, paths = prove.run(model, args.target, candidates_path=args.candidates, budget=args.budget,
                          out_dir=out_dir, gate=not args.no_reach_gate, online=args.online)
    conf, anom, refu = by["confirmed"], by["anomalous_state"], by["refuted"]
    blk, bel = by["blocked"], by["believed"]
    print(f"\nPROOF LOOP: {len(conf)} confirmed, {len(anom)} anomalous-state, {len(refu)} refuted, "
          f"{len(blk)} blocked, {len(bel)} believed")
    print(f"findings -> {paths['findings']}   casefile -> {paths['casefile']}")
    for d in conf:
        print(f"  [CONFIRMED {d.get('cwe')}] {d['file']}:{d['line']}  {d.get('unit', '')}  "
              f"-- {(d.get('evidence') or d.get('why', ''))[:80]}")
    for d in anom:
        print(f"  [ANOMALOUS {d.get('cwe')}] {d['file']}:{d['line']}  -- {d.get('why', '')[:80]}")
    for d in blk:
        print(f"  [BLOCKED   {d.get('cwe')}] {d['file']}:{d['line']}  -- {d.get('why', '')[:80]}")


def cmd_patch(args):
    from pathlib import Path

    from . import patch as patchmod
    from .model import Model
    out_dir = str(Path(args.findings).parent) if args.findings else args.target
    model = Model()
    results, paths = patchmod.run(model, args.target, findings_path=args.findings, budget=args.budget,
                                  out_dir=out_dir, write=args.write)
    fixed = [r for r in results if r["status"] == "fixed"]
    unver = [r for r in results if r["status"] == "patch-unverified"]
    rej = [r for r in results if r["status"] not in ("fixed", "patch-unverified")]
    print(f"\nPATCH + REVERIFY: {len(fixed)} fixed (exploit demonstrably no longer fires), "
          f"{len(unver)} unverified (couldn't re-witness -- NOT fixed), {len(rej)} rejected/failed  "
          f"({'WROTE verified patches' if args.write else 'dry-run -- sources restored'})")
    print(f"patches -> {paths['patches']}")
    for r in results:
        tag = "FIXED" if r["status"] == "fixed" else r["status"].upper()
        print(f"  [{tag} {r.get('cwe')}] {r['file']}:{r['line']}  {r.get('unit', '')}")
        if r.get("gate_a"):
            print(f"      Gate A (exploit re-fired): {r['gate_a']}  -- {r.get('gate_a_note', '')[:80]}")
            print(f"      Gate B (still loads):      {r['gate_b']}  -- {r.get('gate_b_note', '')[:60]}")


def _banner(n, title, detail=""):
    import time as _t
    _banner.t0 = getattr(_banner, "t0", _t.time())
    el = int(_t.time() - _banner.t0)
    bar = "=" * 66
    print(f"\n{bar}\n== STAGE {n}/4 -- {title}   [+{el // 60}m{el % 60:02d}s]", flush=True)
    if detail:
        print(f"   {detail}", flush=True)
    print(bar, flush=True)


def cmd_all(args):
    """One-shot pipeline: eyes(notebook) -> detect -> prove -> (optional) patch, sharing ONE model."""
    from . import detector, notebook, prove, repomap
    from .model import Model
    t = args.target
    model = Model()

    # Stage 1 -- whole-repo map + per-file notebook (model selects targets on big repos)
    _banner(1, "EYES: map the repo + notebook", "building the code map (tree-sitter over every file) ...")
    res = repomap.build_map(t)
    s = res["stats"]
    print(f"[all] map done: {s['files']} files, {s['pinned_files']} pinned, {s['sink_pins']} sink-pins", flush=True)
    idx = notebook.ledger_index(res["cmap"], t, res["per_file"], res["pinned"])
    pinned, per_file = res["pinned"], res["per_file"]
    targets = None
    if len(pinned) > args.notes_budget:
        print(f"[all] {len(pinned)} pinned > budget {args.notes_budget} -- MODEL is selecting which files to "
              f"deep-read (one model call) ...", flush=True)
        picks = notebook.select_targets(model, t, per_file, pinned, args.notes_budget, index=idx)
        if args.interactive:
            picks = _steer(picks, pinned, t)
        targets = [pk["path"] for pk in picks]
        print(f"[all] selected {len(targets)} of {len(pinned)} pinned files to deep-read", flush=True)
    print(f"[all] notebook: the model now READS each selected file into notes (one model call each -- "
          f"watch [notebook] i/N below) ...", flush=True)
    notes, npaths = notebook.read_notes(model, t, per_file, pinned, budget=args.notes_budget, targets=targets)
    total = sum(len(n["findings"]) for n in notes)
    print(f"[all] notebook DONE: {len(notes)} files noted, {total} findings -> {npaths['md']}", flush=True)

    # Stage 2 -- clean-room falsification -> survivors
    _banner(2, "DETECTOR: clean-room falsify each finding",
            f"one fresh model call per finding (up to {args.detect_budget}) -- watch [detect] i/N below ...")
    survivors, refuted, dpaths = detector.run(model, t, budget=args.detect_budget)
    print(f"[all] detect DONE: {len(survivors)} survived, {len(refuted)} refuted -> {dpaths['candidates']}",
          flush=True)
    if not survivors:
        print("[all] no survivors -- pipeline done.")
        return

    # Stage 3 -- confirmation ladder (+ reachability gate)
    _banner(3, "PROOF LOOP: prove the survivors",
            f"canary + model investigation per survivor (up to {args.prove_budget}) -- watch [prove]/"
            f"[investigate] below; first XSS builds the browser image once ...")
    by, _pp = prove.run(model, t, budget=args.prove_budget, gate=not args.no_reach_gate, online=args.online)
    print(f"[all] prove DONE: {len(by['confirmed'])} confirmed, {len(by['anomalous_state'])} anomalous-state, "
          f"{len(by['refuted'])} refuted, {len(by['blocked'])} blocked, {len(by['believed'])} believed", flush=True)

    # Stage 4 -- patch + reverify (optional)
    fixed = []
    if args.patch and by["confirmed"]:
        _banner(4, "PATCH + REVERIFY",
                f"the model writes a fix for each confirmed finding, then the SAME proof re-runs "
                f"({'writing' if args.write else 'dry-run, source restored'}) ...")
        from . import patch as patchmod
        pres, _xp = patchmod.run(model, t, budget=args.patch_budget, write=args.write)
        fixed = [r for r in pres if r["status"] == "fixed"]
        print(f"[all] patch: {len(fixed)} fixed of {len(pres)} confirmed "
              f"({'wrote' if args.write else 'dry-run'})", flush=True)

    from . import report as _report                        # the readable, human-facing findings report
    rp = _report.generate(t, model=getattr(model, "model_id", ""))

    print(f"\n=== PIPELINE on {t} ===")
    print(f"  findings={total}  survivors={len(survivors)}  CONFIRMED={len(by['confirmed'])}  "
          f"anomalous={len(by['anomalous_state'])}  fixed={len(fixed)}")
    for d in by["confirmed"]:
        print(f"  [CONFIRMED {d.get('cwe')}] {d['file']}:{d['line']}  {d.get('unit', '')}  "
              f"-- {(d.get('evidence') or '')[:70]}")
    for d in by["anomalous_state"]:
        print(f"  [ANOMALOUS {d.get('cwe')}] {d['file']}:{d['line']}  -- {d.get('why', '')[:70]}")
    print(f"\n\U0001f4c4 readable report -> {rp}")


def cmd_report(args):
    """(Re)generate the human-readable report from an already-run repo's artifacts."""
    from . import report as _report
    rp = _report.generate(args.target, model=os.environ.get("WAVE_MODEL", ""))
    print(f"report -> {rp}")


# ---- CLI config: set the model/endpoint ONCE (~/.wave/config), so `wave` runs need no env each time -------
def _config_path():
    return Path(os.path.expanduser("~")) / ".wave" / "config"


def _load_config():
    """Load ~/.wave/config then ./.env into the environment (without overriding vars already set), so the
    CLI behaves like a configured tool -- set the model once, then just `wave all <repo>`."""
    for path in (_config_path(), Path(".env")):
        try:
            if not path.is_file():
                continue
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
        except OSError:
            pass


def cmd_config(args):
    """`wave config set <key> <value>` / `wave config show`. Keys: model, base, key (aliases for
    WAVE_MODEL / WAVE_API_BASE / WAVE_API_KEY) or any WAVE_* name."""
    alias = {"model": "WAVE_MODEL", "base": "WAVE_API_BASE", "url": "WAVE_API_BASE",
             "key": "WAVE_API_KEY", "trace": "WAVE_TRACE"}
    cfg = _config_path()
    cfg.parent.mkdir(parents=True, exist_ok=True)
    existing = {}
    if cfg.is_file():
        for line in cfg.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.split("=", 1)
                existing[k.strip()] = v.strip()
    if args.action == "show":
        if not existing:
            print(f"(no config at {cfg})")
        for k, v in existing.items():
            print(f"{k}={'***' if 'KEY' in k else v}")
        return
    key = alias.get((args.key or "").lower(), (args.key or "").upper())
    if not key.startswith("WAVE_"):
        raise SystemExit(f"unknown config key {args.key!r} (use: model | base | key | trace | a WAVE_* name)")
    existing[key] = args.value or ""
    cfg.write_text("\n".join(f"{k}={v}" for k, v in existing.items()) + "\n", encoding="utf-8")
    print(f"set {key} -> {cfg}")


def main():
    _load_config()                                          # set env once via `wave config`; then just run
    ap = argparse.ArgumentParser(prog="wave",
                                 description="wave — a local, autonomous vulnerability-discovery & repair agent")
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
    e.add_argument("--notes-budget", type=int, default=40, metavar="N",
                   help="how many files the notebook reads (default 40); at or below this, ALL pinned files "
                        "are read (full coverage); only when pinned EXCEEDS this does the model SELECT the N "
                        "worth deep-reading")
    e.add_argument("--interactive", action="store_true",
                   help="when the model selects targets on a large repo, pause to let you steer the list "
                        "(drop/add) before deep-reading; without it, auto-proceeds")
    e.set_defaults(func=cmd_eyes)

    dt = sub.add_parser("detect", help="Stage 2: clean-room falsify the notebook's findings -> candidates")
    dt.add_argument("target")
    dt.add_argument("--notebook", default=None,
                    help="path to wave_notebook.jsonl (default <target>/wave_notebook.jsonl)")
    dt.add_argument("--budget", type=int, default=40, metavar="N",
                    help="max findings to falsify this run (severity+confidence order; resumable)")
    dt.set_defaults(func=cmd_detect)

    pr = sub.add_parser("prove", help="Stage 3: run the detector's survivors through the confirmation ladder")
    pr.add_argument("target")
    pr.add_argument("--candidates", default=None,
                    help="path to wave_candidates.jsonl (default <target>/wave_candidates.jsonl)")
    pr.add_argument("--budget", type=int, default=20, metavar="N",
                    help="max candidates to prove this run (severity order; resumable)")
    pr.add_argument("--no-reach-gate", action="store_true",
                    help="disable the reachability gate (which downgrades a confirmed sink to "
                         "anomalous_state/human-review when no untrusted-input path reaches it)")
    pr.add_argument("--online", action="store_true",
                    help="give the model opt-in web_search / web_read tools (the box is otherwise fully "
                         "local; sends queries off-box only when the model is unsure about an API/service)")
    pr.set_defaults(func=cmd_prove)

    pt = sub.add_parser("patch", help="Stage 4: patch each confirmed finding + reverify with the same proof")
    pt.add_argument("target")
    pt.add_argument("--findings", default=None,
                    help="path to wave_findings.jsonl (default <target>/wave_findings.jsonl)")
    pt.add_argument("--budget", type=int, default=10, metavar="N",
                    help="max confirmed findings to patch this run")
    pt.add_argument("--write", action="store_true",
                    help="KEEP a patch that passed both gates (default: dry-run, restore the source)")
    pt.set_defaults(func=cmd_patch)

    al = sub.add_parser("all", help="one-shot pipeline: eyes(notebook) -> detect -> prove [-> patch]")
    al.add_argument("target")
    al.add_argument("--notes-budget", type=int, default=40, metavar="N",
                    help="files the notebook deep-reads; at/below this ALL pinned are read, above it the "
                         "model selects N (default 40)")
    al.add_argument("--detect-budget", type=int, default=60, metavar="N", help="findings to falsify")
    al.add_argument("--prove-budget", type=int, default=12, metavar="N", help="survivors to prove")
    al.add_argument("--patch", action="store_true", help="also run Stage 4 (patch + reverify) on confirmations")
    al.add_argument("--patch-budget", type=int, default=8, metavar="N", help="confirmed findings to patch")
    al.add_argument("--write", action="store_true", help="keep patches that pass both gates (with --patch)")
    al.add_argument("--no-reach-gate", action="store_true", help="disable the reachability gate in prove")
    al.add_argument("--online", action="store_true", help="give the model opt-in web_search/web_read (egress)")
    al.add_argument("--interactive", action="store_true", help="steer the notebook's target selection")
    al.set_defaults(func=cmd_all)

    rpt = sub.add_parser("report", help="(re)generate the readable wave_results/wave_report.md for a repo")
    rpt.add_argument("target")
    rpt.set_defaults(func=cmd_report)

    cf = sub.add_parser("config", help="set the model/endpoint once (~/.wave/config), so runs need no env")
    cf.add_argument("action", choices=["set", "show"])
    cf.add_argument("key", nargs="?", help="model | base | key | trace | a WAVE_* name")
    cf.add_argument("value", nargs="?", help="the value to set")
    cf.set_defaults(func=cmd_config)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
