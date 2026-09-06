"""Stage 3 -- THE PROOF LOOP: run the detector's survivors through the confirmation ladder.

Stage 2 (`detector.py`) produced `wave_candidates.jsonl` -- LINE-based survivors {file,line,class,sink,...}
that survived clean-room falsification. They are BELIEVED, not proven. Here each is driven through the ladder
until a TOOL witnesses the exploit -- the plan's one rule: a `confirmed` verdict must cite an effect the
model actually caused and a tool actually observed.

  rung1.micro_exec  -- cheap canary-in-sink: import the handler, tripwire the DB/HTTP/path sink, call it with
                       a marked payload; marker-in-sink-unsafe => proven, parameterized => safe (no boot, no
                       model). Python handlers only.
  investigate       -- what the canary can't settle (non-Python, no importable handler, unknown): the model
                       drives the execute() docker sandbox to prove/refute by running code, under the
                       grounding rule + the review-adopted context-discipline + structured error escalation.

The provers are FUNCTION-based; the survivors are LINE-based. We bridge with Stage 1's codemap: the enclosing
function (name + span) of each survivor line gives the `unit` the micro-exec/scaffold import and call.

Output: `wave_findings.jsonl` (per-candidate verdict, resumable) + `casefile.json` (the CaseFile report).
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from . import briefs, codemap, reachability, recorder, repro, rung1, taint
from . import investigate as invmod
from .models import Candidate

# detector class -> CWE (the provers key on cwe); "" when there is no clean single mapping
_CLASS_CWE = {"cmd": "CWE-78", "sqli": "CWE-89", "nosqli": "CWE-943", "ssrf": "CWE-918", "path": "CWE-22",
              "xss": "CWE-79", "deser": "CWE-502", "redirect": "CWE-601", "authz": "CWE-639",
              "idor": "CWE-639", "access": "CWE-639", "bola": "CWE-639", "bfla": "CWE-639",
              "eval": "CWE-95", "ssti": "CWE-1336", "protopollution": "CWE-1321", "proto": "CWE-1321",
              "prototype": "CWE-1321", "memory": "CWE-120", "format": "CWE-134", "other": ""}
# classes the cheap in-process canary oracle (rung1) can witness; others go straight to the model prover
_CANARY_CLASSES = {"cmd", "sqli", "nosqli", "ssrf", "path"}
# severity for working order (mirrors detector._SEV so the proof loop works the most dangerous first)
_SEV = {"cmd": 9, "eval": 9, "deser": 8, "ssti": 8, "sqli": 8, "memory": 8, "nosqli": 7, "ssrf": 6,
        "path": 6, "protopollution": 6, "proto": 6, "prototype": 6, "format": 6, "authz": 6, "idor": 6,
        "access": 6, "bola": 6, "bfla": 6, "xss": 4, "redirect": 3, "other": 1}

# intrinsically-dangerous sinks: executing them with a handed-in payload proves the MECHANISM (always true),
# not attacker-control -> a `confirmed` here needs HIGH-confidence reachability (else -> anomalous_state).
_INTRINSIC_CWE = {"CWE-502", "CWE-95", "CWE-1336"}          # deserialization / eval-exec / SSTI

_VERDICT_ORDER = ["confirmed", "anomalous_state", "refuted", "blocked", "believed"]
# only these are DONE on resume; blocked (under-provisioned / transient 500) + believed are re-tried
_TERMINAL = {"confirmed", "refuted", "anomalous_state"}


def _rel(root, path):
    try:
        return str(Path(path).relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def _key(d):
    return (d.get("file", ""), int(d.get("line") or 0), str(d.get("class") or "other").lower())


def load_candidates(path):
    """Read wave_candidates.jsonl -> deduped survivor dicts."""
    out, seen = [], set()
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        k = _key(d)
        if k in seen:
            continue
        seen.add(k)
        out.append(d)
    return out


def _enclosing(fi, line):
    """The smallest-span function (top-level OR method) whose body contains `line` -- gives the unit the
    micro-exec/scaffold imports and calls. None if the line sits outside every function."""
    best = best_span = None
    funcs = list(fi.functions) + [mth for c in fi.classes for mth in c.methods]
    for f in funcs:
        end = f.end or f.line
        if f.line <= line <= end:
            span = end - f.line
            if best is None or span < best_span:
                best, best_span = f, span
    return best


def _to_candidate(surv, rel_index, target):
    """Adapt a line-based survivor + codemap into a models.Candidate the provers consume."""
    rel = surv.get("file", "")
    line = int(surv.get("line") or 0)
    cls = str(surv.get("class") or "other").lower()
    fi = rel_index.get(rel)
    func = _enclosing(fi, line) if fi else None
    unit = (func.name + (func.sig or "()")) if func else ""
    return Candidate(
        file=str(Path(target) / rel), unit=unit, line=line,
        cwe=_CLASS_CWE.get(cls, ""), family=f"{cls} (detector survivor)", detector="detector",
        sink=str(surv.get("sink") or ""),
        provable=cls in _CANARY_CLASSES and rel.endswith(".py") and bool(unit),
        rank=_SEV.get(cls, 1), route_hint=str(surv.get("input") or "")[:80], slice="", resolved_from="")


def _subj(c):
    return f"{c.cwe or c.family} {c.loc()}"


def _prove_one(model, target, c, have_docker, max_steps, online=False):
    """Run ONE candidate through the ladder -> a verdict record dict."""
    tstatus, tnote = taint.analyze(c)                        # intra-function value taint (Python; else unknown)
    reason = "not a canary-provable Python handler"
    if c.provable:
        mr = rung1.micro_exec(c, rt=None)                    # cheap in-process canary (no boot, no model)
        if mr.verdict == "proven":
            return {"verdict": "confirmed", "evidence": mr.evidence, "why": mr.reason, "ran": 0,
                    "oracle": f"rung1 micro-exec (stubs={mr.stubs})", "marker": mr.marker, "taint": tstatus}
        if mr.verdict == "safe":
            return {"verdict": "refuted", "evidence": "", "why": mr.reason, "ran": 0,
                    "oracle": "rung1 micro-exec", "taint": tstatus}
        reason = mr.reason                                   # unknown -> hand to the model prover
    if not have_docker:
        return {"verdict": "believed", "evidence": "", "ran": 0, "oracle": "", "taint": tstatus,
                "why": f"docker unavailable -- canary unsettled ({reason})"}
    if model is None:
        return {"verdict": "believed", "evidence": "", "ran": 0, "oracle": "", "taint": tstatus,
                "why": f"no model to investigate -- canary unsettled ({reason})"}
    if tnote:                                                # resolve the slice for the model (structure, its job)
        reason = f"{reason} | value-taint: {tstatus} -- {tnote}"
    mode = briefs._proof_mode(c)                             # sanitizer/ssti/protopoll/deser/render/call
    scaffold = repro.build(c, target, mode=("render" if mode == "render" else "call"))
    img = briefs._image_for(c.file)
    if briefs._is_js(c.file):                                # JS/TS need tsx + the repo's node_modules;
        from . import js_env                                 # DOM render ALSO needs a real browser --
        if mode == "render":                                 # node:20-slim has none of these (the XSS miss).
            js_env.ensure_deps(target)                       # (all cached/idempotent -> built once, then fast)
            img = js_env.ensure_browser_runner() or js_env.prepare(target) or img
        else:
            img = js_env.prepare(target) or img
    step_to = 120 if mode in ("render", "asan") else (90 if briefs._is_js(c.file) else 45)  # asan compiles
    try:
        # container stays sandboxed (network=none); web_search/web_read run on the HOST -- the single,
        # controlled egress point when online, not blanket container network access.
        v = invmod.investigate(model, briefs._brief_for(c, target, reason, scaffold=scaffold, mode=mode),
                               image=img, mount=target, network="none", max_steps=max_steps,
                               step_timeout=step_to, online=online)
    finally:
        repro.remove(target)
    verdict = v.verdict
    # DIFFERENTIAL (IDOR/access-control): a witnessed boundary crossing is a business-logic JUDGMENT anchored
    # to an observed state change -- always human-review, never a tool-witnessed `confirmed` (design + §10.7).
    if mode == "differential" and verdict == "confirmed":
        verdict = "anomalous_state"
    return {"verdict": verdict, "evidence": (v.evidence or "")[:400], "why": (v.why or "")[:300],
            "oracle": f"investigate ({v.ran} run(s), {mode})", "ran": v.ran, "taint": tstatus}


def _record_outcome(case, hyp_id, c, rec):
    """Fold a verdict into the CaseFile (grounding rule: only a witnessed effect backs `confirmed`)."""
    v = rec["verdict"]
    if v == "confirmed":
        case.supersede(hyp_id, status="confirmed")
        src = "oracle" if str(rec.get("oracle", "")).startswith("rung1") else "model"
        case.record("confirmation", _subj(c), src, "confirmed", provenance=c.loc(), cwe=c.cwe,
                    evidence=rec.get("evidence", ""), oracle=rec.get("oracle", ""))
    elif v == "anomalous_state":
        case.supersede(hyp_id, status="anomalous_state")
        case.record("confirmation", _subj(c), "model", "anomalous_state", provenance=c.loc(), cwe=c.cwe,
                    evidence=rec.get("evidence", ""), oracle=rec.get("oracle", ""))
    elif v == "refuted":
        case.supersede(hyp_id, status="refuted", note=rec.get("why", ""))
    elif v == "blocked":
        case.supersede(hyp_id, status="blocked", note=rec.get("why", ""))
    else:                                                    # believed -- a lead, never a finding
        case.record("evidence", _subj(c), "tool", "believed", provenance=c.loc(), cwe=c.cwe,
                    note=rec.get("why", ""))


def _apply_gate(rec, c, cmap):
    """Context + reachability gates on a `confirmed` sink (never drops -- only re-categorizes to
    `anomalous_state`/human-review):
      (1) CONTEXT: a server-side class proven in FRONTEND/browser code is a mislabel (a browser fetch is not
          server-side SSRF; the browser has no SQL/fs/shell).
      (2) REACHABILITY: no path from an untrusted-facing entry reaches the sink -> may be internal/intended."""
    if rec.get("verdict") != "confirmed":
        return rec
    if c.cwe in reachability.SERVER_ONLY_CWE:                # (1) execution-context gate
        try:
            src = Path(c.file).read_text(encoding="utf-8", errors="replace")
        except OSError:
            src = ""
        if reachability.is_frontend(c.file, source=src):
            rec["verdict"] = "anomalous_state"
            rec["context"] = "frontend/browser code"
            rec["why"] = (f"[context] this sink is in FRONTEND/browser code -- not server-side {c.cwe} "
                          f"(the browser makes this call); review as a client-side concern if any. "
                          + rec.get("why", ""))
            return rec
    # (2) value-taint gate: a MODEL-confirmed sink whose args don't derive from untrusted input in this
    # function is likely a mislabel (the eval-runner shape). Conservative: only 'unrelated' (never the
    # cross-function 'unknown'), and NEVER override a canary -- that dynamically WITNESSED the value at the
    # sink, so it is ground truth over this static heuristic.
    if rec.get("taint") == "unrelated" and str(rec.get("oracle", "")).startswith("investigate"):
        rec["verdict"] = "anomalous_state"
        rec["why"] = ("[value-taint] the sink arguments do not derive from untrusted input in this function "
                      "-- likely a mislabel; human review. " + rec.get("why", ""))
        return rec
    reachable, conf, note = reachability.gate(cmap, c.unit)  # (3) reachability gate (+ confidence)
    rec["reachability"] = note
    if not reachable:
        rec["verdict"] = "anomalous_state"
        rec["why"] = f"[reachability] {note}. " + rec.get("why", "")
        return rec
    # (4) intrinsic-sink bar: deser/eval/ssti sinks are dangerous BY NATURE -- running them with a handed-in
    # payload proves the MECHANISM (trivially true), not that an ATTACKER controls the input. So a `confirmed`
    # here needs HIGH-confidence reachability from a real untrusted entry; if the only path is an ambiguous
    # name-based edge, attacker-control is unproven -> human review (authentik pickle case).
    if c.cwe in _INTRINSIC_CWE and conf != "high":
        rec["verdict"] = "anomalous_state"
        rec["why"] = (f"[intrinsic-sink] {c.cwe} executes arbitrary input (mechanism proven), but "
                      f"attacker-control of that input is NOT established -- reachability is {conf}-confidence "
                      f"({note}). Verify the caller/input source. " + rec.get("why", ""))
    return rec


def run(model, target, candidates_path=None, budget=20, out_dir=None, resume=True, max_steps=8, gate=True,
        online=False):
    """Prove the detector's survivors (severity order, up to `budget`). Writes per-candidate verdicts to
    wave_findings.jsonl (resumable) + casefile.json. Returns (by_verdict, paths)."""
    target = str(target)
    out_dir = Path(out_dir or target)
    candidates_path = candidates_path or (out_dir / "wave_candidates.jsonl")
    if not Path(candidates_path).exists():
        raise SystemExit(f"no candidates at {candidates_path} -- run `detect` first")
    survs = load_candidates(candidates_path)
    survs.sort(key=lambda d: _SEV.get(str(d.get("class") or "other").lower(), 1), reverse=True)

    cmap = codemap.build(target)
    rel_index = {_rel(target, p): fi for p, fi in cmap.files.items()}

    case = recorder.CaseFile(target)
    findings_log = out_dir / "wave_findings.jsonl"
    # append-only log; last record per candidate wins. Only a TERMINAL verdict is "done" -- a `blocked`
    # (under-provisioned / a transient model-500) or `believed` lead is RE-TRIED on a later run.
    prior = {}
    if resume and findings_log.exists():
        for line in findings_log.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                d = json.loads(line)
                prior[(d["file"], d["line"], d["class"])] = d
            except Exception:
                pass
    skip = {k for k, d in prior.items() if d.get("verdict") in _TERMINAL}

    have_docker = shutil.which("docker") is not None
    if not have_docker:
        print("[prove] docker not available -- canary-only; unsettled candidates stay 'believed'", flush=True)
    n_todo = min(budget, sum(1 for s in survs if _key(s) not in skip))
    worked = 0
    with findings_log.open("a", encoding="utf-8") as fh:
        for surv in survs:
            k = _key(surv)
            if k in skip:
                continue
            if worked >= budget:
                break
            worked += 1
            c = _to_candidate(surv, rel_index, target)
            print(f"[prove] {worked}/{n_todo} {c.cwe or surv.get('class')}@{surv.get('file')}:"
                  f"{surv.get('line')} ({c.unit or 'no-func'}) ...", flush=True)
            hyp_id = case.record("hypothesis", _subj(c), "seed", "believed", provenance=c.loc(),
                                 cwe=c.cwe, family=c.family).id
            rec = _prove_one(model, target, c, have_docker, max_steps, online=online)
            if gate:                                        # untrusted-reachability gate on confirmations
                rec = _apply_gate(rec, c, cmap)
            if rec.get("verdict") == "confirmed":           # final EVIDENCE AUDIT (only high-stakes confirms):
                from . import audit                          # re-run the proof + a fresh clean-room skeptic
                av, anote = audit.audit(model, c, rec)
                if av != "confirmed":
                    rec["verdict"] = av
                    rec["why"] = anote + " " + rec.get("why", "")
                rec["audit"] = anote
                print(f"[prove]   audit -> {rec['verdict']}", flush=True)
            _record_outcome(case, hyp_id, c, rec)
            out = {"file": surv.get("file", ""), "line": int(surv.get("line") or 0),
                   "class": str(surv.get("class") or "other").lower(), "cwe": c.cwe, "unit": c.unit,
                   "sink": surv.get("sink", ""), "confidence": surv.get("confidence", ""), **rec}
            fh.write(json.dumps(out) + "\n")
            fh.flush()
            prior[k] = out
            print(f"[prove]   -> {rec['verdict'].upper()}: "
                  f"{(rec.get('evidence') or rec.get('why', ''))[:100]}", flush=True)

    if model is not None:
        try:
            model.unload()
        except Exception:
            pass

    by = {v: [] for v in _VERDICT_ORDER}
    for d in prior.values():                                # last verdict per candidate
        by.get(d.get("verdict", "believed"), by["believed"]).append(d)
    casefile = out_dir / "casefile.json"
    try:
        case.save(str(casefile))
    except OSError:
        pass
    return by, {"findings": str(findings_log), "casefile": str(casefile), "report": case.report()}
