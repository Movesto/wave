"""State machine — the serialized loop that ties the stages together.

v0.1: the deterministic DETECT->PROVE loop (discover -> provision -> exploit -> oracle) with a
DEFER ledger. The model-driven halves (auth synthesis, patch + dual-gate) attach at the marked
points as remediate.py / model.py land. Precision-first: only oracle-PROVEN candidates become
findings; provable candidates the oracle can't confirm are DEFERRED with a reason.
"""
from dataclasses import asdict

from . import discover as disc
from . import provision as prov
from . import routes as routes_mod
from . import registry, oracle, remediate, idor, exploit, dom_oracle, oast, missing_controls, behavioral
from . import browser_recon, bizlogic, recorder, rung0, rung1, reader, editor, reporters
from . import auth as auth_mod
from .models import Finding


def _prove_xss(rt, c, routes, model, auth):
    """XSS has no backend sink -- the model crafts an executing payload and the headless-browser DOM
    oracle witnesses it run (mere reflection is not proven). Reflected XSS via the crafted request URL."""
    import secrets
    marker = "WZ" + secrets.token_hex(3)
    for r in exploit.craft_requests(model, c, routes, marker):
        url = rt.base_url.rstrip("/") + "/" + r["path"].lstrip("/")
        v = dom_oracle.prove_xss(url, {**(auth or {}), **(r["headers"] or {})}, marker)
        if v.get("status") == "proven":
            v["proven_request"], v["request"], v["payload"] = r, f"{r['method']} {r['path']}", r["payload"]
            return v
    return {"status": "not-proven", "cwe": "CWE-79", "notes": "no crafted XSS executed in the DOM"}


def run_loop(target, host_port=None, strikes=1, fix=False, model_discover=False, use_reader=False,
             budget=80, audit_deps=True, dynamic=False, online=False):
    """Full loop on `target`: discover -> provision -> (MODEL crafts exploits) prove, then (if fix)
    patch + dual-gate. The model drives exploitation and remediation; tools prove. Returns a dict.

    Discovery is a HINT only (P4): deterministic by default (reliable); `model_discover=True` uses
    the fast review model. Either way the oracle is what proves a candidate, so a missed/over-eager
    candidate costs recall, never a false result."""
    from .model import Model
    target = str(target)
    routes = routes_mod.extract_routes(target)
    cands = disc.discover(target, model_driven=model_discover)
    provable = [c for c in cands if c.provable]

    # --- Case File up front + Rung 0 STATIC pre-pass: settle what we can from the CODE before booting,
    # so verdicts survive even if the app never provisions (investigation-loop plan, Rung 0). ---
    case = recorder.CaseFile(target)
    for r in routes:
        case.record("route", f"{r.method} {r.path}", "tool", "confirmed", provenance=r.file or "")

    # --- Reporter (Phase 6): dependency-vulnerability audit -- external intel, CONFIRMED by the advisory
    # DB (Tier-1-grade), static so it runs even if the app never boots. General to any project. ---
    if audit_deps:
        dep_vulns = reporters.dependency_audit(target)
        for d in dep_vulns:
            subj = f"{d['id']} {d['package']}=={d['version']}"
            case.record("hypothesis", subj, "tool", "confirmed", provenance=f"{d['package']}=={d['version']}",
                        cwe=d["id"], family="vulnerable dependency")
            case.record("confirmation", subj, "oracle", "confirmed", provenance=f"{d['package']}=={d['version']}",
                        cwe=d["id"], evidence=f"advisory {d['id']} ({d['ecosystem']}): fix {d['fix']} -- {d['desc']}")
        if dep_vulns:
            print(f"[reporter] dependency audit: {len(dep_vulns)} known-vulnerable dependency finding(s)", flush=True)

    secrets_found = reporters.secret_scan(target)   # hardcoded credentials (CWE-798); offline, always on
    for s in secrets_found:
        loc = f"{s['file']}:{s['line']}"
        subj = f"CWE-798 {s['type']} {loc}"
        case.record("hypothesis", subj, "tool", "confirmed" if s["status"] == "confirmed" else "believed",
                    provenance=loc, cwe="CWE-798", family=f"hardcoded secret ({s['type']})")
        if s["status"] == "confirmed":
            case.record("confirmation", subj, "oracle", "confirmed", provenance=loc, cwe="CWE-798",
                        evidence=f"hardcoded {s['type']}: {s['snippet']}")
    if secrets_found:
        nconf = sum(1 for s in secrets_found if s["status"] == "confirmed")
        print(f"[reporter] secret scan: {nconf} confirmed + {len(secrets_found) - nconf} suspected "
              f"hardcoded secret(s)", flush=True)

    dev_markers = reporters.todo_scan(target)       # security-flavoured TODO/HACK -> prioritization hints
    hint_files = {m["file"] for m in dev_markers}
    for m in dev_markers:
        case.record("evidence", f"dev-marker {m['tag']} {m['file']}:{m['line']}", "tool", "believed",
                    provenance=f"{m['file']}:{m['line']}", note=f"{m['tag']}: {m['text']}")
    if dev_markers:
        print(f"[reporter] dev markers: {len(dev_markers)} security-flavoured TODO/HACK hint(s)", flush=True)

    def _subj(c):
        return f"{c.cwe} {c.route_hint or c.loc()}"

    hyp = {}                                                # subject -> its hypothesis entry id

    def _ensure_hyp(c):
        s = _subj(c)
        if s not in hyp:
            src = "model" if c.detector == "reader" else "seed"   # a Reader hypothesis vs a seed-pattern one
            hyp[s] = case.record("hypothesis", s, src, "believed", provenance=c.loc(),
                                 cwe=c.cwe, family=c.family).id
        return s

    model = None
    if use_reader:                                          # Phase 4+7: the model READS prioritized files and
        model = Model()                                     # forms its OWN hypotheses, REVISITING via import-leads
        reader_cands, reader_report = reader.read_iterative(model, target, provable, routes,
                                                            budget=6, per_round=3, max_rounds=2,
                                                            online=online)
        if online:
            print("[reader] --online: low-confidence hypotheses may spend a web-search lookup", flush=True)
        for path, summary, _h in reader_report:
            case.record("file_summary", path, "model", "believed", note=summary)
        seen = {(c.file, c.cwe) for c in provable}
        added = 0
        for rc in reader_cands:                             # merge model hypotheses the seed pass missed
            if rc.provable and (rc.file, rc.cwe) not in seen:
                provable.append(rc)
                seen.add((rc.file, rc.cwe))
                added += 1
        print(f"[reader] read {len(reader_report)} file(s) -> "
              f"{sum(len(h) for _p, _s, h in reader_report)} hypotheses; "
              f"+{added} candidate(s) beyond the seed pass", flush=True)

    provable_runtime, refuted, reachable_subjects = [], [], set()
    for c in provable:
        _ensure_hyp(c)
        a = rung0.assess(c)
        if a.verdict == "safe":                             # proven-safe without running -> REFUTE
            case.supersede(hyp[_subj(c)], status="refuted", note=f"Rung0: {a.reason}")
            refuted.append((c, a.reason))
        else:
            if a.verdict == "reachable":                    # a stronger lead -> note it, still prove at runtime
                reachable_subjects.add(_subj(c))
                case.record("evidence", _subj(c), "tool", "believed", provenance=c.loc(),
                            cwe=c.cwe, note=f"Rung0 reachable: {a.reason}")
            provable_runtime.append(c)
    if refuted:
        print(f"[rung0] cleared {len(refuted)} candidate(s) as proven-safe (no boot); "
              f"{len(provable_runtime)} left for the runtime oracle", flush=True)

    # --- Editor (Phase 5): work the highest-value hypotheses first (severity x confidence x
    # reachability) and BOUND the run with a budget -- the rest are recorded, not silently dropped. ---
    provable_runtime = editor.prioritize(provable_runtime, reachable_subjects, hint_files)
    provable_runtime, budget_deferred = editor.apply_budget(provable_runtime, budget)
    for c in budget_deferred:
        case.record("evidence", _subj(c), "tool", "believed", provenance=c.loc(), cwe=c.cwe,
                    note="deferred (budget) -- lower-priority, not worked this run")
    if budget_deferred:
        print(f"[editor] budget={budget}: working {len(provable_runtime)} highest-priority candidate(s), "
              f"{len(budget_deferred)} deferred", flush=True)

    findings, deferred = [], []

    if not dynamic:
        # === RUN-BY-PIECE (default): micro-execute ONLY the pieces we're skeptical of. Scan the whole
        # repo statically, but never boot the whole app to understand one function. Whole-app dynamic
        # testing (Rung 2 + business-logic differentials) is opt-in via --dynamic. ===
        prep_rt = None
        try:
            prep_rt, _pf, _pp = prov.prepare(target, host_port)   # write the compose/hooks; do NOT boot
        except Exception as e:
            case.record("blocked", "prepare", "tool", "blocked", provenance=str(target),
                        note=f"could not prepare the image for micro-exec: {type(e).__name__}: {e}")
        n_safe = 0
        for c in provable_runtime:
            mr = rung1.micro_exec(c, rt=prep_rt)               # run JUST this piece (in-process, else in-image)
            s = _ensure_hyp(c)
            if mr.verdict == "proven":
                case.supersede(hyp[s], status="confirmed")
                case.record("confirmation", s, "oracle", "confirmed", provenance=c.loc(), cwe=c.cwe,
                            evidence=mr.evidence, oracle=f"Rung1 micro-exec (stubs={mr.stubs})")
                findings.append(Finding(candidate=c, status="proven (rung1)", evidence=mr.evidence,
                                        payload=mr.marker, proven_request=None, notes="Rung1 micro-exec (no boot)"))
            elif mr.verdict == "safe":
                case.supersede(hyp[s], status="refuted", note=f"Rung1: {mr.reason}")
                n_safe += 1
            else:
                deferred.append((c, "micro-exec unsettled -- a lead for review (or run --dynamic to boot the app)"))
        if prep_rt is not None:
            try:
                prep_rt.down()
            except Exception:
                pass
        if model is not None:
            model.unload()
        for c, reason in deferred:
            case.record("evidence", _ensure_hyp(c), "tool", "believed", provenance=c.loc(), cwe=c.cwe, note=reason)
        print(f"[rung1] run-by-piece: {len(findings)} proven, {n_safe} refuted-safe, {len(deferred)} unsettled "
              f"(no whole-app boot; use --dynamic for the differential/business-logic oracles)", flush=True)
        print(f"[recorder] case file: {len(case.all())} entries -- {len(case.by_kind('route'))} routes, "
              f"{len(case.hypotheses())} hypotheses, {len(case.findings())} confirmed, "
              f"{len(case.refuted())} refuted-safe, {len(case.by_kind('evidence'))} evidence", flush=True)
        print(editor.summary(case, len(budget_deferred)), flush=True)
        return {"findings": findings, "deferred": deferred, "case": case,
                "summary": {"candidates": len(cands), "provable": len(provable), "refuted_static": len(refuted),
                            "proven": len(findings), "deferred": len(deferred), "fixed": 0}}

    # === DYNAMIC (opt-in): boot the whole app -> Rung 2 craft + business-logic/IDOR differentials. ===
    findings, deferred, pending_oast = [], [], []
    rt = canary = hook_list = None                          # model may already be loaded (Reader); else load in try
    auth = {}
    try:
        rt = prov.provision(target, host_port=host_port)
        recon = browser_recon.recon(rt)                     # browser-as-eyes: live forms/links/egress (§18 #5)
        if recon.get("routes"):                             # augment the static route table with what the app renders
            known = {(r.method, r.path) for r in routes}
            new = [r for r in recon["routes"] if (r.method, r.path) not in known]
            if new:
                print(f"[recon] +{len(new)} route(s) from the rendered DOM (forms/links)", flush=True)
                routes = routes + new
        if recon.get("egress"):
            print(f"[recon] external hosts the app contacts: {recon['egress']}", flush=True)
        hook_list = registry.select(rt.profile.deps_text, rt.profile.lang)   # the app's instrumented sinks
        auth = auth_mod.synthesize(rt, routes)              # session for routes behind login (or {})
        if auth:
            print(f"[auth] synthesized session ({list(auth)[0]})", flush=True)
        if model is None:                                   # loaded early only when the Reader ran
            model = Model()                                 # 14B: crafts exploits + patches
        canary = oast.Canary().start()                      # OAST: async/blind egress witness
        for c in provable_runtime:
            if c.cwe == "CWE-79":                          # XSS -> DOM oracle (headless browser)
                v = _prove_xss(rt, c, routes, model, auth)
            elif c.cwe == "CWE-1333":                      # ReDoS -> behavioral timing oracle
                v = behavioral.prove_redos(rt, c, auth)
            elif not hook_list:
                deferred.append((c, "no instrumented sink hook for this app's drivers"))
                continue
            else:
                v = oracle.prove_injection(rt, hook_list, c, routes, model, strikes=strikes,
                                           auth=auth, canary=canary)
            if v.get("status") == "proven":
                f = Finding(candidate=c, status="proven", evidence=v["evidence"], payload=v.get("payload", ""),
                            proven_request=v.get("proven_request"),
                            notes=f"{v.get('oracle', '')} via {v.get('request', '')}")
                if v.get("proven_request"):
                    f.baseline_status = oracle.benign_status(rt, f.proven_request, auth=auth)
                findings.append(f)
            else:
                deferred.append((c, v.get("notes", "not proven at sink")))
                if v.get("marker"):
                    pending_oast.append((v["marker"], c))  # sweep for a LATE callback (async/2nd-order)

        # --- IDOR / authorization (differential oracle; model judges which id-routes are private) ---
        idor_routes = idor.flag_owned(model, idor.id_param_routes(routes))
        attackers = auth_mod.synthesize_multi(rt, routes, 2)      # >=1 authenticated attacker
        atk = attackers[0]["auth"] if attackers else auth
        for route in idor_routes:
            c = idor.candidate_for(route)
            v = idor.prove_idor(rt, route, atk)
            if v.get("status") == "proven":
                findings.append(Finding(candidate=c, status="proven", evidence=v["evidence"],
                                        payload=v["payload"], proven_request=None,
                                        notes=f"{v['oracle']} via {v['request']} [owner-judgment: needs confirm]"))
            else:
                deferred.append((c, v.get("notes", "idor not proven")))

        # --- Missing controls (behavioral; §18 #2): rate limiting on credential-sensitive routes ---
        for route in missing_controls.sensitive_routes(routes):
            c = missing_controls.candidate_for(route)
            v = missing_controls.prove_no_ratelimit(rt, route, auth)
            if v.get("status") == "proven":
                findings.append(Finding(candidate=c, status="proven", evidence=v["evidence"],
                                        payload=v["payload"], proven_request=None,
                                        notes=f"{v['oracle']} via {v['request']} [control-judgment: needs confirm]"))
            else:
                deferred.append((c, v.get("notes", "control present")))
        for route in missing_controls.change_routes(routes):   # missing old-password check (CWE-620)
            c = missing_controls.candidate_for_change(route)
            v = missing_controls.prove_no_oldpassword(rt, route, auth)
            if v.get("status") == "proven":
                findings.append(Finding(candidate=c, status="proven", evidence=v["evidence"],
                                        payload=v["payload"], proven_request=None,
                                        notes=f"{v['oracle']} via {v['request']} [control-judgment: needs confirm]"))
            else:
                deferred.append((c, v.get("notes", "control present")))

        # --- Business logic (Tier-2; §18): the MODEL proposes an invariant + tamper, a differential
        # PROVES the violation by a server-confirmed, attacker-favorable delta. First class: web
        # parameter tampering (CWE-472) -- server trusts a client price/amount it should own. ---
        biz_hints = bizlogic.propose_hints(model, routes)      # model frames body/fields (hint only)
        for route in bizlogic.value_routes(routes):
            c = bizlogic.candidate_for(route)
            v = bizlogic.prove_tamper(rt, route, auth, hint=biz_hints.get(route.path))
            if v.get("status") == "proven":
                findings.append(Finding(candidate=c, status="proven", evidence=v["evidence"],
                                        payload=v["payload"], proven_request=None,
                                        notes=f"{v['oracle']} via {v['request']} [logic-judgment: needs confirm]"))
            else:
                deferred.append((c, v.get("notes", "no tamper delta")))
        for route in bizlogic.value_routes(routes):            # negative quantity / numeric invariant (CWE-1284)
            c = bizlogic.candidate_for_negative(route)
            v = bizlogic.prove_negative(rt, route, auth, hint=biz_hints.get(route.path))
            if v.get("status") == "proven":
                findings.append(Finding(candidate=c, status="proven", evidence=v["evidence"],
                                        payload=v["payload"], proven_request=None,
                                        notes=f"{v['oracle']} via {v['request']} [logic-judgment: needs confirm]"))
            else:
                deferred.append((c, v.get("notes", "quantity validated")))
        for route in bizlogic.flow_routes(routes):             # fund-flow reversal / negative amount (CWE-682)
            c = bizlogic.candidate_for_reversal(route)
            v = bizlogic.prove_reversal(rt, route, auth)
            if v.get("status") == "proven":
                findings.append(Finding(candidate=c, status="proven", evidence=v["evidence"],
                                        payload=v["payload"], proven_request=None,
                                        notes=f"{v['oracle']} via {v['request']} [logic-judgment: needs confirm]"))
            else:
                deferred.append((c, v.get("notes", "amount validated")))
        for route in bizlogic.privilege_routes(routes):        # privilege-via-parameter / mass assignment (CWE-915)
            c = bizlogic.candidate_for_privilege(route)
            v = bizlogic.prove_mass_assignment(rt, route, auth)
            if v.get("status") == "proven":
                findings.append(Finding(candidate=c, status="proven", evidence=v["evidence"],
                                        payload=v["payload"], proven_request=None,
                                        notes=f"{v['oracle']} via {v['request']} [logic-judgment: needs confirm]"))
            else:
                deferred.append((c, v.get("notes", "no privilege persisted")))
        for route in bizlogic.replay_routes(routes):           # replay / missing idempotency (CWE-837)
            c = bizlogic.candidate_for_replay(route)
            v = bizlogic.prove_replay(rt, route, auth)
            if v.get("status") == "proven":
                findings.append(Finding(candidate=c, status="proven", evidence=v["evidence"],
                                        payload=v["payload"], proven_request=None,
                                        notes=f"{v['oracle']} via {v['request']} [logic-judgment: needs confirm]"))
            else:
                deferred.append((c, v.get("notes", "idempotent / no stacking")))
        for protected, prereqs in bizlogic.workflow_pairs(routes):   # workflow / step-order bypass (CWE-840)
            c = bizlogic.candidate_for_workflow(protected)
            v = {"status": "not-proven", "notes": "workflow enforced / no bypass"}
            for q in prereqs:
                r = bizlogic.prove_stepbypass(rt, q, protected, auth)
                if r.get("status") == "proven":
                    v = r
                    break
            if v.get("status") == "proven":
                findings.append(Finding(candidate=c, status="proven", evidence=v["evidence"],
                                        payload=v["payload"], proven_request=None,
                                        notes=f"{v['oracle']} via {v['request']} [logic-judgment: needs confirm]"))
            else:
                deferred.append((c, v.get("notes", "workflow enforced")))

        # --- OAST async sweep: a callback that arrived AFTER the synchronous proving window (a
        # second-order payload / a delayed worker egress) -- exactly what the sync sink poll misses. ---
        for mk, c in pending_oast:
            late = canary.hit(mk, wait=6)
            if late:
                findings.append(Finding(candidate=c, status="proven",
                    evidence=f"delayed OAST callback at {late[0]['path']} from {late[0]['client']}",
                    payload=mk, notes=f"OAST-canary (async) via {c.route_hint or c.loc()}"))
                deferred[:] = [(dc, r) for (dc, r) in deferred if dc is not c]
    except Exception as e:                                  # dynamic stage failed -> Rung 1, then static verdicts
        case.record("blocked", "provisioning/runtime", "tool", "blocked", provenance=target,
                    note=f"could not run the app dynamically: {type(e).__name__}: {e}")
        print(f"[loop] dynamic stage failed ({type(e).__name__}: {e}) -- trying Rung 1 "
              f"(micro-execution, no boot)", flush=True)
        r1 = 0
        for i, c in enumerate(provable_runtime):            # Rung 1: confirm WITHOUT booting (in-process, or
            allow_container = i < 10                        # in-container -- bounded, it starts a container each)
            mr = rung1.micro_exec(c, target=target if allow_container else None)
            if mr.verdict == "proven":
                findings.append(Finding(candidate=c, status="proven (rung1)", evidence=mr.evidence,
                                        payload=mr.marker, proven_request=None,
                                        notes=f"Rung1 micro-exec (stubs={mr.stubs})"))
                r1 += 1
            elif mr.verdict == "safe":
                case.supersede(hyp[_ensure_hyp(c)], status="refuted", note=f"Rung1: {mr.reason}")
        if r1:
            print(f"[rung1] confirmed {r1} candidate(s) by micro-execution (no boot)", flush=True)
    finally:
        if canary is not None:
            canary.stop()
        if rt is not None:
            rt.down()                  # free the port before the patch phase re-provisions

    if fix and findings and model is not None:
        for f in findings:
            if f.candidate.detector in ("differential", "behavioral") or f.candidate.cwe in ("CWE-79", "CWE-1333"):
                f.status = "proven (fix-deferred)"          # IDOR / rate-limit / XSS / ReDoS fixes not automated
                continue
            r = remediate.remediate(target, f.candidate, f, model, routes, hook_list, host_port=host_port)
            f.patch = r.get("patch", "")
            f.gate_a = r.get("gate_a", "")
            f.gate_b = r.get("gate_b", "")
            f.status = "fixed" if r.get("status") == "fixed" else "proven (" + r.get("status", "?") + ")"
    if model is not None:
        model.unload()

    # --- record what the runtime stage proved/deferred into the Case File (hypotheses + Rung-0
    # verdicts already recorded above). PROVEN -> the belief transitions to confirmed; DEFERRED ->
    # evidence (still a believed hypothesis, never a finding). ---
    for f in findings:
        s = _ensure_hyp(f.candidate)
        case.supersede(hyp[s], status="confirmed")
        case.record("confirmation", s, "oracle", "confirmed", provenance=f.candidate.loc(),
                    cwe=f.candidate.cwe, evidence=f.evidence, oracle=f.notes)
    for c, reason in deferred:
        s = _ensure_hyp(c)
        case.record("evidence", s, "tool", "believed", provenance=c.loc(), cwe=c.cwe, note=reason)
    print(f"[recorder] case file: {len(case.all())} entries -- {len(case.by_kind('route'))} routes, "
          f"{len(case.hypotheses())} hypotheses, {len(case.findings())} confirmed, "
          f"{len(case.refuted())} refuted-safe, {len(case.by_kind('evidence'))} evidence", flush=True)
    print(editor.summary(case, len(budget_deferred)), flush=True)

    return {
        "findings": findings,
        "deferred": deferred,
        "case": case,
        "summary": {"candidates": len(cands), "provable": len(provable),
                    "refuted_static": len(refuted), "proven": len(findings),
                    "deferred": len(deferred), "fixed": sum(1 for f in findings if f.status == "fixed")},
    }
