"""The tool-use loop -- the model drives the `execute` tool to prove its own hypotheses.

hypothesize -> act -> observe -> reason -> conclude. The model is handed a hypothesis and a sandbox; each
turn it emits ONE json action -- run a command, or conclude -- and we feed the real result back until it
decides. R1/Qwen have no native function-calling, so this is a text protocol: the model writes a json
action, we run it, append the observation, and re-generate.

THE GROUNDING RULE (evidence-grounded plan): the model reasons and has the final say, but a `confirmed`
verdict must cite an effect it actually CAUSED and OBSERVED -- reasoning alone can only PROPOSE
(`believed`). Enforced here: a "confirmed" with no command ever run is downgraded to "believed". The tool
supplies reality; the model supplies the judgement.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .execute import execute

_AGENT_SYS = (
    "You are a security investigator with a real SANDBOX you can run commands in. Investigate the "
    "hypothesis below by ACTUALLY RUNNING code -- write a script, execute it, observe the real result. "
    "Do NOT guess and do NOT invent facts (no made-up CVEs). Each turn output EXACTLY ONE json object and "
    "nothing else:\n"
    '  run a command: {"action":"run","command":"<shell command>","image":"<optional docker image, '
    'e.g. python:3.12-slim or node:20-slim>","network":"<none|host>","why":"<what you expect to see>"}\n'
    '  finish:        {"action":"conclude","verdict":"confirmed|refuted|believed|blocked|anomalous_state",'
    '"cwe":"CWE-XX","why":"<why, citing what you OBSERVED>","evidence":"<the concrete observed effect>"}\n'
    "RULES: (1) You may only CONFIRM after you have RUN something and OBSERVED the effect that proves it; "
    "reasoning alone is 'believed', never 'confirmed'. (2) 'refuted' means you ran it and saw it is safe. "
    "(3) 'blocked' means you could not run what you needed. (4) Keep commands self-contained; the target's "
    "code is under the working directory. Keep any reasoning BRIEF, then output ONLY the json object. "
    "(5) A MISSING dependency (ModuleNotFoundError / Cannot find module) or a refused connection is an "
    "ENVIRONMENT problem, NOT proof the code is safe -- install it and re-run; if you still cannot run it, "
    "RESEARCH the dependency/API (if web_search is available) and conclude a reasoned 'believed' citing what "
    "you found, else 'blocked' -- NEVER 'refuted'/'confirmed' without running it. (6) Use 'anomalous_state' "
    "for an OBSERVED business-logic / IDOR state change (a judgment call, not a tool-witnessed injection).\n"
    "HOW TO RUN CODE: each action is exactly ONE shell command. Do NOT run a file you have not created. "
    "Either run it INLINE, e.g. command \"python3 -c 'import app; app.f(\\\"; id\\\")'\", or CREATE the "
    "file first in one command with a heredoc, e.g. \"cat > t.py <<'EOF'\\n...\\nEOF\\npython3 t.py\". "
    "If a command fails, READ the error and try a DIFFERENT approach -- never repeat the same failing "
    "command.\n"
    "READING THE PROOF: when you inject a command (e.g. `; id`, `; echo WAVE-PWNED`), the OUTPUT of that "
    "injected command IS the proof -- a `uid=...` line, your marker, a file listing means it executed. "
    "The moment you see it, CONCLUDE 'confirmed' and cite that exact output as the evidence; do not keep "
    "poking.\n"
    "FILL IN REAL VALUES -- never copy the literal placeholder text above (not the string "
    "'confirmed|refuted|believed|blocked', not '<...>'). Example of a good FIRST action:\n"
    "  {\"action\":\"run\",\"command\":\"node -e \\\"require('/work/app').pingHost('; id')\\\"\","
    "\"why\":\"inject id; a uid= line proves it ran\"}\n"
    "and later, if you saw uid=:  {\"action\":\"conclude\",\"verdict\":\"confirmed\",\"cwe\":\"CWE-78\","
    "\"why\":\"the injected id ran\",\"evidence\":\"uid=0(root) gid=0(root)\"}"
)

_VERDICTS = {"confirmed", "refuted", "believed", "blocked", "anomalous_state"}

# --- Native tool-calling path (for a tool-tuned model behind an OpenAI-compatible API: ollama etc.) ---
# The model returns structured tool_calls instead of our text JSON; the enum on `verdict` makes parroting
# impossible. Same grounding rule, same execute() sandbox -- just the model's native interface.
_NATIVE_SYS = (
    "You are a security investigator with a real sandbox. Investigate the hypothesis by CALLING "
    "run_command to actually run code and OBSERVE the result -- never guess, never invent output. You "
    "may only conclude 'confirmed' AFTER a run_command whose output shows the effect (e.g. an injected "
    "`id` prints a uid= line, your marker appears). The target repo is mounted at /work. When you are "
    "done, call conclude. To run an exported function, require/import it (e.g. "
    "node -e \"require('/work/app').f('; id')\" or python3 -c \"import app; app.f('; id')\"). "
    "A run that fails with a MISSING dependency (ModuleNotFoundError / Cannot find module) or a refused "
    "connection is an ENVIRONMENT problem, NOT evidence the code is safe -- fix it (install the package "
    "with network 'host', e.g. `pip install <pkg>` / `npm i <pkg>`, or start the service) and re-run. "
    "If you still cannot run it AND web_search is available, do what a pentester does when they can't run the "
    "target: RESEARCH it -- web_search the dependency/API/service, web_read the docs, and reason about "
    "whether the flow is exploitable given how that library ACTUALLY behaves. Then conclude a reasoned "
    "'believed' (likely-vulnerable OR likely-safe), citing what you learned -- NOT 'blocked'. Use 'blocked' "
    "only if even research leaves it genuinely undecidable, and NEVER 'refuted'/'confirmed' without having "
    "run it (research informs a BELIEF; only an observed effect proves). Instead of re-running to re-read a "
    "big output, use grep_output(pattern) / tail_output(lines) to inspect the last run. Use verdict "
    "'anomalous_state' (not 'confirmed') when you OBSERVED a business-logic / IDOR state change that is a "
    "judgment call rather than a tool-witnessed injection. "
    "ACT, DON'T ORIENT: the relevant code is ALREADY in the task -- do NOT waste steps re-reading files "
    "with cat/sed/ls/head. Your budget is small. Your FIRST action should TEST the vulnerability (run the "
    "scaffold with a payload, or call the function with an injection) and OBSERVE the effect; then CONCLUDE. "
    "If a class cannot be proven by running one piece because it needs a live backend/service you cannot "
    "start, conclude 'blocked' promptly; if it looks vulnerable but you did not witness the effect, conclude "
    "'believed' -- do not keep exploring."
)

_RUN_TOOL = {"type": "function", "function": {
    "name": "run_command",
    "description": "Run one shell command in the sandbox; returns its stdout, stderr, and exit code.",
    "parameters": {"type": "object", "properties": {
        "command": {"type": "string", "description": "the shell command to run in the target's environment"},
        "image": {"type": "string", "description": "optional docker image, e.g. node:20-slim or python:3.12-slim"},
        "network": {"type": "string", "enum": ["none", "host"], "description": "network access (default none)"},
    }, "required": ["command"]}}}

_CONCLUDE_TOOL = {"type": "function", "function": {
    "name": "conclude",
    "description": "Give the final verdict once you have run enough to decide.",
    "parameters": {"type": "object", "properties": {
        "verdict": {"type": "string",
                    "enum": ["confirmed", "refuted", "believed", "blocked", "anomalous_state"]},
        "cwe": {"type": "string"},
        "why": {"type": "string", "description": "why, citing what you observed"},
        "evidence": {"type": "string", "description": "the concrete observed effect"},
    }, "required": ["verdict", "why"]}}}


# --- review-adopted (Stage 3): context discipline + structured error escalation helpers ---

# provisioning-failure signals: a run that fails on a MISSING dep/service must never read as `refuted`.
_PROV_SIGNALS = (
    "modulenotfounderror", "no module named", "importerror", "cannot find module", "module_not_found",
    "err_module_not_found", "econnrefused", "connection refused", "could not connect", "command not found",
    "executable file not found", "no such file or directory",
)

# a run that actually got the TARGET to execute (scaffold marker / injected effect / the fn threw / a
# sanitizer fired) -- distinguishes "refuted because safe" from "refuted because nothing ever ran".
_REAL_EXEC_MARKERS = ("WAVE_RESULT", "WAVE_RENDER_CANARY", "WAVE_OUTPUT", "WAVE_CALL_ERROR", "WAVE_LOAD_ERROR",
                      "uid=", "wave_HIT", "WAVE-PWNED",
                      "AddressSanitizer", "runtime error:", "LeakSanitizer", "SUMMARY: ")  # C/C++ ASan/UBSan


def _provision_signal(text):
    t = (text or "").lower()
    return any(s in t for s in _PROV_SIGNALS)


def _real_exec(text):
    return any(m in (text or "") for m in _REAL_EXEC_MARKERS)


def _combined(res):
    return ((res.stdout or "") + ("\n" + res.stderr if res.stderr else "")).strip()


def _digest(res, tail=20, tools=True):
    """Short model-facing digest of a run: header + the LAST `tail` lines. The FULL output stays OUT of the
    prompt -- the model pulls more with grep_output/tail_output. Replaces the blind 1200-char truncation
    that could slice off the exact proof line (wave_architecture_plan.md, Stage 3 review-adopted)."""
    head = (f"$ {res.command}\n[exit {res.exit_code}" + (" TIMED OUT" if res.timed_out else "")
            + f", {res.duration:.1f}s]")
    body = _combined(res)
    if not body:
        return head + "\n(no output)"
    lines = body.splitlines()
    if len(lines) <= tail + 8:
        return head + "\n" + body
    hint = " -- use grep_output(pattern) / tail_output(lines) for more" if tools else ""
    return (head + f"\n--- output: last {tail} of {len(lines)} lines{hint} ---\n" + "\n".join(lines[-tail:]))


def _grep(run_log, pattern, limit=10):
    if not run_log:
        return "no command has been run yet -- run_command first."
    lines = run_log.splitlines()
    try:
        rx = re.compile(pattern, re.I).search
    except re.error:
        rx = None
    hits = [f"{i + 1}: {ln}" for i, ln in enumerate(lines)
            if (rx(ln) if rx else pattern.lower() in ln.lower())]
    if not hits:
        return f"no line matches {pattern!r} in the last run ({len(lines)} lines)."
    extra = f"\n... (+{len(hits) - limit} more matches)" if len(hits) > limit else ""
    return "\n".join(hits[:limit]) + extra


def _tail(run_log, n=20):
    if not run_log:
        return "no command has been run yet -- run_command first."
    return "\n".join(run_log.splitlines()[-n:])


def _finalize(verdict, why, ran, saw_prov, saw_real):
    """The grounding rule + structured error escalation on a raw conclusion:
    - confirmed / anomalous_state need an OBSERVATION (ran>0), else -> believed.
    - a 'refuted' whose ONLY observations were provisioning failures (the target never ran cleanly) is not
      a safe verdict -> blocked (under-provisioned)."""
    if verdict not in _VERDICTS:
        verdict = "believed"
    if verdict in ("confirmed", "anomalous_state") and ran == 0:
        return "believed", f"(downgraded from {verdict}: no command was run to observe the effect) " + why
    if verdict == "refuted" and saw_prov and not saw_real:
        return "blocked", ("(under-provisioned: 'refuted' overturned -- the target never executed cleanly; "
                           "every run hit a missing dependency/service, so safety is NOT proven) " + why)
    return verdict, why


def _force_conclude(model, messages, ran, saw_prov, saw_real):
    """Out of exploration budget -> ONE final call constrained to conclude, so we get a REASONED verdict
    instead of a flat 'step budget spent'. Returns a Verdict, or None if the model still won't decide."""
    import json as _json
    msgs = messages + [{"role": "user", "content":
        "You are OUT of exploration steps -- do NOT run more commands. Call conclude NOW with your final "
        "verdict from what you already observed: 'confirmed' only if you WITNESSED the effect; 'blocked' if "
        "a proof needs a service/backend you could not start; 'believed' if it looks vulnerable but you did "
        "not prove it; 'refuted' if you saw it is safe."}]
    try:
        msg = model.chat(msgs, tools=[_CONCLUDE_TOOL], temperature=0.1)
    except Exception:
        return None
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function", {}) or {}
        if fn.get("name") != "conclude":
            continue
        raw = fn.get("arguments")
        try:
            args = raw if isinstance(raw, dict) else _json.loads(raw or "{}")
        except Exception:
            args = {}
        verdict, why = _finalize(str(args.get("verdict", "believed")).lower(), str(args.get("why", "")),
                                 ran, saw_prov, saw_real)
        return Verdict(verdict, why, str(args.get("evidence", "")), str(args.get("cwe", "")), ran, [])
    return None


_GREP_TOOL = {"type": "function", "function": {
    "name": "grep_output",
    "description": "Search the LAST command's FULL output for a substring/regex; returns matching lines. Use "
                   "this to find a marker, `uid=`, or an error in a big output instead of re-running.",
    "parameters": {"type": "object", "properties": {
        "pattern": {"type": "string", "description": "substring or regex to find in the last run's output"},
        "lines": {"type": "integer", "description": "max matching lines to return (default 10)"},
    }, "required": ["pattern"]}}}

_TAIL_TOOL = {"type": "function", "function": {
    "name": "tail_output",
    "description": "Return the last N lines of the LAST command's full output.",
    "parameters": {"type": "object", "properties": {
        "lines": {"type": "integer", "description": "how many trailing lines (default 20)"},
    }, "required": []}}}

# --- opt-in web tools (only added when online=True): the model's eyes on the world for an unfamiliar API,
# library, or third-party service (AWS, etc.) it must understand to judge a flow. Context only, never proof.
_WEB_SEARCH_TOOL = {"type": "function", "function": {
    "name": "web_search",
    "description": "Search the web for an unfamiliar API / library / framework / service you must understand "
                   "to judge this code. Returns ranked title/URL/snippet lines. Context only -- it never "
                   "proves a vuln; only a run_command observation can.",
    "parameters": {"type": "object", "properties": {
        "query": {"type": "string", "description": "the search query"},
    }, "required": ["query"]}}}

_WEB_READ_TOOL = {"type": "function", "function": {
    "name": "web_read",
    "description": "Read ONE web page deeply (clean text/markdown) -- e.g. a docs or advisory URL from "
                   "web_search -- when a snippet isn't enough to understand an API/service. Context only.",
    "parameters": {"type": "object", "properties": {
        "url": {"type": "string", "description": "the http(s) URL to read"},
    }, "required": ["url"]}}}


def _investigate_native(model, brief, *, image, mount, container, network, max_steps, step_timeout,
                        online=False):
    """Tool-calling loop over the model's NATIVE tools interface (structured tool_calls)."""
    import json as _json
    messages = [{"role": "system", "content": _NATIVE_SYS}, {"role": "user", "content": brief}]
    tools = [_RUN_TOOL, _GREP_TOOL, _TAIL_TOOL, _CONCLUDE_TOOL]
    if online:                                              # opt-in egress: the model's eyes on the world
        tools += [_WEB_SEARCH_TOOL, _WEB_READ_TOOL]
    trail, ran = [], 0
    run_log = ""                                            # the LAST run's full output (grep/tail read it)
    saw_prov = saw_real = False                             # provisioning-failure vs. real target execution
    seen_cmds = set()                                       # to nudge a model re-running the same command
    believed_nudged = False                                 # one-time: a belief must cite evidence
    for step in range(max_steps):
        try:
            msg = model.chat(messages, tools=tools, temperature=0.2)
        except Exception as e:                              # API down/500 after retries -> degrade, never crash
            print(f"[investigate:native] API error, stopping this candidate: {type(e).__name__}", flush=True)
            return Verdict("blocked", f"model API error after retries: {type(e).__name__}: {e}",
                           ran=ran, trail=trail)
        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:                                  # model answered in prose -> steer it back to tools
            messages.append({"role": "assistant", "content": msg.get("content") or ""})
            messages.append({"role": "user", "content": "Call run_command to test it, or conclude with a verdict."})
            continue
        messages.append(msg)                                # the assistant turn (carries the tool_calls)
        for tc in tool_calls:
            fn = tc.get("function", {}) or {}
            name = fn.get("name")
            raw = fn.get("arguments")                        # /v1 -> JSON string; ollama native -> dict
            try:
                args = raw if isinstance(raw, dict) else _json.loads(raw or "{}")
            except Exception:
                args = {}
            if name == "conclude":
                verdict, why = _finalize(str(args.get("verdict", "believed")).lower(),
                                         str(args.get("why", "")), ran, saw_prov, saw_real)
                evidence = str(args.get("evidence", ""))
                # a BELIEF is not a bare assertion -- it must cite evidence. One-time nudge if it doesn't.
                if (verdict == "believed" and not believed_nudged and step < max_steps - 1
                        and len((evidence + why).strip()) < 40):
                    believed_nudged = True
                    messages.append({"role": "user", "content":
                        "A 'believed' verdict must PRESENT EVIDENCE, not assert. Re-read the exact line(s) "
                        "that support it (grep_output / re-read the file), and if web_search is available and "
                        "you are unsure, research to strengthen or overturn it. Then conclude again with the "
                        "concrete evidence (a cited line / observation / source)."})
                    continue
                print(f"[investigate:native] concluded: {verdict} after {ran} run(s)", flush=True)
                return Verdict(verdict, why, evidence, str(args.get("cwe", "")), ran, trail,
                               transcript=list(messages))
            if name == "grep_output":
                content = _grep(run_log, str(args.get("pattern", "")), int(args.get("lines") or 10))
                messages.append({"role": "tool", "tool_call_id": tc.get("id"), "name": name, "content": content})
                continue
            if name == "tail_output":
                content = _tail(run_log, int(args.get("lines") or 20))
                messages.append({"role": "tool", "tool_call_id": tc.get("id"), "name": name, "content": content})
                continue
            if name in ("web_search", "web_read"):          # opt-in egress; degrades to '' on any failure
                from . import search
                if name == "web_search":
                    out = search.web_search(str(args.get("query", "")))
                else:
                    out = search.web_read(str(args.get("url", "")))
                content = out or "(no result / offline -- proceed on what you already know)"
                print(f"[investigate:native] {name} -> {len(out)} chars", flush=True)
                messages.append({"role": "tool", "tool_call_id": tc.get("id"), "name": name, "content": content})
                continue
            cmd = str(args.get("command", "")).strip()      # run_command
            res = execute(cmd, image=str(args.get("image") or image), mount=mount, container=container,
                          network=str(args.get("network") or network), timeout=step_timeout)
            ran += 1
            run_log = _combined(res)                         # full output stays here, not in the prompt
            prov = _provision_signal(run_log)
            saw_prov, saw_real = saw_prov or prov, saw_real or _real_exec(run_log)
            print(f"[investigate:native] step {step + 1}: ran {cmd[:70]!r} -> exit {res.exit_code}"
                  + (" TIMEOUT" if res.timed_out else "") + (" [prov-fail]" if prov else ""), flush=True)
            digest = _digest(res)
            if prov:                                         # escalate, never let it read as 'safe'
                digest += ("\nNOTE: this is a MISSING DEPENDENCY/SERVICE (an environment problem), NOT proof "
                           "the code is safe. Fix it -- install the package (network 'host') or start the "
                           "service, then re-run. Do NOT conclude 'refuted' from this; if you still cannot "
                           "provision, conclude 'blocked'.")
            if cmd in seen_cmds:                             # zombie loop: re-running a command already run
                digest += ("\nNOTE: you ALREADY ran this exact command -- do NOT repeat it. Stop reading; "
                           "TEST the vulnerability with a payload or CONCLUDE now.")
            seen_cmds.add(cmd)
            if max_steps - step <= 2:                        # budget almost gone -> push to finish
                digest += (f"\nNOTE: only {max_steps - step} step(s) left. Run your ONE decisive test now, "
                           "or call conclude.")
            trail.append((cmd, digest))
            messages.append({"role": "tool", "tool_call_id": tc.get("id"), "name": name, "content": digest})
    fv = _force_conclude(model, messages, ran, saw_prov, saw_real)   # budget spent -> extract a real verdict
    if fv is not None:
        fv.trail = trail
        fv.transcript = list(messages)
        print(f"[investigate:native] forced conclusion: {fv.verdict} after {ran} run(s)", flush=True)
        return fv
    verdict = "blocked" if (saw_prov and not saw_real) or ran == 0 else "believed"
    return Verdict(verdict, f"step budget ({max_steps}) spent; model would not conclude", ran=ran, trail=trail)


@dataclass
class Verdict:
    verdict: str                       # confirmed | believed | refuted | blocked | anomalous_state
    why: str
    evidence: str = ""
    cwe: str = ""
    ran: int = 0                       # how many commands were actually executed
    trail: list = field(default_factory=list)   # [(command, result_summary)]
    transcript: list = field(default_factory=list)   # the FULL model conversation (for the trace-logger)


def _parse_action(txt):
    """Pull the last {...} carrying an "action" key from an R1/Qwen reply (answer buried after <think>)."""
    txt = txt or ""
    for scope in (txt.split("</think>")[-1], txt):
        cands = re.findall(r'\{[^{}]*"action"[^{}]*\}', scope, re.S)
        for raw in reversed(cands):
            try:
                d = json.loads(raw)
                if isinstance(d, dict) and d.get("action"):
                    return d
            except Exception:
                continue
    return None


def _render(trail, limit=1500):
    if not trail:
        return "(no commands run yet)"
    out = []
    for i, (cmd, summ) in enumerate(trail, 1):
        out.append(f"--- step {i} ---\n{summ[:limit]}")
    return "\n".join(out)


def investigate(model, brief, *, image="python:3.12-slim", mount=None, container=None,
                network="none", max_steps=6, step_timeout=60, max_new_tokens=2000, online=False) -> Verdict:
    """Let the model investigate `brief` (a hypothesis + the relevant code) by running commands in a
    sandbox, until it concludes or the step budget is spent. `mount` binds the target dir into the box;
    `container` runs inside the app's own container instead. `online=True` adds the opt-in web_search /
    web_read tools (the box is otherwise fully local). A tool-calling model (WAVE_API_BASE) drives the
    NATIVE tools loop; a local text model uses the JSON-action protocol below."""
    if getattr(model, "supports_tools", False):
        return _investigate_native(model, brief, image=image, mount=mount, container=container,
                                   network=network, max_steps=max_steps, step_timeout=step_timeout,
                                   online=online)
    trail = []
    ran = 0
    saw_prov = saw_real = False                             # provisioning-failure vs. real target execution
    for step in range(max_steps):
        user = (f"HYPOTHESIS / TASK:\n{brief}\n\nWORK SO FAR:\n{_render(trail)}\n\n"
                f"Steps left: {max_steps - step}. Your next action (one json object):")
        out = model.generate(_AGENT_SYS, user, max_new_tokens=max_new_tokens, temperature=0.2)
        act = _parse_action(out)
        if not act:
            trail.append(("(no action parsed)", "the model emitted no valid json action"))
            continue
        kind = str(act.get("action", "")).lower()
        if kind == "run":
            cmd = str(act.get("command", "")).strip()
            if not cmd:
                trail.append(("(empty command)", "no command supplied"))
                continue
            res = execute(cmd, image=str(act.get("image") or image), mount=mount, container=container,
                          network=str(act.get("network") or network), timeout=step_timeout)
            ran += 1
            prov = _provision_signal(_combined(res))
            saw_prov, saw_real = saw_prov or prov, saw_real or _real_exec(_combined(res))
            print(f"[investigate] step {step + 1}: ran {cmd[:70]!r} -> exit {res.exit_code}"
                  + (" TIMEOUT" if res.timed_out else "") + (" [prov-fail]" if prov else ""), flush=True)
            summ = _digest(res, tools=False)               # head/tail digest, not a blind truncation
            if prov:                                        # missing dep/service -> escalate, never "safe"
                summ += ("\nNOTE: this is a MISSING DEPENDENCY/SERVICE (an environment problem), NOT proof "
                         "the code is safe. Install it and re-run; do NOT conclude 'refuted' -- use "
                         "'blocked' if you cannot provision.")
            # nudge a stuck model: it repeated a command it ALREADY ran (whether it failed OR succeeded --
            # a zombie loop re-running a passing command never reads its own output). Push it to move on.
            if any(pc == cmd for pc, _ps in trail):
                summ += ("\nNOTE: you already ran this EXACT command. Do NOT repeat it -- READ the output "
                         "above and either CONCLUDE now (if it proves or refutes the issue) or try a "
                         "DIFFERENT command.")
            trail.append((cmd, summ))
        elif kind == "conclude":
            verdict = str(act.get("verdict", "believed")).lower()
            why = str(act.get("why", ""))
            # reject a parroted schema/placeholder (e.g. verdict "confirmed|refuted|believed|blocked", or a
            # "<...>" why) -- an invalid verdict is not a conclusion; nudge and keep going.
            if verdict not in _VERDICTS or "<" in why or "|" in verdict:
                trail.append(("(invalid conclude)", "you copied the placeholder text instead of real "
                              "values, or gave an invalid verdict -- RUN a command and OBSERVE before "
                              "concluding, then use a real verdict (confirmed/refuted/believed/blocked)"))
                continue
            verdict, why = _finalize(verdict, why, ran, saw_prov, saw_real)   # grounding + error escalation
            print(f"[investigate] concluded: {verdict} after {ran} run(s)", flush=True)
            return Verdict(verdict, why, str(act.get("evidence", "")), str(act.get("cwe", "")), ran, trail)
        else:
            trail.append((f"(unknown action {kind!r})", "expected run or conclude"))
    verdict = "blocked" if (saw_prov and not saw_real) or ran == 0 else "believed"
    return Verdict(verdict, f"step budget ({max_steps}) spent without a conclusion", ran=ran, trail=trail)
