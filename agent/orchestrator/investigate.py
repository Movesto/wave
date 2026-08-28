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
    '  finish:        {"action":"conclude","verdict":"confirmed|refuted|believed|blocked","cwe":"CWE-XX",'
    '"why":"<why, citing what you OBSERVED>","evidence":"<the concrete observed effect>"}\n'
    "RULES: (1) You may only CONFIRM after you have RUN something and OBSERVED the effect that proves it; "
    "reasoning alone is 'believed', never 'confirmed'. (2) 'refuted' means you ran it and saw it is safe. "
    "(3) 'blocked' means you could not run what you needed. (4) Keep commands self-contained; the target's "
    "code is under the working directory. Keep any reasoning BRIEF, then output ONLY the json object."
)


@dataclass
class Verdict:
    verdict: str                       # confirmed | believed | refuted | blocked
    why: str
    evidence: str = ""
    cwe: str = ""
    ran: int = 0                       # how many commands were actually executed
    trail: list = field(default_factory=list)   # [(command, result_summary)]


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
                network="none", max_steps=6, step_timeout=60, max_new_tokens=2000) -> Verdict:
    """Let the model investigate `brief` (a hypothesis + the relevant code) by running commands in a
    sandbox, until it concludes or the step budget is spent. `mount` binds the target dir into the box;
    `container` runs inside the app's own container instead."""
    trail = []
    ran = 0
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
            print(f"[investigate] step {step + 1}: ran {cmd[:70]!r} -> exit {res.exit_code}"
                  + (" TIMEOUT" if res.timed_out else ""), flush=True)
            trail.append((cmd, res.summary()))
        elif kind == "conclude":
            verdict = str(act.get("verdict", "believed")).lower()
            why = str(act.get("why", ""))
            if verdict == "confirmed" and ran == 0:        # GROUNDING RULE: no observation -> can't confirm
                verdict = "believed"
                why = "(downgraded from confirmed: no command was ever run to observe the effect) " + why
            print(f"[investigate] concluded: {verdict} after {ran} run(s)", flush=True)
            return Verdict(verdict, why, str(act.get("evidence", "")), str(act.get("cwe", "")), ran, trail)
        else:
            trail.append((f"(unknown action {kind!r})", "expected run or conclude"))
    return Verdict("blocked", f"step budget ({max_steps}) spent without a conclusion", ran=ran, trail=trail)
