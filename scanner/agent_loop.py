"""The inference-time AGENTIC loop: the reasoner DRIVES tools to resolve a (possibly cross-file)
vulnerability it was never trained on -- reason -> {retrieve, witness, prove_safe} -> re-reason ->
verdict + fix -> VERIFY the fix. This is the piece that carries the model to complex vulns via
tools, not memory: when the sink is in a file it can't see, it asks for it and continues.

Composes existing deterministic tools:
  retrieve(symbol)   -> scanner.local_retrieve.resolve_local  (pull an unseen def from the project)
  witness(kind)      -> guard_witness.witness_scan            (prove a guard bypassable)
  prove_safe(kind)   -> safe_veto.prove_safe_ev               (prove a guard sufficient)

The model call is injected as `gen_fn(messages)->str`, so the loop is testable with a stub and runs
in production with the full reasoner (Qwen3.5-9B via scanner.full_model).
"""
import os, re, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guard_witness import witness_scan
from safe_veto import prove_safe_ev
from scanner.local_retrieve import resolve_local

CWE2KIND = {"CWE-22": "path", "CWE-23": "path", "CWE-59": "path", "CWE-78": "command",
            "CWE-77": "command", "CWE-89": "sql", "CWE-918": "ssrf", "CWE-1321": "proto",
            "CWE-601": "redirect", "CWE-79": "xss"}

SYSTEM = """You are a senior security engineer deciding whether ONE function is vulnerable. You may
not have the whole story in front of you -- the sink or a helper may live in another file. Rather
than guess, use the tools.

TOOLS (write a call on its own line, then STOP and wait for the result):
  TOOL: retrieve(<symbol>)   -- fetch the definition of a function/helper you need but cannot see.
  TOOL: witness(<kind>)      -- prove whether a guard is bypassable. kind: path|command|ssrf|proto|
                                redirect|xss. Returns a concrete bypass input if insufficient.
  TOOL: prove_safe(<kind>)   -- prove a guard is sufficient (same kinds).

Reason step by step about untrusted input, the sink, and any guard. If the deciding code is not in
view, RETRIEVE it -- do not conclude on what you cannot see. When you are certain, output exactly:
  VERDICT: vulnerable | safe | unsure
  VULN_LINE: <the vulnerable line, or 'none'>
  FIX: <the corrected code, or 'none'>
  WHY: <one sentence on why the fix closes the specific flaw>"""

_TOOL = re.compile(r"TOOL:\s*(retrieve|witness|prove_safe)\s*\(\s*([^)\n]*?)\s*\)", re.I)
_VERDICT = re.compile(r"VERDICT:\s*(vulnerable|vuln|safe|unsure)", re.I)


def _kind_of(cwe):
    return CWE2KIND.get((cwe or "").upper())


def run_tool(name, arg, ctx):
    """Run one tool. ctx carries the accumulated code seen, project_root, current_file, cwe."""
    name = name.lower()
    if name == "retrieve":
        hit = resolve_local(ctx.get("project_root") or ".", arg,
                            exclude_path=ctx.get("current_file"))
        if not hit:
            return f"retrieve({arg}): not found in the project."
        ctx["code_seen"] += "\n\n// " + hit["path"] + "\n" + hit["snippet"]   # widen what tools see
        ctx.setdefault("retrieved", {})[arg] = hit["path"]
        return f"retrieve({arg}) -> from {hit['path']}:\n{hit['snippet']}"
    kind = arg.lower() if arg.lower() in (
        "path", "command", "ssrf", "proto", "redirect", "xss", "sql") else _kind_of(ctx.get("cwe"))
    if not kind:
        return f"{name}({arg}): no witness battery for that kind."
    if name == "witness":
        w = witness_scan(ctx["code_seen"], kind)
        return (f"witness({kind}): INSUFFICIENT -- input {w['bypass']!r} defeats guard "
                f"`{w['guard']}` ({w['why']})") if w else \
               f"witness({kind}): no bypass proven (guard not a recognised-insufficient shape)."
    if name == "prove_safe":
        ev = prove_safe_ev(ctx["code_seen"], kind)
        return (f"prove_safe({kind}): SUFFICIENT -- {ev[0]} (evidence: {ev[1]})") if ev else \
               f"prove_safe({kind}): could not prove sufficient."
    return f"unknown tool {name}"


def _verify_fix(fix_code, cwe):
    """Close the loop: run the witness on the FIXED code. If the bypass is gone, the fix holds."""
    kind = _kind_of(cwe)
    if not kind or not fix_code or fix_code.strip().lower() == "none":
        return None
    try:
        still = witness_scan(fix_code, kind)
    except Exception:
        return None
    return "fix-verified (witness finds no bypass)" if not still else \
           f"fix-INCOMPLETE (witness still bypasses: {still['bypass']!r})"


def run_agent(gen_fn, code, cwe=None, project_root=None, current_file=None,
              max_turns=4, log=None):
    """Drive the loop. gen_fn(messages)->str is the model call. Returns a structured result."""
    ctx = {"code_seen": code, "project_root": project_root,
           "current_file": current_file, "cwe": cwe}
    msgs = [{"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"```\n{code}\n```"
             + (f"\n(suspected class: {cwe})" if cwe else "")}]
    final = ""
    for turn in range(max_turns):
        r = gen_fn(msgs)
        if log:
            log(f"--- turn {turn+1} ---\n{r}")
        msgs.append({"role": "assistant", "content": r})
        m = _TOOL.search(r)
        if m and not _VERDICT.search(r):          # a tool call and no final yet -> run it, continue
            res = run_tool(m.group(1), m.group(2), ctx)
            if log:
                log(f"--- tool: {m.group(1)}({m.group(2)}) ---\n{res}")
            msgs.append({"role": "user", "content": res + "\n\nContinue."})
            continue
        final = r
        break

    vm = _VERDICT.search(final)
    vraw = (vm.group(1).lower() if vm else "unsure")
    verdict = "vuln" if vraw.startswith("vuln") else ("safe" if vraw == "safe" else "unsure")
    fixm = re.search(r"FIX:\s*(.+?)(?:\nWHY:|\Z)", final, re.S)
    fix = fixm.group(1).strip() if fixm else None
    return {"verdict": verdict, "fix": fix,
            "retrieved": ctx.get("retrieved", {}),
            "turns": turn + 1,
            "fix_check": _verify_fix(fix, cwe) if verdict == "vuln" else None,
            "final": final}
