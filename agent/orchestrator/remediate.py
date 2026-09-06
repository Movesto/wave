"""Remediation + dual-gate.

The model TRANSLATES a fix (rewrites the vulnerable function); deterministic gates PROVE it:
  Gate A  the exact exploit is re-fired at the rebuilt app -- the payload must no longer reach the
          sink unneutralized (verified AT THE SINK, not just via HTTP status).
  Gate B  a benign request to the same route still works (functional regression; smoke where the
          target has no native suite, e.g. VAmPI -- Phase-0 finding F5).
Prove-first: a weak/overfitting model patch is caught by Gate A/B, so the loop can't ship a false
"fixed". The target's source is restored afterwards (gate checks are transient).
"""
import urllib.parse
from pathlib import Path

from . import provision as prov
from . import oracle, exploit
from .model import code_block

_SYSTEM = (
    "You are a security engineer. You are given ONE function that contains a confirmed vulnerability. "
    "Rewrite ONLY this function to fix the vulnerability while preserving its exact signature and "
    "normal behavior (same inputs -> same legitimate outputs). Use parameterized queries / proper "
    "validation / safe APIs as appropriate. Output the full fixed function in a single fenced code "
    "block and nothing else.")


def gen_patch(model, candidate, finding):
    user = (f"Vulnerability: {candidate.cwe}. A probe payload reached the sink unneutralized:\n"
            f"  {finding.evidence}\n\nFix this function:\n```\n{candidate.slice}\n```")
    # reasoning model: give it room to finish thinking AND emit the fenced code (short fn, but R1 rambles)
    return code_block(model.generate(_SYSTEM, user, max_new_tokens=2800))


def _reindent(src, target_base):
    """Shift every line of `src` so its first line sits at `target_base` columns (the model often
    emits a function at column 0; the slice it replaces may be an indented class method)."""
    lines = src.splitlines()
    if not lines:
        return src
    cur = len(lines[0]) - len(lines[0].lstrip())
    delta = target_base - cur
    if delta == 0:
        return src
    out = []
    for l in lines:
        if not l.strip():
            out.append(l)
        elif delta > 0:
            out.append(" " * delta + l)
        else:
            drop = min(-delta, len(l) - len(l.lstrip()))
            out.append(l[drop:])
    return "\n".join(out)


def _apply(candidate, new_src):
    code = Path(candidate.file).read_text(encoding="utf-8", errors="replace")
    if not candidate.slice or candidate.slice not in code:
        return None
    first = candidate.slice.splitlines()[0]
    base = len(first) - len(first.lstrip())
    new_src = _reindent(new_src, base)                 # match the slice's indentation
    Path(candidate.file).write_text(code.replace(candidate.slice, new_src, 1), encoding="utf-8")
    return code   # original, for restore


def _gate_b(rt, finding, auth=None):
    """Differential regression: the patch regressed iff a benign version of the PROVEN request that
    the ORIGINAL app served is now broken. (VAmPI without /createdb 500s on ANY query -- both original
    and patched -- so that is not a regression; only a patch that makes a working request worse counts.)"""
    base = finding.baseline_status
    patched = oracle.benign_status(rt, finding.proven_request, auth=auth)
    if patched is None:
        return (base is None), f"benign {base}->unreachable"
    if patched >= 500 and (base is not None and base < 500):
        return False, f"benign {base}->{patched} (patch broke a working request)"
    return True, f"benign {base}->{patched}"


def remediate(target, candidate, finding, model, routes, hooks, host_port=None):
    """Generate a patch, rebuild, and run the dual gate. Restores the original source afterwards."""
    patch = gen_patch(model, candidate, finding)
    if not patch:
        return {"status": "no-patch", "notes": "model produced no code block"}

    original = _apply(candidate, patch)
    if original is None:
        return {"status": "apply-failed", "patch": patch,
                "notes": "could not locate the function slice in the file"}
    try:
        rt = prov.provision(target, host_port=host_port)
        try:
            if not rt.healthy:
                # the patch didn't even boot -> it broke the app; gates are meaningless. REJECT.
                # (a down app fakes a "blocked" exploit + a "passing" smoke -- must not read as fixed)
                return {"status": "patch-rejected", "patch": patch,
                        "gate_a": "app-down", "gate_b": "app-down",
                        "gate_b_note": "patched app failed to boot"}
            from . import auth as auth_mod
            auth = auth_mod.synthesize(rt, routes)          # fresh session for the rebuilt app
            gate_a_v = oracle.prove_injection(rt, hooks, candidate, routes, model, auth=auth)
            gate_a = "blocked" if gate_a_v.get("status") != "proven" else "STILL-VULNERABLE"
            ok_b, gate_b_note = _gate_b(rt, finding, auth=auth)
            gate_b = "pass" if ok_b else "regressed"
        finally:
            rt.down()
    finally:
        Path(candidate.file).write_text(original, encoding="utf-8")   # restore vulnerable source

    fixed = (gate_a == "blocked" and gate_b == "pass")
    return {"status": "fixed" if fixed else "patch-rejected",
            "patch": patch, "gate_a": gate_a, "gate_b": gate_b, "gate_b_note": gate_b_note}
