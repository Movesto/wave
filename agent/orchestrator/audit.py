"""The Evidence Audit -- a final, decorrelated check on a CONFIRMED finding.

A single model cannot reliably grade its own prose (it tells itself a fluent, self-consistent, possibly wrong
story). So we do NOT ask it to. Two mechanisms, both anchored to things the model cannot fake:

  1. CORROBORATION (deterministic, cheap). For a canary-witnessed finding, re-run the exact deterministic
     proof a SECOND time -- rung1 uses a fresh random marker each call, so this is an independent second
     proof. It must fire again; a finding that does not reproduce is non-deterministic -> downgrade.
  2. FRESH-AUDITOR falsification (context asymmetry). One clean-room call, given ONLY the code slice + the
     claimed evidence (no investigation history, no sunk cost), tasked with the grounded "5-whys" rubric:
     does the evidence show an ATTACKER-EXPLOITABLE vuln, or merely that a dangerous sink RAN with a payload
     handed directly to it (mechanism, not exploitability)? It must ground each answer in the slice/evidence.

The HARNESS -- not the model -- decides: a `confirmed` survives only if the canary re-fires (when applicable)
AND the fresh auditor upholds it. Otherwise it is downgraded to `anomalous_state` (human-review). The model
does the work; the pass condition is a fact outside its control (the proof re-fired) or a decorrelated
skeptic's grounded verdict -- neither is gameable by a confident narrative.

Scope: runs ONLY on `confirmed` findings (few, high-stakes). Bounded cost: one deterministic re-run (canary
only) + one model call.
"""
from __future__ import annotations

from pathlib import Path

from . import rung1
from .detector import _parse                                # reuse the hardened reason-first JSON parser

_AUDIT_SYS = (
    "You are a senior security reviewer AUDITING a finding another analyst marked CONFIRMED. You are shown "
    "ONLY the code slice and the EVIDENCE they observed -- not their reasoning. Judge whether the evidence "
    "proves a REAL, ATTACKER-EXPLOITABLE vulnerability, NOT merely that a dangerous function executed a "
    "payload handed directly to it (that is a mechanism, true of eval/pickle/templates by nature -- not an "
    "exploit). Work through these, grounded in the slice/evidence (cite lines; never assume): "
    "(1) What OBSERVED effect proves it? (2) What UNTRUSTED input reaches the sink and by what path -- is it "
    "actually attacker-controlled, or internal/server-supplied (a DB value, a constant, config)? (3) Could "
    "this same evidence appear for a NON-vulnerable case? (4) What is the strongest reason it is NOT "
    "exploitable? "
    "Write `reason` FIRST (your grounded analysis), then `verdict` LAST as the conclusion that follows. "
    "Output ONE JSON object: {\"reason\": \"...\", \"verdict\": \"upheld\"|\"downgrade\"}. "
    "\"upheld\" = the evidence shows attacker-controlled input reaching the sink (a real exploit). "
    "\"downgrade\" = the evidence only shows the dangerous mechanism / the input is not shown to be "
    "attacker-controlled -> needs human review. Be skeptical; do NOT uphold on assumption.")


def _slice(path, line, pad=30):
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    a = max(0, line - 1 - pad)
    b = min(len(lines), line + pad)
    return "\n".join(f"{a + i + 1}: {ln}" for i, ln in enumerate(lines[a:b]))


def audit(model, c, rec):
    """Audit ONE confirmed finding. Returns (verdict, note): 'confirmed' (upheld) or 'anomalous_state'
    (downgraded to human-review). Never raises -- any failure UPHOLDS (a glitch must not silently clear a
    real confirmation)."""
    # 1. corroboration -- re-run the deterministic canary; it must reproduce (fresh marker = independent).
    if str(rec.get("oracle", "")).startswith("rung1") and getattr(c, "provable", False):
        try:
            mr = rung1.micro_exec(c, rt=None)
        except Exception:
            mr = None
        if mr is not None and mr.verdict != "proven":
            return "anomalous_state", (f"[audit] the canary did NOT reproduce on an independent re-run "
                                       f"({mr.verdict}: {mr.reason[:80]}) -- non-deterministic; human review.")

    # 2. fresh-auditor falsification -- one decorrelated clean-room call on slice + claimed evidence.
    if model is None:
        return "confirmed", "[audit] corroborated (no model for the clean-room pass)"
    code = _slice(getattr(c, "file", ""), int(getattr(c, "line", 0) or 0))
    if not code.strip():
        return "confirmed", "[audit] upheld (could not read the slice for the clean-room pass)"
    user = (f"CLAIM: confirmed {c.cwe} at line {c.line}. sink: {c.sink}.\n\n"
            f"EVIDENCE the analyst observed:\n{(rec.get('evidence') or rec.get('why') or '(none given)')[:600]}\n\n"
            f"CODE:\n{code}\n\nAudit this finding.")
    try:
        txt = model.generate(_AUDIT_SYS, user, max_new_tokens=1400, temperature=0.1, think=False,
                             json_mode=True)
    except Exception as e:
        return "confirmed", f"[audit] upheld (auditor call failed: {type(e).__name__})"
    d = _parse(txt)
    if str(d.get("verdict", "")).lower() == "downgrade":
        return "anomalous_state", f"[audit] fresh auditor could not confirm exploitability: {str(d.get('reason', ''))[:220]}"
    return "confirmed", "[audit] upheld by the fresh clean-room auditor"
