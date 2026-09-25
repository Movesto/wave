"""DAST escalation for the eyes->detect->prove pipeline: which UNPROVEN findings a live-app run could
witness, and how.

The static / unit-level prove stage lands `believed` or `blocked` on findings that genuinely need a RUNNING
app -- an injection behind auth against a live DB, an SSRF the sandbox can't reach, an IDOR needing two real
users. This module decides which of those to escalate to the full-app DAST oracle (provision + an instrumented
-sink injection oracle or a 2-identity differential), and whether the target can even be booted.

The DECISION (plan/bootable/dast_mode) is deterministic and unit-tested here. The EXECUTION drives docker
(provision + oracle) and is verified live when docker is free -- so a run never silently blocks on it.
"""
from __future__ import annotations

from pathlib import Path

from . import provision as prov

# a live oracle exists for these; map a finding's class/CWE to the DAST mode that can witness it
_DIFF_CWE = {"CWE-639", "CWE-284", "CWE-862", "CWE-863", "CWE-566"}
_DIFF_CLASS = {"authz", "idor", "access", "bola"}
_INJ_CLASS = {"sqli", "nosqli", "cmd", "ssrf", "path", "redirect", "xss", "ssti", "eval", "deser"}
# verdicts a live run could still turn into a real witness (a confirmed/anomalous is already settled)
_UNWITNESSED = {"believed", "blocked"}


def dast_mode(finding):
    """The live oracle that could witness this finding: 'differential' (access-control), 'injection'
    (instrumented-sink), or None (nothing a live run adds)."""
    cwe = (finding.get("cwe") or "").upper()
    cls = (finding.get("class") or "").lower()
    if cwe in _DIFF_CWE or cls in _DIFF_CLASS:
        return "differential"
    if cls in _INJ_CLASS:
        return "injection"
    return None


def bootable(target):
    """True if the repo can plausibly be stood up for DAST -- a compose file or a Dockerfile. Does NOT boot."""
    root = Path(target)
    try:
        if prov._pick_compose(str(root)):
            return True
    except Exception:
        pass
    if (root / "Dockerfile").exists():
        return True
    try:
        return bool(prov._find(str(root), ["Dockerfile"]))   # _find returns "" (not None) when absent
    except Exception:
        return False


def plan(findings, target=None, can_boot=None):
    """The escalation plan: the unproven findings a live oracle could witness, each with a mode + reason.
    Empty if the target isn't bootable (DAST needs a running app) -- the honest 'nothing to escalate'."""
    boot = can_boot if can_boot is not None else (bootable(target) if target else False)
    if not boot:
        return []
    out = []
    for f in findings:
        if f.get("verdict") not in _UNWITNESSED:
            continue
        mode = dast_mode(f)
        if mode:
            out.append({"file": f.get("file"), "line": f.get("line"), "class": f.get("class"),
                        "cwe": f.get("cwe"), "verdict": f.get("verdict"), "mode": mode,
                        "reason": f"{f.get('verdict')} statically; a live {mode} run can witness it"})
    return out


def summarize(escalations):
    """One-line-per-mode summary of a plan, for the report / CLI."""
    from collections import Counter
    if not escalations:
        return "no findings need (or a repo that supports) a live DAST run"
    by = Counter(e["mode"] for e in escalations)
    return ", ".join(f"{n} {mode}" for mode, n in by.items()) + " -> live-app run"
