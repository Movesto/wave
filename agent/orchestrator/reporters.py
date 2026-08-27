"""Phase 6 of the investigation loop: specialized REPORTERS -- extra evidence sources that feed the
Case File, general to ANY project (no framework/stack assumptions).

The dependency-vulnerability reporter is external intel: it audits the project's DECLARED dependencies
against the advisory database (pip-audit for Python, npm audit for Node). A known-vulnerable version is
a CONFIRMED finding -- the advisory DB is the deterministic oracle, so this is Tier-1-grade, not a
hypothesis. It is static (reads the manifest), so it works even on an app that never boots.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

_SKIP = {"node_modules", "site-packages", ".git", "venv", ".venv", "__pycache__"}


def _find(target, name):
    p = Path(target)
    if p.is_dir():
        direct = p / name
        if direct.exists():
            return direct
        for f in p.rglob(name):
            if not any(s in f.parts for s in _SKIP):
                return f
    return None


def _pip_audit(req):
    try:
        r = subprocess.run(["python", "-m", "pip_audit", "-r", str(req), "--format", "json",
                            "--progress-spinner", "off"], capture_output=True, text=True, timeout=180)
    except Exception:
        return []
    try:
        data = json.loads(r.stdout or "{}")
    except Exception:
        return []
    out = []
    for dep in data.get("dependencies", []):
        for v in dep.get("vulns", []):
            out.append({"package": dep.get("name"), "version": dep.get("version"), "id": v.get("id"),
                        "fix": ", ".join(v.get("fix_versions") or []) or "?",
                        "desc": (v.get("description") or "").replace("\n", " ")[:180], "ecosystem": "pypi"})
    return out


def _npm_audit(pkg_dir):
    try:
        r = subprocess.run(["npm", "audit", "--json"], cwd=str(pkg_dir),
                           capture_output=True, text=True, timeout=180)
    except Exception:
        return []
    try:
        data = json.loads(r.stdout or "{}")
    except Exception:
        return []
    out = []
    for name, v in (data.get("vulnerabilities") or {}).items():
        via = v.get("via") or []
        adv = next((x for x in via if isinstance(x, dict)), {})
        out.append({"package": name, "version": str(v.get("range", "")), "id": adv.get("url") or adv.get("source") or "GHSA",
                    "fix": "update" if v.get("fixAvailable") else "?",
                    "desc": (adv.get("title") or f"{v.get('severity', '')} severity")[:180], "ecosystem": "npm"})
    return out


def dependency_audit(target):
    """Confirmed dependency-vulnerability findings for the project (pip-audit + npm audit; best-effort)."""
    findings = []
    req = _find(target, "requirements.txt")
    if req:
        findings += _pip_audit(req)
    pkg = _find(target, "package.json")
    if pkg:
        findings += _npm_audit(pkg.parent)
    return findings
