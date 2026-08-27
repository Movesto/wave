"""Phase 6 of the investigation loop: specialized REPORTERS -- extra evidence sources that feed the
Case File, general to ANY project (no framework/stack assumptions).

The dependency-vulnerability reporter is external intel: it audits the project's DECLARED dependencies
against the advisory database (pip-audit for Python, npm audit for Node). A known-vulnerable version is
a CONFIRMED finding -- the advisory DB is the deterministic oracle, so this is Tier-1-grade, not a
hypothesis. It is static (reads the manifest), so it works even on an app that never boots.
"""
from __future__ import annotations

import json
import math
import re
import subprocess
from collections import Counter
from pathlib import Path

_SKIP = {"node_modules", "site-packages", ".git", "venv", ".venv", "__pycache__", "dist", "build"}


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


# ---- Secret scanner: hardcoded credentials in source (CWE-798) -- offline, general to any project ----
# A matched KNOWN key format is a confident finding (confirmed); a generic secret-shaped assignment is
# a believed lead (needs confirm -- it may be a placeholder). Placeholders and low-entropy values drop.
_SECRET_RULES = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), True),
    ("github-token", re.compile(r"\bghp_[0-9A-Za-z]{36}\b"), True),
    ("github-pat", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{60,}\b"), True),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), True),
    ("stripe-live-key", re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"), True),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), True),
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"), True),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), True),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}"), False),
    ("generic-secret", re.compile(
        r"(?i)\b(passwd|password|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|token)\b"
        r"\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"), False),
]
_PLACEHOLDER = re.compile(
    r"(?i)getenv|environ|process\.env|\$\{|\{\{|<[^>]{2,}>|change[_-]?me|example|your[_-]|xxxx|"
    r"placeholder|dummy|\bsample\b|\bnull\b|\bnone\b|redacted|\*\*\*|template|test[_-]?key|f['\"]")
_SECRET_EXTS = {".py", ".js", ".ts", ".mjs", ".env", ".yml", ".yaml", ".json", ".properties", ".cfg",
                ".ini", ".conf", ".toml", ".sh", ".xml", ".txt"}
_KNOWN_EXAMPLES = {"AKIAIOSFODNN7EXAMPLE"}


def _entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def _iter_src(target, budget=500):
    p = Path(target)
    n = 0
    for f in ([p] if p.is_file() else p.rglob("*")):
        if n >= budget:
            break
        if not f.is_file() or any(s in f.parts for s in _SKIP):
            continue
        if f.suffix.lower() in _SECRET_EXTS or f.name.startswith(".env"):
            n += 1
            yield f


def secret_scan(target):
    """Hardcoded-credential findings (CWE-798). Known key formats -> confirmed; generic secret-shaped
    assignments -> believed (needs confirm). Offline + deterministic."""
    out = []
    for f in _iter_src(target):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if len(line) > 400:
                continue
            for name, rx, strong in _SECRET_RULES:
                m = rx.search(line)
                if not m:
                    continue
                val = m.group(m.lastindex) if (m.lastindex and m.lastindex >= 2) else m.group(0)
                if val in _KNOWN_EXAMPLES:
                    continue
                if not strong:                          # generic / jwt -> drop placeholders + low entropy
                    if _PLACEHOLDER.search(line) or _entropy(val) < 3.2:
                        continue
                out.append({"file": str(f), "line": i, "type": name,
                            "status": "confirmed" if strong else "believed",
                            "snippet": line.strip()[:110]})
                break                                   # one finding per line
    return out
