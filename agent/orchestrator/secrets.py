"""Secret scanning in git HISTORY -- credentials that were committed and later removed are still in the log
and accessible to anyone who clones the repo.

Deterministic (no model). Runs `git log -p` over all refs and scans ADDED lines for high-signal secret
patterns (cloud keys, private-key blocks, provider tokens, credentials in URLs, and secret-ish assignments).
Matches are REDACTED in the report. Needs `git` + a git repo; degrades to [] otherwise. For deeper coverage
integrate trufflehog/gitleaks -- this is the zero-dependency built-in.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

# name -> (regex, severity). High-precision provider patterns first; the generic assignment is lower-severity.
_PATTERNS = [
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}"), "high"),
    ("GitHub token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}|github_pat_[0-9A-Za-z_]{40,}"), "high"),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "high"),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "high"),
    ("Stripe secret key", re.compile(r"sk_live_[0-9A-Za-z]{24,}"), "high"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "high"),
    ("Credentials in URL", re.compile(r"[a-zA-Z][\w+.\-]*://[^:@/\s]+:[^@/\s]{3,}@"), "high"),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "medium"),
]
# secret-ish assignment: <optional-prefix>KEY = "value" (>=8 chars) -- catches db_password, my_secret, etc.
_ASSIGN = re.compile(r"""(?ix)([\w.\-]{0,20}(?:password|passwd|secret|api[_-]?key|apikey|access[_-]?key|
                         auth[_-]?token|client[_-]?secret|private[_-]?key))\s*[:=]\s*['"]([^'"]{8,})['"]""", re.X)
_PLACEHOLDER = re.compile(r"(?i)example|changeme|change_me|your[_-]?|placeholder|dummy|test|xxxx|redacted|"
                          r"\$\{|process\.env|os\.environ|getenv|<[^>]+>|\bnull\b|\bnone\b|\*{3,}")


def _redact(s):
    s = s.strip()
    return (s[:4] + "…" + f"({len(s)} chars)") if len(s) > 8 else "(redacted)"


def scan_diff(diff_text):
    """Scan `git log -p` output for secrets in ADDED lines. Returns findings (commit/file/type/redacted).
    Pure/testable -- no git needed."""
    out, seen = [], set()
    commit, path = "", ""
    for line in diff_text.splitlines():
        if line.startswith("commit "):
            commit = line.split()[1][:10]
            continue
        if line.startswith("+++ b/"):
            path = line[6:].strip()
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        added = line[1:]
        for name, rx, sev in _PATTERNS:
            m = rx.search(added)
            if m:
                if "EXAMPLE" in m.group(0).upper():           # AWS's canonical AKIA...EXAMPLE etc. -- not real
                    continue
                key = (name, commit, path, m.group(0)[:12])
                if key not in seen:
                    seen.add(key)
                    out.append({"type": name, "severity": sev, "commit": commit, "file": path,
                                "match": _redact(m.group(0))})
        am = _ASSIGN.search(added)
        if am and not _PLACEHOLDER.search(am.group(2)):
            key = ("assign:" + am.group(1).lower(), commit, path, am.group(2)[:12])
            if key not in seen:
                seen.add(key)
                out.append({"type": f"hardcoded {am.group(1).lower()}", "severity": "medium",
                            "commit": commit, "file": path, "match": _redact(am.group(2))})
    return out


def scan(target, max_commits=3000, timeout=120):
    """Scan the repo's git history for committed secrets. Needs git + a repo; else []."""
    target = str(target)
    if not shutil.which("git") or not (Path(target) / ".git").exists():
        return []
    try:
        p = subprocess.run(
            ["git", "-C", target, "log", "--all", "-p", "-U0", "--no-color", f"--max-count={max_commits}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    except (subprocess.SubprocessError, OSError):
        return []
    return scan_diff(p.stdout or "")


def render(findings):
    if not findings:
        return "## Secrets in git history\n\nNo secrets found in git history.\n"
    lines = [f"## Secrets in git history  ({len(findings)})", "",
             "Credentials committed at some point (still in the log even if later removed). "
             "**Rotate every exposed credential** -- deleting the file does not un-expose it.", ""]
    for f in findings:
        loc = f"{f['file']}@{f['commit']}" if f["file"] else f["commit"]
        lines.append(f"- **{f['type']}** _[{f['severity']}]_ — {loc}: `{f['match']}`")
    return "\n".join(lines) + "\n"
