"""Config / infrastructure-as-code scanning -- known-dangerous patterns in Dockerfiles, Compose files, and
GitHub Actions workflows.

Deterministic (no model): these are pattern-matching problems. Covers the common, high-signal, low-FP issues:
  Dockerfile      -- runs as root, `ADD <url>`, `curl|sh`, baked-in secrets.
  docker-compose  -- privileged, host network, a database port exposed to the host, secrets in environment.
  GitHub Actions  -- pull_request_target with an untrusted checkout, `${{ github.event.* }}` in a run block
                     (script injection), write-all permissions.
Findings are review-tier advisories (like controls.py). For broader IaC coverage integrate Checkov/Trivy.
"""
from __future__ import annotations

import re
from pathlib import Path

_SKIP = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "vendor", "target", ".next"}
_SECRET_KEY = re.compile(r"(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)", re.I)
_DB_PORTS = {"5432": "postgres", "3306": "mysql", "27017": "mongodb", "6379": "redis", "9200": "elasticsearch",
             "5984": "couchdb", "11211": "memcached", "1433": "mssql", "3389": "rdp"}


def _iter(target, match):
    p = Path(target)
    files = [p] if p.is_file() else [f for f in p.rglob("*")
                                     if f.is_file() and not any(s in f.parts for s in _SKIP)]
    return [f for f in files if match(f)]


def _f(kind, file, line, title, detail, sev, fix):
    return {"kind": kind, "file": str(file), "line": line, "title": title, "detail": detail,
            "severity": sev, "fix": fix}


# ---- Dockerfile -------------------------------------------------------------------------------------------

def _is_dockerfile(f):
    n = f.name.lower()
    return n == "dockerfile" or n.startswith("dockerfile.") or n.endswith(".dockerfile")


def _scan_dockerfile(f, lines):
    out, last_user = [], None
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        low = s.lower()
        if low.startswith("user "):
            last_user = s.split(None, 1)[1].strip()
        if re.match(r"(?i)add\s+https?://", s):
            out.append(_f("dockerfile", f, i, "Dockerfile ADD with a remote URL",
                          f"{s[:100]}", "low", "Use COPY for local files; fetch+verify remote content explicitly."))
        if re.search(r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash)", s):
            out.append(_f("dockerfile", f, i, "Pipe-to-shell install (curl|sh)",
                          f"{s[:100]}", "medium", "Download, checksum-verify, then execute -- never pipe network to a shell."))
        if s.upper().startswith(("ENV ", "ARG ")) and _SECRET_KEY.search(s) and "=" in s and \
                not re.search(r"=\s*($|[\"']?\s*$)", s):
            out.append(_f("dockerfile", f, i, "Possible secret baked into the image",
                          f"{s[:100]}", "high", "Pass secrets at runtime (env/secret mounts), never bake them into layers."))
    if last_user is None or last_user.split(":")[0] in ("root", "0"):
        out.append(_f("dockerfile", f, 1, "Container runs as root",
                      "no non-root USER instruction (or USER root)" if last_user is None else f"USER {last_user}",
                      "medium", "Add a non-root `USER` before the entrypoint."))
    return out


# ---- docker-compose ---------------------------------------------------------------------------------------

def _is_compose(f):
    n = f.name.lower()
    return (n.startswith("docker-compose") or n.startswith("compose")) and n.endswith((".yml", ".yaml"))


def _scan_compose(f, lines):
    out = []
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        low = s.lower()
        if re.match(r"privileged:\s*true", low):
            out.append(_f("compose", f, i, "Privileged container", s[:80], "high",
                          "Drop `privileged: true`; grant only the specific capabilities needed."))
        if re.match(r"network_mode:\s*[\"']?host", low):
            out.append(_f("compose", f, i, "Host network mode", s[:80], "medium",
                          "Avoid `network_mode: host`; use a bridge network and publish only needed ports."))
        m = re.search(r'["\']?(\d{2,5}):(\d{2,5})["\']?', s)
        if m and low.lstrip().startswith("-") and (m.group(1) in _DB_PORTS or m.group(2) in _DB_PORTS):
            svc = _DB_PORTS.get(m.group(1)) or _DB_PORTS.get(m.group(2))
            out.append(_f("compose", f, i, f"Database port exposed to the host ({svc})", s[:80], "medium",
                          "Don't publish DB ports to the host; reach the DB over the internal compose network."))
        if _SECRET_KEY.search(s) and re.search(r":\s*[\"']?[^\s${}\"']{6,}", s) and "environment" not in low:
            out.append(_f("compose", f, i, "Hardcoded secret in environment", s[:80], "high",
                          "Use an env file / secrets, not a literal value in the compose file."))
    return out


# ---- GitHub Actions ---------------------------------------------------------------------------------------

def _is_gh_action(f):
    parts = [p.lower() for p in f.parts]
    return ".github" in parts and "workflows" in parts and f.suffix.lower() in (".yml", ".yaml")


def _scan_gh_action(f, lines):
    out = []
    text = "\n".join(lines).lower()
    pr_target = "pull_request_target" in text
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        low = s.lower()
        if pr_target and re.search(r"uses:\s*actions/checkout", low) and \
                re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request", "\n".join(lines[i - 1:i + 3]).lower()):
            out.append(_f("gh-actions", f, i, "pull_request_target checks out untrusted PR code",
                          s[:90], "high",
                          "pull_request_target runs with repo secrets; checking out+building the PR head lets a "
                          "fork run code with those secrets. Use pull_request, or don't build untrusted refs."))
        if re.search(r"\$\{\{\s*github\.event\.[\w.]*(title|body|head_ref|comment|issue|pull_request)", low) and \
                ("run:" in low or _in_run_block(lines, i - 1)):
            out.append(_f("gh-actions", f, i, "Untrusted github.event value in a run: block (script injection)",
                          s[:90], "high",
                          "github.event.* (title/body/branch) is attacker-controlled; interpolating it into `run:` "
                          "is shell injection. Pass it via an env: var and reference \"$VAR\" instead."))
        if re.search(r"permissions:\s*write-all", low):
            out.append(_f("gh-actions", f, i, "Workflow granted write-all permissions", s[:80], "medium",
                          "Set least-privilege `permissions:` per job instead of write-all."))
    return out


def _in_run_block(lines, idx):
    """True if line idx sits inside a `run: |` block (walk back to the nearest key at lower indent)."""
    if idx < 0 or idx >= len(lines):
        return False
    indent = len(lines[idx]) - len(lines[idx].lstrip())
    for j in range(idx - 1, max(-1, idx - 12), -1):
        ln = lines[j]
        if not ln.strip():
            continue
        ji = len(ln) - len(ln.lstrip())
        if ji < indent and re.match(r"\s*run:\s*[|>]?", ln):
            return True
        if ji < indent:
            return False
    return False


def scan(target):
    """Deterministic IaC/config advisories. Returns a list of finding dicts."""
    out = []
    for f, scanner in ((_is_dockerfile, _scan_dockerfile), (_is_compose, _scan_compose),
                       (_is_gh_action, _scan_gh_action)):
        for path in _iter(target, f):
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            try:
                out += scanner(path, lines)
            except Exception:
                continue
    return out


def render(findings):
    if not findings:
        return "## Config / infrastructure issues\n\nNo IaC/config advisories.\n"
    lines = [f"## Config / infrastructure issues  ({len(findings)})", "",
             "Dangerous patterns in Dockerfiles / Compose / GitHub Actions (deterministic, review-tier).", ""]
    for f in findings:
        loc = f"{Path(f['file']).name}:{f['line']}"
        lines.append(f"- **[{f['kind']}]** {f['title']}  _[{f['severity']}]_ — {loc}")
        lines.append(f"  - {f['detail']}")
        lines.append(f"  - fix: {f['fix']}")
    return "\n".join(lines) + "\n"
