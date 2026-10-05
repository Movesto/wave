"""Dependency vulnerability scanning -- known CVEs in third-party packages, via the OSV.dev API.

Deterministic (no model, no external CLI tools). Parses manifest/lock files for (package, version), queries
the OSV.dev batch API (covers PyPI / npm / crates.io / Go / RubyGems / Packagist / ...), and reports known
advisories with severity + the fixed version. Needs network egress to OSV.dev, so the caller gates it
(`online`). Network/parse failures degrade to an empty result -- never crash a scan.

The most common attack vector in the real world is a vulnerable dependency, not first-party code; every
commercial SAST tool reports these. This closes that gap using an authoritative, current source (OSV, run by
Google) with zero first-party rules to maintain.
"""
from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path

_OSV_BATCH = "https://api.osv.dev/v1/querybatch"
_OSV_VULN = "https://api.osv.dev/v1/vulns/"
_SKIP = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "vendor", "target", ".next"}


# ---- lock/manifest parsers (name, version) ----------------------------------------------------------------

def _parse_requirements(text):
    out = []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([0-9][^\s;,]*)", line)   # only EXACT pins (== a version)
        if m:
            out.append((m.group(1).lower().replace("_", "-"), m.group(2)))
    return out


def _parse_package_lock(text):
    out = []
    try:
        d = json.loads(text)
    except Exception:
        return out
    pkgs = d.get("packages")
    if isinstance(pkgs, dict):                                  # lockfile v2 / v3
        for path, info in pkgs.items():
            if not path or not isinstance(info, dict):          # "" is the root package
                continue
            name = path.split("node_modules/")[-1]
            ver = info.get("version")
            if name and ver:
                out.append((name, ver))
    if not out and isinstance(d.get("dependencies"), dict):     # lockfile v1
        def rec(dd):
            for name, info in dd.items():
                if not isinstance(info, dict):
                    continue
                if info.get("version"):
                    out.append((name, info["version"]))
                if isinstance(info.get("dependencies"), dict):
                    rec(info["dependencies"])
        rec(d["dependencies"])
    return out


def _parse_cargo_lock(text):
    out, name = [], None
    for line in text.splitlines():
        s = line.strip()
        if s == "[[package]]":
            name = None
            continue
        m = re.match(r'name\s*=\s*"([^"]+)"', s)
        if m:
            name = m.group(1)
            continue
        m = re.match(r'version\s*=\s*"([^"]+)"', s)
        if m and name:
            out.append((name, m.group(1)))
            name = None
    return out


def _parse_go_mod(text):
    out, inblock = [], False
    for line in text.splitlines():
        s = line.split("//")[0].strip()
        if s.startswith("require ("):
            inblock = True
            continue
        if inblock and s == ")":
            inblock = False
            continue
        m = re.match(r'(?:require\s+)?([\w.\-]+(?:/[\w.\-]+)+)\s+v([0-9][\w.\-+]*)', s)
        if m:
            out.append((m.group(1), m.group(2)))               # OSV Go wants the version WITHOUT the leading 'v'
    return out


# file name -> (OSV ecosystem, parser). LOCK files first (exact, transitive versions).
_FILES = {
    "requirements.txt": ("PyPI", _parse_requirements),
    "package-lock.json": ("npm", _parse_package_lock),
    "Cargo.lock": ("crates.io", _parse_cargo_lock),
    "go.mod": ("Go", _parse_go_mod),
}


def _iter_files(target):
    p = Path(target)
    if p.is_file():
        if p.name in _FILES:
            yield p
        return
    for f in p.rglob("*"):
        if f.name in _FILES and not any(s in f.parts for s in _SKIP):
            yield f


def collect(target):
    """Every (ecosystem, name, version, file) pin found in the repo's manifests/locks (deduped)."""
    seen, out = set(), []
    for f in _iter_files(target):
        eco, parser = _FILES[f.name]
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name, ver in parser(text):
            key = (eco, name, ver)
            if key in seen:
                continue
            seen.add(key)
            out.append({"ecosystem": eco, "name": name, "version": ver, "file": str(f)})
    return out


# ---- OSV.dev queries --------------------------------------------------------------------------------------

def _post_json(url, payload, timeout):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json",
                                                          "User-Agent": "wave-deps/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _get_json(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": "wave-deps/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _fixed_version(vuln, name, eco):
    """First 'fixed' version OSV lists for this package (best-effort)."""
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("name") != name or (pkg.get("ecosystem") and pkg["ecosystem"] != eco):
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if ev.get("fixed"):
                    return ev["fixed"]
    return ""


def _severity(vuln):
    for s in vuln.get("severity", []) or []:
        if s.get("score"):
            return str(s["score"])
    ds = vuln.get("database_specific", {}) or {}
    return str(ds.get("severity", "") or "")


def scan(target, online=True, timeout=30, max_details=200):
    """Return known-CVE findings for the repo's dependencies. `online=False` (or any network error) -> []."""
    pins = collect(target)
    if not pins or not online:
        return []
    findings, id_seen = [], {}
    # OSV batch: up to 1000 queries per request.
    for i in range(0, len(pins), 1000):
        chunk = pins[i:i + 1000]
        queries = [{"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": p["version"]}
                   for p in chunk]
        try:
            res = _post_json(_OSV_BATCH, {"queries": queries}, timeout).get("results", [])
        except Exception:
            continue                                            # network/API failure -> skip this chunk
        for p, r in zip(chunk, res):
            for v in (r or {}).get("vulns", []) or []:
                findings.append({**p, "id": v.get("id", "")})
    # enrich unique advisory ids with summary / severity / fixed version (bounded)
    details = {}
    for f in findings[:max_details]:
        vid = f["id"]
        if vid and vid not in details:
            try:
                details[vid] = _get_json(_OSV_VULN + vid, timeout)
            except Exception:
                details[vid] = {}
    out = []
    for f in findings:
        v = details.get(f["id"], {})
        aliases = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
        out.append({
            "ecosystem": f["ecosystem"], "package": f["name"], "version": f["version"],
            "id": f["id"], "cve": aliases[0] if aliases else "",
            "severity": _severity(v), "fixed": _fixed_version(v, f["name"], f["ecosystem"]),
            "summary": (v.get("summary") or v.get("details", "") or "")[:200], "file": f["file"],
        })
    out.sort(key=lambda d: (d["ecosystem"], d["package"], d["version"]))
    return out


def render(findings, target=""):
    """Markdown section for the report."""
    if not findings:
        return "## Dependency vulnerabilities\n\nNo known-vulnerable dependencies found (OSV.dev).\n"
    lines = [f"## Dependency vulnerabilities  ({len(findings)})", "",
             "Known CVEs in third-party packages (OSV.dev). Upgrade to the fixed version.", ""]
    for f in findings:
        fix = f" -> fix in **{f['fixed']}**" if f["fixed"] else " (no fixed version listed)"
        cve = f" ({f['cve']})" if f["cve"] else ""
        sev = f" [{f['severity']}]" if f["severity"] else ""
        lines.append(f"- **{f['package']} {f['version']}** ({f['ecosystem']}){sev}: {f['id']}{cve}{fix}")
        if f["summary"]:
            lines.append(f"  - {f['summary']}")
    return "\n".join(lines) + "\n"
