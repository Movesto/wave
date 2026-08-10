"""Discovery station: the model reads the WHOLE project (cross-file) for the vulns dataflow
tools CANNOT pattern-match -- missing authorization, IDOR, broken auth, business-logic and
insecure-design flaws. Findings are REVIEW-tier (a tool cannot verify "missing ownership
check"), complementing -- not replacing -- the tool-grounded findings.

Scope:
  - project fits the context budget -> feed the whole source at once (true cross-file view).
  - project too large -> build a PROJECT MAP (per-file routes / handlers / auth checks) that
    fits, feed that; the model names suspicious endpoints; then we feed those files for detail.

The model's line numbers are unreliable, so snap_line() corrects each finding to the real
definition line of the function/handler it names, via a deterministic search.
"""
import re
from pathlib import Path

CHAR_BUDGET = 90_000     # ~22K tokens

SYSTEM = """You are a senior application-security engineer doing a MANUAL review that automated
tools CANNOT do. Automated dataflow tools ALREADY cover injection, XSS, path traversal, SSRF
and deserialization -- DO NOT report those. Report ONLY issues that need INTENT and CROSS-FILE
logic:
  - Missing/broken authorization or access control (a user acting on ANOTHER user's object by
    id -- IDOR; an endpoint missing an ownership or role check).
  - Authentication logic flaws (predictable/reusable tokens, auth that can be skipped).
  - Business-logic flaws (a workflow abused: negative amounts, price/quantity tampering, replay).
  - Insecure design / trust-boundary mistakes (trusting a client-supplied role/flag).
Trace the logic ACROSS files. For each real issue output EXACTLY:

FINDING: <one-line title>
FILE: <file:line>
FUNCTION: <the function/handler name where the flaw lives>
WHY: <the flaw and how it is abused, referencing the cross-file path>
---
Report only genuine issues. If none, output exactly: NONE."""


# ---- parse the model's free-form findings -------------------------------------------
def parse_findings(text):
    out = []
    for blk in re.split(r"\n-{3,}\n|\n(?=FINDING:)", text):
        f = re.search(r"FINDING:\s*(.+)", blk)
        if not f:
            continue
        fl = re.search(r"FILE:\s*(.+)", blk)
        fn = re.search(r"FUNCTION:\s*(.+)", blk)
        why = re.search(r"WHY:\s*([\s\S]+?)(?:\n[A-Z]+:|\Z)", blk)
        file_path, line = "", 0
        if fl:
            m = re.match(r"(.+?):(\d+)", fl.group(1).strip())
            if m:
                file_path, line = m.group(1).strip(), int(m.group(2))
            else:
                file_path = fl.group(1).strip()
        out.append({"title": f.group(1).strip(), "file": file_path, "line": line,
                    "function": (fn.group(1).strip() if fn else ""),
                    "why": (why.group(1).strip() if why else "")})
    return out


# ---- snap the guessed line to the real definition of the named function -------------
def _candidate_names(finding):
    names = []
    if finding.get("function"):
        names.append(re.sub(r"\(.*", "", finding["function"]).strip())
    # identifiers named in the title/why: camelCase or snake, >=4 chars, not common words
    for m in re.findall(r"\b([a-zA-Z_]\w{3,})\b", finding["title"] + " " + finding["why"]):
        if (any(c.isupper() for c in m[1:]) or "_" in m) and m.lower() not in (
                "which", "without", "authenticated", "attacker", "cross", "reset"):
            names.append(m)
    seen, uniq = set(), []
    for n in names:
        if n and n not in seen:
            seen.add(n); uniq.append(n)
    return uniq


def _resolve_file(repo_root, fp):
    base = Path(fp.replace("\\", "/")).name if fp else ""
    if not base:
        return None
    hits = list(Path(repo_root).rglob(base))
    return hits[0] if hits else None


def snap_line(repo_root, finding):
    """Return (file, snapped_line, snapped_bool). Correct the model's guessed line to the real
    DEFINITION line of the function/handler it named; fall back to the guess."""
    cand = _resolve_file(repo_root, finding.get("file", ""))
    if cand is None:
        return finding.get("file", ""), finding.get("line", 0), False
    lines = cand.read_text(encoding="utf-8", errors="replace").splitlines()
    names = _candidate_names(finding)
    # pass 1: a real definition of the named function
    for name in names:
        n = re.escape(name)
        defrx = re.compile(
            r"(?:module\.exports\.|exports\.|function\s+|async\s+|def\s+)" + n + r"\b"
            r"|\b" + n + r"\s*[:=]\s*(?:async\s*)?(?:function|\([^)]*\)\s*=>|\()"
            r"|@\w+[^\n]*\b" + n + r"\b")
        for i, ln in enumerate(lines, 1):
            if defrx.search(ln):
                return str(cand), i, True
    # pass 2: first line that even mentions the named function
    for name in names:
        for i, ln in enumerate(lines, 1):
            if re.search(r"\b" + re.escape(name) + r"\b", ln):
                return str(cand), i, True
    return str(cand), finding.get("line", 0), False


# ---- project map (large repos that don't fit one context window) --------------------
_ROUTE = re.compile(r"(?:router|app)\.(get|post|put|delete|patch|use)\s*\(\s*['\"]([^'\"]+)['\"]"
                    r"|@(Get|Post|Put|Delete|Patch)\s*\(\s*['\"]?([^'\")]*)", re.I)
_AUTH = re.compile(r"isAuthenticated|requireAuth|@UseGuards|ensureAuth|req\.user|passport|"
                   r"authorize|hasRole|isAdmin|\.role\b|checkOwner|verifyToken", re.I)
_EXPORT_FN = re.compile(r"(?:module\.exports\.|exports\.)(\w+)\s*=|function\s+(\w+)\s*\(|"
                        r"async\s+(\w+)\s*\(|(\w+)\s*=\s*(?:async\s*)?function")


def build_project_map(files):
    """Compact per-file structural summary (routes, handlers, whether auth appears)."""
    lines = ["PROJECT MAP (routes, handlers, and whether an auth/ownership check appears):\n"]
    for f in sorted(files):
        try:
            code = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        routes = [f"{(m.group(1) or m.group(3) or '').upper()} {m.group(2) or m.group(4) or ''}"
                  for m in _ROUTE.finditer(code)]
        fns = sorted({g for m in _EXPORT_FN.finditer(code) for g in m.groups() if g})
        auth = "AUTH-CHECK-PRESENT" if _AUTH.search(code) else "NO-AUTH-CHECK-SEEN"
        if routes or fns:
            lines.append(f"// {f}  [{auth}]")
            if routes:
                lines.append("   routes: " + "; ".join(routes[:12]))
            if fns:
                lines.append("   handlers: " + ", ".join(fns[:20]))
    return "\n".join(lines)


# ---- orchestration ------------------------------------------------------------------
def _build_corpus(files, budget):
    total = 0
    parts = []
    for f in sorted(files):
        try:
            code = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        parts.append(f"\n// FILE: {f}\n{code}\n")
        total += len(parts[-1])
    return "".join(parts), total


def run_discovery(files, predict, repo_root, budget=CHAR_BUDGET):
    """files: list of Path; predict(system, user)->str. Returns (findings, mode).

    mode 'full' = whole project fed at once; mode 'map' = project too big, fed a structural
    MAP (routes/handlers/auth) so the model can still reason about the WHOLE project's design.
    Each finding's line is snapped to the real definition."""
    corpus, total = _build_corpus(files, budget)
    if total <= budget:
        user, mode = corpus, "full"
    else:
        user, mode = (build_project_map(files) +
                      "\n\n(The full source is too large to inline; reason from this MAP -- "
                      "flag endpoints missing an auth/ownership check or with a logic flaw, "
                      "naming the file and function.)", "map")
    raw = predict(SYSTEM, user)
    finds = parse_findings(raw)
    for f in finds:
        f["file"], f["line"], f["snapped"] = snap_line(repo_root, f)
        f["tier"] = "REVIEW"          # unverifiable by a tool -> human-check
    return finds, mode
