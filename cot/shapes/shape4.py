# ============================================================
# cot/shapes/shape4.py
#
# Shape 4 — Whole-project synthesis.
#
# Inputs: a set of 4–8 findings (sampled from generated Shape 1
# and Shape 3 outputs) plus a short fake project map. Outputs:
# <think> cluster + rank + infer systemic </think> followed by
# an executive summary, ranked findings, and systemic
# observations.
#
# Sampling: reads from data/cot/pilot/shape1.jsonl and shape3.jsonl
# if they exist. Falls back to a small synthetic set otherwise so
# the pilot for Shape 4 can run independently if needed.
#
# Verifier: parses ranked-findings section, checks every finding
# title was present in the input finding-set (anti-hallucination),
# and that severity ordering is non-increasing.
# ============================================================
import json
import random
from pathlib import Path
from typing import Optional

from ..config import PILOT_DIR
from .exemplars import format_shape4_exemplars
from ..specificity import score_assistant, gate


name = "shape4"

random.seed(45)


# Fallback synthetic findings if Shape 1/3 outputs aren't available yet.
SYNTHETIC_FINDINGS = [
    {"title": "SQL injection in get_user_orders", "cwe": "CWE-89", "severity": "HIGH", "file": "api/orders.py", "language": "python"},
    {"title": "Hardcoded JWT secret in auth helper", "cwe": "CWE-798", "severity": "HIGH", "file": "auth/jwt.py", "language": "python"},
    {"title": "SSRF in image proxy endpoint", "cwe": "CWE-918", "severity": "HIGH", "file": "media/proxy.py", "language": "python"},
    {"title": "Open redirect in /login?next= flow", "cwe": "CWE-601", "severity": "MEDIUM", "file": "auth/login.py", "language": "python"},
    {"title": "Path traversal in /download", "cwe": "CWE-22", "severity": "HIGH", "file": "api/files.py", "language": "python"},
    {"title": "Insecure deserialization in /import", "cwe": "CWE-502", "severity": "HIGH", "file": "api/import.py", "language": "python"},
    {"title": "XSS via dangerouslySetInnerHTML in BioCard", "cwe": "CWE-79", "severity": "HIGH", "file": "components/BioCard.tsx", "language": "react"},
    {"title": "Prototype pollution in deep-merge helper", "cwe": "CWE-1321", "severity": "MEDIUM", "file": "utils/merge.js", "language": "javascript"},
    {"title": "Weak random for password reset tokens", "cwe": "CWE-338", "severity": "HIGH", "file": "auth/reset.py", "language": "python"},
    {"title": "Missing TLS verify on outbound HTTP", "cwe": "CWE-295", "severity": "MEDIUM", "file": "services/http.py", "language": "python"},
    {"title": "Race in idempotency-key check", "cwe": "CWE-362", "severity": "MEDIUM", "file": "billing/idempotent.py", "language": "python"},
    {"title": "Sensitive data in error response", "cwe": "CWE-209", "severity": "LOW", "file": "api/errors.py", "language": "python"},
    # --- Expanded pool ---
    {"title": "Stored XSS via mark_safe in profile", "cwe": "CWE-79", "severity": "HIGH", "file": "accounts/profile.py", "language": "python"},
    {"title": "CSRF on /account/delete endpoint", "cwe": "CWE-352", "severity": "HIGH", "file": "api/account.py", "language": "python"},
    {"title": "Command injection in /admin/exec", "cwe": "CWE-78", "severity": "HIGH", "file": "admin/exec.py", "language": "python"},
    {"title": "IDOR via user_id query param", "cwe": "CWE-639", "severity": "HIGH", "file": "api/orders_view.py", "language": "python"},
    {"title": "Permissive CORS with credentials", "cwe": "CWE-942", "severity": "HIGH", "file": "settings.py", "language": "python"},
    {"title": "Mass assignment in PATCH /users/me", "cwe": "CWE-915", "severity": "HIGH", "file": "api/users.ts", "language": "typescript"},
    {"title": "XPath injection in user search", "cwe": "CWE-643", "severity": "HIGH", "file": "ldap/search.py", "language": "python"},
    {"title": "Cookie missing httpOnly+secure flags", "cwe": "CWE-1004", "severity": "MEDIUM", "file": "auth/session.py", "language": "python"},
    {"title": "MD5 used for password hashing", "cwe": "CWE-327", "severity": "HIGH", "file": "auth/password.py", "language": "python"},
    {"title": "Timing attack in API token compare", "cwe": "CWE-208", "severity": "MEDIUM", "file": "auth/token_verify.py", "language": "python"},
    {"title": "Log injection in winston logger", "cwe": "CWE-117", "severity": "MEDIUM", "file": "lib/log.js", "language": "javascript"},
    {"title": "Dynamic require from user input", "cwe": "CWE-829", "severity": "HIGH", "file": "lib/plugins.js", "language": "javascript"},
    {"title": "Missing authorization on /admin/users", "cwe": "CWE-862", "severity": "HIGH", "file": "admin/users.py", "language": "python"},
    {"title": "ReDoS via nested-quantifier regex", "cwe": "CWE-400", "severity": "MEDIUM", "file": "validation/username.py", "language": "python"},
    {"title": "Excessive data exposure in /users/:id", "cwe": "CWE-200", "severity": "HIGH", "file": "api/users.ts", "language": "typescript"},
    {"title": "chmod 777 on uploaded file", "cwe": "CWE-732", "severity": "MEDIUM", "file": "uploads/save.py", "language": "python"},
    {"title": "Function() constructor on user expr", "cwe": "CWE-94", "severity": "HIGH", "file": "api/formula.js", "language": "javascript"},
    {"title": "SSRF redirect-bypass in fetch_avatar", "cwe": "CWE-918", "severity": "HIGH", "file": "services/avatar.py", "language": "python"},
    {"title": "Hardcoded Stripe live key in source", "cwe": "CWE-798", "severity": "HIGH", "file": "billing/charge.py", "language": "python"},
    {"title": "XXE via lxml default parser", "cwe": "CWE-611", "severity": "HIGH", "file": "parsers/xml.py", "language": "python"},
    {"title": "Pickle deserialization in /import", "cwe": "CWE-502", "severity": "HIGH", "file": "serializers/blob.py", "language": "python"},
]


def _load_findings_from_pilot() -> list[dict]:
    """Pull verified findings from pilot Shape 1/3 outputs."""
    findings = []
    for fname in ("shape1.jsonl", "shape3.jsonl"):
        path = PILOT_DIR / fname
        if not path.exists():
            continue
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                meta = rec.get("_meta", {})
                if meta.get("label") not in ("vuln", "confirmed"):
                    continue  # synthesis is about real findings
                cwes = meta.get("cwes") or []
                lang = meta.get("language", "unknown")
                # Best-effort short title from the assistant payload
                asst = rec["messages"][1]["content"] if isinstance(rec.get("messages"), list) and len(rec["messages"]) > 1 else ""
                title = _make_short_title(asst, cwes)
                findings.append({
                    "title": title,
                    "cwe": cwes[0] if cwes else "CWE-?",
                    "severity": _extract_severity(asst),
                    "file": f"unknown_{len(findings)}.{('py' if lang == 'python' else 'js')}",
                    "language": lang,
                })
    return findings


_PLACEHOLDER_PATTERNS = ("see reasoning", "see above", "n/a", "tbd", "todo")


def _make_short_title(asst: str, cwes: list[str]) -> str:
    """Pull a one-line title from the trace field. Reject obvious placeholders
    (which contaminate shape4 finding sets) and fall back to a CWE-derived stub."""
    import re as _re
    m = _re.search(r"^\s*trace\s*:\s*(.+?)\s*$", asst, _re.IGNORECASE | _re.MULTILINE)
    if m:
        t = m.group(1).strip()
        low = t.lower()
        if any(p in low for p in _PLACEHOLDER_PATTERNS):
            t = ""  # placeholder, ignore
        if len(t) >= 20:
            return t[:80]
    if cwes:
        return f"{cwes[0]} finding"
    return "Vulnerability finding"


def _extract_severity(asst: str) -> str:
    import re as _re
    m = _re.search(r"^\s*severity\s*:\s*(HIGH|MEDIUM|LOW)\s*$", asst, _re.IGNORECASE | _re.MULTILINE)
    return m.group(1).upper() if m else "MEDIUM"


SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def prepare_tasks(limit: int) -> list[dict]:
    """Each Shape 4 task = a sampled set of 4-8 findings + a project map.

    Stability invariant: prepare_tasks(N)[:M] == prepare_tasks(M) for M <= N.
    Each set_id seeds its own RNG so set:i's findings are independent of limit.
    """
    pool = _load_findings_from_pilot()
    # Threshold tuned for the pilot phase: prefer SYNTHETIC seeds until we have
    # a real-scale Shape 1/3 corpus. Pilot Shape 1/3 outputs produce noisy
    # titles (truncated trace lines) that don't compose well into clean
    # synthesis examples — the synthetic seeds give crisper finding titles.
    if len(pool) < 50:
        pool = SYNTHETIC_FINDINGS

    tasks = []
    for i in range(limit):
        rng = random.Random(45_000 + i)  # per-set seed -> deterministic content
        n = rng.randint(4, min(8, len(pool)))
        findings = rng.sample(pool, n)
        # Include intentional near-duplicates ~30% of the time so the trace has
        # something to dedup against.
        if len(findings) >= 4 and rng.random() < 0.3:
            dup = dict(findings[0])
            dup["file"] = dup["file"].replace(".", "_v2.", 1) if "." in dup["file"] else dup["file"] + "_v2"
            findings.append(dup)
        project_map = _make_project_map(findings)
        tasks.append({
            "task_id": f"shape4:set:{i}",
            "findings": findings,
            "project_map": project_map,
        })
    return tasks


def _make_project_map(findings: list[dict]) -> str:
    """Simulate a tiny tree of the affected files."""
    files = sorted({f["file"] for f in findings})
    return "PROJECT MAP\n" + "\n".join(f"  {p}" for p in files)


SYSTEM = (
    "You generate chain-of-thought training data for whole-project security synthesis. "
    "Given a set of findings and a small project map, you cluster duplicates, rank by "
    "exploitability, and surface systemic root causes — then produce an executive summary, "
    "ranked findings, and systemic observations."
)


def build_prompt(task: dict) -> tuple[Optional[str], str]:
    findings = task["findings"]
    project_map = task["project_map"]

    findings_block = "\n".join(
        f"  [{i + 1}] {f['title']}  ({f['cwe']}, sev={f['severity']}, file={f['file']}, lang={f['language']})"
        for i, f in enumerate(findings)
    )

    exemplar_block = format_shape4_exemplars(count=1)
    instruction = f"""{exemplar_block}

You are synthesizing a whole-project security report.

{project_map}

FINDINGS ({len(findings)} items):
{findings_block}

TASK 1 — Write a <think> block that does, in order:
  1. Cluster near-duplicate findings by root cause.
  2. Rank by exploitability (consider reachability, blast radius, CVSS-like reasoning).
  3. Infer 1-3 SYSTEMIC patterns (e.g., "no central input validation layer", "secrets sprawled outside config").

TASK 2 — Output the structured report. EXACTLY this shape:

<think>
[your reasoning, 6-15 short sentences]
</think>

executive_summary: <2-3 sentence summary of overall security posture>

ranked_findings:
  - rank: 1
    title: <verbatim title from input>
    severity: HIGH | MEDIUM | LOW
    rationale: <why this rank>
  - rank: 2
    title: ...
    ...

systemic_observations:
  - <observation 1>
  - <observation 2>

dedup_notes: <which input findings were clustered together, if any; "none" if no duplicates>

CONSTRAINTS:
- Every title in ranked_findings must appear verbatim in the input findings list above.
- Ranks must be 1, 2, 3, ... with severity non-increasing (HIGH before MEDIUM before LOW).
- Do NOT invent new findings.
"""
    return SYSTEM, instruction


def _parse_ranked_titles(generated: str) -> list[tuple[int, str, str]]:
    """Pull (rank, title, severity) tuples from the ranked_findings block.

    Lenient: handles truncated output (no systemic_observations / dedup_notes
    terminator), strips surrounding quotes from YAML-style titles, and tolerates
    the last finding being cut off mid-line."""
    import re as _re
    # Block regex accepts either explicit terminator OR end-of-string (for
    # truncated outputs).
    block = _re.search(
        r"ranked_findings\s*:\s*\n(.*?)(?:\n\s*(?:systemic_observations|dedup_notes)\b|\Z)",
        generated, _re.DOTALL | _re.IGNORECASE,
    )
    if not block:
        return []
    out = []
    items = _re.split(r"\n\s*-\s*rank\s*:\s*", block.group(1))
    for raw in items:
        raw = raw.strip()
        if not raw:
            continue
        m_rank = _re.match(r"(\d+)", raw)
        rank = int(m_rank.group(1)) if m_rank else None
        m_title = _re.search(r"title\s*:\s*(.+?)\s*$", raw, _re.IGNORECASE | _re.MULTILINE)
        m_sev = _re.search(r"severity\s*:\s*(HIGH|MEDIUM|LOW)", raw, _re.IGNORECASE)
        if rank is None or not m_title:
            continue
        title = m_title.group(1).strip()
        # Strip surrounding quotes if YAML-style "..." or '...'
        if (title.startswith('"') and title.endswith('"')) or \
           (title.startswith("'") and title.endswith("'")):
            title = title[1:-1].strip()
        out.append((rank, title, (m_sev.group(1).upper() if m_sev else "MEDIUM")))
    return out


def verify(task: dict, generated_text: str) -> Optional[dict]:
    import re as _re

    # Must have <think>
    if not _re.search(r"<think>.*?</think>", generated_text, _re.DOTALL):
        return None
    # Must have exec summary
    if not _re.search(r"executive_summary\s*:", generated_text, _re.IGNORECASE):
        return None

    ranked = _parse_ranked_titles(generated_text)
    if len(ranked) < min(3, len(task["findings"])):
        return None  # too few ranked items

    # Anti-hallucination: every ranked title must substring-match an input title
    input_titles = [f["title"].lower() for f in task["findings"]]
    for _, title, _ in ranked:
        title_low = title.lower()
        if not any(it in title_low or title_low in it for it in input_titles):
            return None  # hallucinated finding

    # Severity ordering must be non-increasing
    sev_seq = [SEVERITY_RANK.get(s, 0) for _, _, s in ranked]
    if any(sev_seq[i] < sev_seq[i + 1] for i in range(len(sev_seq) - 1)):
        return None

    # Specificity gate — opt-in via WAVE_SPECIFICITY_GATE=true.
    import os as _os
    spec_meta = None
    if _os.environ.get("WAVE_SPECIFICITY_GATE", "false").lower() in ("1", "true", "yes"):
        pseudo_code = _user_side_prompt(task)
        spec_meta = score_assistant(generated_text, pseudo_code, "mixed")
        if not gate(spec_meta["score"]):
            return None

    record = {
        "messages": [
            {"role": "user", "content": _user_side_prompt(task)},
            {"role": "assistant", "content": generated_text.strip()},
        ],
        "_meta": {
            "shape": "shape4",
            "label": "synthesis",
            "num_findings": len(task["findings"]),
            "cwes": [f["cwe"] for f in task["findings"]],
            "language": "mixed",
            "specificity": spec_meta["score"] if spec_meta else None,
        },
    }
    return record


def _user_side_prompt(task: dict) -> str:
    findings_block = "\n".join(
        f"  [{i + 1}] {f['title']}  ({f['cwe']}, sev={f['severity']}, file={f['file']}, lang={f['language']})"
        for i, f in enumerate(task["findings"])
    )
    return (
        "<SYNTHESIZE>\n"
        f"{task['project_map']}\n\n"
        f"FINDINGS ({len(task['findings'])}):\n"
        f"{findings_block}\n"
        "</SYNTHESIZE>"
    )
