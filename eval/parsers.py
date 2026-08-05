# ============================================================
# eval/parsers.py
#
# Parse a model's generated text into a structured prediction
# per shape. The structure mirrors what the training data
# emitted, so the same fields can be compared to ground truth.
# ============================================================
import re
from typing import Optional


CWE_RE = re.compile(r"\bCWE-(\d{1,4})\b")
THINK_RE = re.compile(r"<think>(.*?)</think>", re.DOTALL | re.IGNORECASE)
FIELD_RE = re.compile(r"^\s*(status|cwe|severity|line|trace|fix|partial_trace)\s*:\s*(.+?)\s*$",
                      re.IGNORECASE | re.MULTILINE)


def _extract_think(text: str) -> Optional[str]:
    m = THINK_RE.search(text)
    return m.group(1).strip() if m else None


def _normalize_status(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    s = raw.strip().lower().split()[0].strip(".,;")
    if s in ("confirmed", "vuln", "vulnerable"):
        return "confirmed"
    if s in ("safe", "clean"):
        return "safe"
    if "needs_context" in s or "needs" in s:
        return "needs_context"
    if s in ("synthesis",):
        return "synthesis"
    return None


def _normalize_cwe(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    m = CWE_RE.search(raw)
    return f"CWE-{m.group(1)}" if m else None


def _extract_status_raw(text: str) -> Optional[str]:
    m = re.search(r"^\s*status\s*:\s*(.+?)\s*$", text, re.IGNORECASE | re.MULTILINE)
    return m.group(1).strip() if m else None


def _extract_open_refs(text: str) -> list[str]:
    return _extract_dash_list("open_refs", text)


def _extract_dash_list(field: str, text: str) -> list[str]:
    """Read a `field:` whose value is a dash list.

    Accepts BOTH layouts. The multi-line form is what the format specifies, but
    postprocessing collapses whitespace, so every stored shape2 record is single-line
    (`open_refs: - a (x.py) - b (y.py)`) — a newline-only regex parsed 0 of 80 of them
    and silently returned no references at all. Handle both, or the field is decorative.
    """
    m = re.search(rf"{field}\s*:\s*\n((?:\s*-\s*[^\n]+\n?)+)", text, re.IGNORECASE)
    if m:
        return [ln.strip().lstrip("-").strip()
                for ln in m.group(1).splitlines() if ln.strip().startswith("-")]

    # Single-line: consume up to the next known field label.
    m = re.search(rf"{field}\s*:\s*(.+?)(?=\b(?:status|partial_trace|open_refs|"
                  rf"follow_up_refs|trace|fix|cwe|severity|line)\s*:|$)",
                  text, re.IGNORECASE | re.DOTALL)
    if not m:
        return []
    return [part.strip() for part in m.group(1).split("-") if part.strip()]


def _extract_follow_ups(text: str) -> list[str]:
    m = re.search(r"follow_up_refs\s*:\s*\n((?:\s*-\s*[^\n]+\n?)+)", text, re.IGNORECASE)
    if not m:
        return []
    out = []
    for line in m.group(1).splitlines():
        line = line.strip()
        if line.startswith("-"):
            out.append(line.lstrip("-").strip())
    return out



# Verdict words that are only asserted when the model has DECIDED, not while it
# hedges. The negations ("no vulnerability", "not vulnerable", "appears safe") are
# checked first so a "not vulnerable" sentence is not read as a vuln because it
# contains the word "vulnerable".
_SAFE_PHRASE = re.compile(
    r"\b(no\s+(?:security\s+)?(?:vulnerabilit|issue|flaw|risk)"
    r"|not\s+(?:vulnerable|exploitable)"
    r"|is\s+safe|appears?\s+safe|properly\s+(?:sanitiz|validat|escap|paramet)"
    r"|correctly\s+(?:sanitiz|validat|handl)|code\s+is\s+secure)", re.I)
_VULN_PHRASE = re.compile(
    r"\b(is\s+vulnerable|vulnerabilit(?:y|ies)\s+aris|this\s+is\s+an?\s+"
    r"(?:sql|command|os\s+command|path|xss|ssrf|code|xxe|insecure)"
    r"|an?\s+attacker\s+(?:can|could|is\s+able|provides?|controls?)"
    r"|allows?\s+(?:an?\s+)?(?:attacker|injection|traversal|arbitrary)"
    r"|can\s+(?:inject|be\s+exploited|control)"
    r"|(?:could|can|may|would)\s+lead\s+to\s+(?:sql|command|remote|arbitrary|"
    r"ssrf|xss|path|injection)"
    r"|without\s+(?:any\s+)?(?:sanitiz|validat|parameter|escap))", re.I)


def _status_from_prose(text: str) -> Optional[str]:
    """Infer a verdict from free-form reasoning when there is no status: line.

    v14 free-forms into numbered prose on a bare <SCAN> prompt and emits no status:
    line, so the scanner scored correct SQLi/SSRF/path catches as no-finding.

    Regex-first-match was too fragile: "does NOT properly validate" fired the safe
    pattern on the word "validate", ignoring the negation that reverses it. This scores
    EVIDENCE instead -- count vuln vs safe signals, and let an explicit exploit
    demonstration settle ties. It is a fallback, and deliberately abstains (None) when
    the signals are weak rather than guessing.
    """
    t = " ".join(text.lower().split())

    # An explicit exploit demonstration is near-decisive: the model does not narrate an
    # attack payload for code it thinks is safe.
    exploit = bool(re.search(
        r"\.\./|/etc/passwd|<script|;\s*rm\s|;\s*cat\s|union\s+select"
        r"|or\s+1\s*=\s*1|127\.0\.0\.1|169\.254|attacker[- ]controlled", t))

    vuln_hits = len(re.findall(
        r"is\s+vulnerable|vulnerabilit(?:y|ies)\s+aris|an?\s+attacker\s+(?:can|could|"
        r"is\s+able|provides?|controls?|injects?|supplies)|can\s+(?:inject|be\s+"
        r"exploited|control|traverse)|(?:could|can|may|would)\s+lead\s+to|"
        r"without\s+(?:any\s+)?(?:sanitiz|validat|paramet|escap)|"
        r"direct(?:ly)?\s+concatenat|string\s+concatenation|not\s+(?:properly\s+)?"
        r"(?:sanitiz|validat|paramet|escap)|user[- ](?:provided|controlled|supplied)"
        r"|arbitrary\s+(?:sql|command|file|code)|injection|traversal", t))

    # Safe signals must NOT be negated. "does not properly validate" is a vuln signal,
    # so a preceding "not"/"n't"/"fails to"/"missing" cancels the safe reading.
    safe_hits = 0
    for m in re.finditer(
            r"(is\s+safe|appears?\s+safe|properly\s+(?:sanitiz|validat|escap|paramet)"
            r"|correctly\s+(?:sanitiz|validat|handl)|code\s+is\s+secure|no\s+"
            r"(?:security\s+)?(?:vulnerabilit|issue|flaw|risk)|is\s+not\s+"
            r"(?:vulnerable|exploitable)|uses?\s+(?:a\s+)?parameter)", t):
        pre = t[max(0, m.start() - 24):m.start()]
        if not re.search(r"(not|n't|fails?\s+to|without|missing|lacks?|no)", pre):
            safe_hits += 1

    if exploit and safe_hits == 0:
        return "confirmed"
    if vuln_hits >= safe_hits and vuln_hits >= 1:
        return "confirmed"
    if safe_hits > vuln_hits and safe_hits >= 1:
        return "safe"
    return None


def parse_shape1(text: str) -> dict:
    fields = {}
    for m in FIELD_RE.finditer(text):
        fields[m.group(1).lower()] = m.group(2).strip()
    return {
        "think":    _extract_think(text),
        "status":   (_normalize_status(_extract_status_raw(text))
                     or _status_from_prose(text)),
        "cwe":      _normalize_cwe(fields.get("cwe")) or _normalize_cwe(text),
        "severity": (fields.get("severity") or "").upper() if fields.get("severity") else None,
        "trace":    fields.get("trace"),
        "fix":      fields.get("fix"),
    }


def parse_shape2(text: str) -> dict:
    status_raw = _extract_status_raw(text) or ""
    return {
        "think":     _extract_think(text),
        "status":    _normalize_status(status_raw),
        "open_refs": _extract_open_refs(text),
    }


def parse_shape3(text: str) -> dict:
    fields = {}
    for m in FIELD_RE.finditer(text):
        fields[m.group(1).lower()] = m.group(2).strip()
    return {
        "think":          _extract_think(text),
        "status":         _normalize_status(_extract_status_raw(text)),
        "cwe":            _normalize_cwe(fields.get("cwe")),
        "severity":       (fields.get("severity") or "").upper() if fields.get("severity") else None,
        "trace":          fields.get("trace"),
        "fix":            fields.get("fix"),
        "follow_up_refs": _extract_follow_ups(text),
    }


SEV_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def parse_shape4(text: str) -> dict:
    think = _extract_think(text)
    exec_match = re.search(r"executive_summary\s*:\s*(.+?)(?=\n\s*ranked_findings|\Z)",
                           text, re.IGNORECASE | re.DOTALL)
    exec_summary = exec_match.group(1).strip() if exec_match else None

    # Ranked findings: list of (rank, title, severity)
    block_match = re.search(r"ranked_findings\s*:\s*\n(.*?)(?=\n\s*(?:systemic_observations|dedup_notes|\Z))",
                            text, re.IGNORECASE | re.DOTALL)
    ranked = []
    if block_match:
        items = re.split(r"\n\s*-\s*rank\s*:\s*", block_match.group(1))
        for raw in items:
            raw = raw.strip()
            if not raw:
                continue
            m_rank = re.match(r"(\d+)", raw)
            m_title = re.search(r"title\s*:\s*(.+?)\s*$", raw, re.IGNORECASE | re.MULTILINE)
            m_sev = re.search(r"severity\s*:\s*(HIGH|MEDIUM|LOW)", raw, re.IGNORECASE)
            if not m_rank or not m_title:
                continue
            ranked.append({
                "rank": int(m_rank.group(1)),
                "title": m_title.group(1).strip(),
                "severity": (m_sev.group(1).upper() if m_sev else "MEDIUM"),
            })

    # Systemic observations
    obs_block = re.search(r"systemic_observations\s*:\s*\n((?:\s*-\s*[^\n]+\n?)+)",
                          text, re.IGNORECASE)
    obs = []
    if obs_block:
        for line in obs_block.group(1).splitlines():
            line = line.strip()
            if line.startswith("-"):
                obs.append(line.lstrip("-").strip())

    return {
        "think":             think,
        "executive_summary": exec_summary,
        "ranked":            ranked,
        "systemic":          obs,
    }


def parse_for_shape(shape: str, text: str) -> dict:
    parsers = {
        "shape1": parse_shape1,
        "shape2": parse_shape2,
        "shape3": parse_shape3,
        "shape4": parse_shape4,
    }
    # Language-coverage variants are all shape1-format (status/cwe verdict).
    return parsers.get(shape, parse_shape1)(text)
