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
    m = re.search(r"open_refs\s*:\s*\n((?:\s*-\s*[^\n]+\n?)+)", text, re.IGNORECASE)
    if not m:
        return []
    refs = []
    for line in m.group(1).splitlines():
        line = line.strip()
        if line.startswith("-"):
            refs.append(line.lstrip("-").strip())
    return refs


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


def parse_shape1(text: str) -> dict:
    fields = {}
    for m in FIELD_RE.finditer(text):
        fields[m.group(1).lower()] = m.group(2).strip()
    return {
        "think":    _extract_think(text),
        "status":   _normalize_status(_extract_status_raw(text)),
        "cwe":      _normalize_cwe(fields.get("cwe")),
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
