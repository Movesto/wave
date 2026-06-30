# ============================================================
# cot/shapes/common.py
#
# Helpers shared by shape generators: SFT loaders, ground-truth
# extractors, language detection (reused from inventory script),
# response parsers for the structured CoT output.
# ============================================================
import json
import re
from pathlib import Path
from typing import Optional, Iterator

from ..config import SFT_DIR


CWE_RE = re.compile(r"\bCWE-(\d{1,4})\b")
SCAN_OPEN_RE = re.compile(r"<SCAN>\s*\n?(.*?)\n?</SCAN>", re.DOTALL)

PY_HINTS = ["def ", "import ", "from ", "self.", "    ", "lambda ", "class "]
JS_HINTS = ["function ", "const ", "let ", "=>", "require(", "module.exports", "import {", "export "]
TS_HINTS = [": string", ": number", ": boolean", ": Promise<", "interface ", "type ", " as "]
REACT_HINTS = ["useState", "useEffect", "<div", "<button", "<form", "props.", "dangerouslySetInnerHTML"]


def detect_language(text: str) -> str:
    """Cheap classifier — sufficient for sampling and bookkeeping."""
    if any(h in text for h in REACT_HINTS) and ("<" in text and "/>" in text or "jsx" in text.lower()):
        return "react"
    if any(h in text for h in TS_HINTS) and any(h in text for h in JS_HINTS):
        return "typescript"
    if any(h in text for h in JS_HINTS):
        return "javascript"
    if any(h in text for h in PY_HINTS):
        return "python"
    return "other"


def extract_scan_code(user_content: str) -> Optional[str]:
    m = SCAN_OPEN_RE.search(user_content)
    if m:
        return m.group(1).strip()
    return None


def iter_jsonl(filename: str) -> Iterator[dict]:
    """Yield parsed records from data/sft/<filename>, skipping malformed."""
    path = SFT_DIR / filename
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def get_messages(record: dict) -> Optional[tuple[str, str]]:
    """Return (user_text, assistant_text) from a record, or None if malformed."""
    if not isinstance(record, dict):
        return None
    msgs = record.get("messages")
    if not isinstance(msgs, list) or len(msgs) < 2:
        return None
    user = next((m for m in msgs if m.get("role") == "user"), None)
    asst = next((m for m in msgs if m.get("role") == "assistant"), None)
    if not user or not asst:
        return None
    return user.get("content", ""), asst.get("content", "")


# --- Response parser for the structured CoT verdict ---

THINK_RE = re.compile(r"<think>(.*?)</think>", re.DOTALL | re.IGNORECASE)
FIELD_RE = re.compile(r"^\s*(status|cwe|severity|line|trace|fix)\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)


def parse_verdict(generated_text: str) -> dict:
    """Parse the generated CoT response.

    Expected format:
        <think> ... </think>

        status: confirmed | safe
        cwe: CWE-XX | none
        severity: HIGH | MEDIUM | LOW | none
        line: N | none
        trace: ...
        fix: ... | none

    Returns dict with keys 'think', 'status', 'cwe', 'severity', 'line',
    'trace', 'fix'. Missing fields default to None.
    """
    result = {"think": None, "status": None, "cwe": None, "severity": None,
              "line": None, "trace": None, "fix": None}

    think_match = THINK_RE.search(generated_text)
    if think_match:
        result["think"] = think_match.group(1).strip()
        # Strip the <think> block before parsing fields
        rest = generated_text[think_match.end():]
    else:
        rest = generated_text

    for m in FIELD_RE.finditer(rest):
        key = m.group(1).lower()
        val = m.group(2).strip()
        if val.lower() in ("none", "n/a", "-", ""):
            val = None
        result[key] = val

    # Normalize status
    if result["status"]:
        s = result["status"].lower().split()[0]  # take first word
        if s in ("confirmed", "vuln", "vulnerable"):
            result["status"] = "confirmed"
        elif s in ("safe", "clean"):
            result["status"] = "safe"
        else:
            result["status"] = None

    # Normalize CWE
    if result["cwe"]:
        m = CWE_RE.search(result["cwe"])
        result["cwe"] = f"CWE-{m.group(1)}" if m else None

    return result


# --- Safe-verdict output normalizer ---
#
# The generator stores the model's RAW output. On the `safe` branch the model
# routinely emits incoherent structured fields that contradict the verdict:
#   - shape1: a vuln-style `trace: CWE-79 in `foo`` (plus dangling narrative)
#   - shape3: leftover `cwe: CWE-XX | none` placeholder and `severity: HIGH`
# Training on those teaches the model to attach CWEs/HIGH severity to safe code
# — directly hurting the FPR metric. This normalizer rewrites the structured
# block of a `safe` record into a coherent form. It is a no-op for confirmed/
# vuln records and must only be called when the verdict is safe.

_SAFE_FIELD_RE = re.compile(
    r"^(?P<indent>\s*)(?P<key>status|cwe|severity|line|trace|fix)(?P<sep>\s*:\s*)(?P<val>.*)$",
    re.IGNORECASE,
)
_REFS_RE = re.compile(r"^\s*(follow_up_refs|open_refs)\s*:", re.IGNORECASE)
_LIST_ITEM_RE = re.compile(r"^\s*-\s")
_TRACE_CWE_IN_RE = re.compile(r"^\s*CWE-\S+\s+in\s+(?P<ident>.+?)\s*$", re.IGNORECASE)

_SAFE_TRACE_FALLBACK = "no untrusted input reaches a dangerous sink; code is safe"


def _clean_safe_trace(val: str) -> str:
    """Turn a vuln-flavored trace line into a safe-flow summary.

    `CWE-79 in `jzt`` -> `no untrusted-input-to-sink data flow involving `jzt`; code is safe`
    A trace with no CWE reference is returned unchanged.
    """
    if not val:
        return _SAFE_TRACE_FALLBACK
    m = _TRACE_CWE_IN_RE.match(val)
    if m:
        ident = m.group("ident").strip()
        return f"no untrusted-input-to-sink data flow involving {ident}; code is safe"
    if CWE_RE.search(val) or "CWE-XX" in val.upper():
        stripped = CWE_RE.sub("", val)
        stripped = re.sub(r"CWE-XX", "", stripped, flags=re.IGNORECASE).strip(" -|:")
        return stripped if len(stripped) >= 8 else _SAFE_TRACE_FALLBACK
    return val


def normalize_safe_assistant(content: str) -> str:
    """Rewrite the structured fields of a `safe` assistant payload to be
    internally consistent. Leaves the <think> block untouched.

    - status -> safe
    - cwe, severity, line -> none
    - trace -> safe-flow summary (CWE references removed)
    - fix -> kept as-is (e.g. shape3's "n/a — code is safe")
    - follow_up_refs / open_refs lists -> kept
    - dangling vuln-narrative lines after `trace:` -> dropped
    """
    think_match = THINK_RE.search(content)
    if think_match:
        head = content[: think_match.end()]
        tail = content[think_match.end():]
    else:
        head, tail = "", content

    out: list[str] = []
    in_trace_continuation = False
    in_refs_block = False
    for line in tail.splitlines():
        fm = _SAFE_FIELD_RE.match(line)
        if fm:
            in_refs_block = False
            key = fm.group("key").lower()
            indent, sep, val = fm.group("indent"), fm.group("sep"), fm.group("val").strip()
            in_trace_continuation = False
            if key == "status":
                val = "safe"
            elif key in ("cwe", "severity", "line"):
                val = "none"
            elif key == "trace":
                val = _clean_safe_trace(val)
                in_trace_continuation = True  # drop any narrative that follows
            # `fix` is kept verbatim
            out.append(f"{indent}{key}{sep}{val}")
            continue
        if _REFS_RE.match(line):
            in_trace_continuation = False
            in_refs_block = True
            out.append(line)
            continue
        if in_refs_block and _LIST_ITEM_RE.match(line):
            out.append(line)
            continue
        if in_trace_continuation and line.strip():
            # dangling vuln-style narrative under the rewritten trace — drop it
            continue
        out.append(line)

    return head + "\n".join(out)
