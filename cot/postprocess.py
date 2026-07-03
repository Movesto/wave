"""Post-process raw scanner output into clean, well-formed fields.

The fine-tuned model is reliable on the VERDICT (status/cwe/severity) but on
verbose-reasoning cases it degrades the tail fields: `trace:` runs on or
truncates, `fix:` echoes the analysis prose/markdown, and the `<think>` block
sometimes invents a specific CVE id it can't substantiate. This module repairs
those fields deterministically so the product always emits clean output. It
NEVER changes the verdict fields, only tidies trace/fix/line and strips
unverifiable CVE citations from the reasoning.
"""
import re

FIELDS = ["status", "cwe", "severity", "line", "trace", "fix"]
_FIELD_RE = re.compile(r"^\s*(status|cwe|severity|line|trace|fix)\s*:\s*(.*)$", re.I)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{3,7}\b", re.I)

# Deterministic remediation fallback when the model's `fix` field is degraded
# (echoes analysis / markdown / empty). Keyed by CWE id.
_CWE_FIX = {
    "CWE-89": "Use parameterized queries / prepared statements; never interpolate input into SQL.",
    "CWE-78": "Avoid shell execution with untrusted input; use subprocess with an argument list (no shell=True) and validate/allowlist the input.",
    "CWE-79": "Escape or encode user input before inserting into the DOM; use textContent or an auto-escaping template, not innerHTML.",
    "CWE-22": "Resolve and confine paths to an allowed base directory; reject '..' and absolute paths.",
    "CWE-502": "Do not deserialize untrusted data; use a safe format (JSON) or a signed/allowlisted deserializer.",
    "CWE-327": "Use a strong, current algorithm (e.g. AES-GCM, SHA-256+); avoid MD5/SHA1/DES/ECB.",
    "CWE-94": "Never pass untrusted input to eval/exec/dynamic code; use a safe parser or allowlist.",
    "CWE-798": "Remove hardcoded credentials; load secrets from a vault or environment configuration.",
    "CWE-918": "Validate and allowlist outbound URLs/hosts; block internal address ranges.",
    "CWE-601": "Validate redirect targets against an allowlist of known-safe URLs.",
}


def _is_degraded(value: str) -> bool:
    """A trace/fix value that looks like echoed analysis rather than a concise field."""
    if not value:
        return True
    v = value.strip()
    if "**" in v:                       # markdown header echo
        return True
    if re.match(r"(?i)^(specific code|the specific code|mechanism of|analysis of|"
                r"potential impact|contextual relevance|step \d)", v):
        return True
    if v.endswith(("...", "—")) or re.search(r"\b\w{1,3}$", v) and len(v) > 140:
        return True                     # mid-word truncation on a long run-on
    return False


_PROSE_TRACE = re.compile(
    r"the vulnerabilit|is (?:primarily |)related|handling of|argument in|because of|"
    r"due to|this (?:code|function|line)|specific code|mechanism of|note that|refers to",
    re.I)
# a "strong" code token: a call foo(...), a dotted name a.b.c, or a --flag.
_CODE_TOK = re.compile(r"[A-Za-z_][\w.]*\([^)]*\)|[A-Za-z_]\w*(?:\.\w+)+|--?[A-Za-z][\w-]+")


def _trim_trace(value: str) -> str:
    """Keep the concise source->sink chain (or sink construct); drop prose."""
    v = value.replace("`", "").strip()
    # 1. If it already has an arrow chain, keep it — only drop trailing prose.
    if "->" in v or "→" in v:
        for sep in [" — ", " -- ", ". ", "; Since", " Since ", ", an attacker",
                    ", because", " which ", " where the "]:
            if sep in v:
                v = v.split(sep, 1)[0].strip()
                break
        return v.rstrip(",")[:160]
    # 2. Cut trailing prose at a separator, keeping a code-construct head.
    for sep in [" — ", " -- ", ". ", "; Since", " Since ", ", an attacker", ", because"]:
        if sep in v:
            head = v.split(sep, 1)[0].strip()
            if re.search(r"[=(]", head) or "->" in head:
                return head.rstrip(",")[:160]
    # 3. Degraded prose (analysis dumped into the field): extract the code tokens
    #    it mentions and present a minimal chain, instead of keeping the prose.
    if _PROSE_TRACE.search(v) or len(v) > 130:
        toks = []
        for t in _CODE_TOK.findall(v):
            t = t.strip()
            if t not in toks:
                toks.append(t)
            if len(toks) >= 3:
                break
        if toks:
            return " -> ".join(toks)[:160]
        return v.split(".")[0].strip()[:90]        # last resort: first clause
    # 4. Otherwise it's already a short code construct / sentence — keep it.
    return re.split(r"(?<=[.;])\s", v, 1)[0].strip().rstrip(",")[:160]


def _clean_value(field: str, value: str, cwe: str) -> str:
    v = re.sub(r"\*\*", "", value).strip().strip("`").strip()
    if field == "trace":
        return _trim_trace(v)
    if field == "fix":
        if _is_degraded(value):
            return _CWE_FIX.get(cwe.upper(), "Validate/neutralize the untrusted input before it reaches the sink.")
        # keep first 1-2 sentences, no markdown
        v = " ".join(re.split(r"(?<=[.])\s", v)[:2]).strip()
        return v
    return v


def _clean_think(think: str) -> str:
    """Drop sentences that cite an unverifiable specific CVE id (hallucination guard)."""
    if not _CVE_RE.search(think):
        return think
    parts = re.split(r"(?<=[.!?])\s+", think)
    kept = [s for s in parts if not _CVE_RE.search(s)]
    return " ".join(kept).strip() if kept else _CVE_RE.sub("the relevant weakness", think)


def clean_scan_output(raw: str) -> str:
    """Repair a raw shape1 scan into clean think + canonical concise fields."""
    think = ""
    m = re.search(r"<think>(.*?)</think>", raw, re.S)
    if m:
        think = _clean_think(m.group(1).strip())
        body = raw[m.end():]
    else:
        body = raw

    # Parse fields; a value runs until the next field marker.
    found, cur_key, cur_val = {}, None, []
    for line in body.splitlines():
        fm = _FIELD_RE.match(line)
        if fm:
            if cur_key:
                found[cur_key] = " ".join(cur_val).strip()
            cur_key, cur_val = fm.group(1).lower(), [fm.group(2)]
        elif cur_key:
            cur_val.append(line.strip())
    if cur_key:
        found[cur_key] = " ".join(cur_val).strip()

    # Only normalize shape1-style verdicts; leave other shapes' output untouched.
    if "status" not in found and "cwe" not in found:
        return raw

    # Normalize the CWE field: unicode hyphens -> ASCII, bare number -> CWE-N.
    if "cwe" in found:
        cv = re.sub(r"[‐-―−]", "-", found["cwe"]).strip()
        if re.fullmatch(r"\d{1,4}", cv):
            cv = f"CWE-{cv}"
        m = re.search(r"CWE-\d+", cv, re.I)
        found["cwe"] = m.group(0).upper() if m else cv

    # Safe-verdict coherence: a safe record must not carry vuln-only fields.
    status = found.get("status", "").lower()
    if status == "safe":
        found["cwe"] = "none"
        for f in ("severity", "line", "fix"):
            if f in found:
                found[f] = "none"

    cwe = found.get("cwe", "none")
    out = []
    if think:
        out.append(f"<think>\n{think}\n</think>\n")
    for f in FIELDS:
        if f in found:
            out.append(f"{f}: {_clean_value(f, found[f], cwe)}")
    return "\n".join(out)
