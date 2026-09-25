"""CWE metadata -- a human name, a severity, and a one-line remediation per class wave proves.

Deterministic lookup (no model). The report uses it so a finding reads as "CWE-89 (SQL Injection, high) --
use parameterized queries" instead of a bare id, and so findings can be ordered by severity. Keyed by CWE id
with a fallback by class label, so a finding is still described even when the model's CWE label is fuzzy.
"""
from __future__ import annotations

# cwe id -> (short name, severity, one-line remediation)
_CWE = {
    "CWE-89":   ("SQL Injection", "high", "Use parameterized queries / prepared statements; never build SQL by string concatenation."),
    "CWE-943":  ("NoSQL Injection", "high", "Never let user input become a query operator; coerce to the expected scalar type; use a query builder."),
    "CWE-78":   ("OS Command Injection", "critical", "Don't invoke a shell; pass arguments as a list (never a shell string) and allow-list the command."),
    "CWE-77":   ("Command Injection", "critical", "Avoid shell interpolation; pass args as a vector and validate against an allow-list."),
    "CWE-79":   ("Cross-Site Scripting (XSS)", "high", "Contextually escape output / rely on the framework's auto-escaping; never emit raw untrusted HTML."),
    "CWE-80":   ("Cross-Site Scripting (XSS)", "high", "Escape HTML special characters on output; prefer a templating engine that auto-escapes."),
    "CWE-22":   ("Path Traversal", "high", "Resolve the real path and confirm it stays under an allowed base dir; reject '..'; use a safe path-join."),
    "CWE-918":  ("Server-Side Request Forgery (SSRF)", "high", "Allow-list destination hosts; block internal/link-local ranges; disable redirects to internal targets."),
    "CWE-502":  ("Insecure Deserialization", "critical", "Don't feed untrusted data to a deserializer that can execute code or instantiate arbitrary types (pickle, Java readObject, PHP unserialize, YAML full-load); use a safe, typed, data-only format. (Note: Rust serde / typed-struct deserialization does NOT execute code and is not this.)"),
    "CWE-601":  ("Open Redirect", "medium", "Only allow relative paths or an allow-list of hosts; reject absolute and protocol-relative URLs."),
    "CWE-95":   ("Code Injection (eval)", "critical", "Never eval/exec untrusted input; use a safe parser or a capability-free sandbox."),
    "CWE-1336": ("Server-Side Template Injection", "high", "Never render user input as a template; pass it as data into a fixed template."),
    "CWE-1321": ("Prototype Pollution", "high", "Reject __proto__/constructor keys in merges; use Map or null-prototype objects; guard recursive merges."),
    "CWE-639":  ("IDOR / Broken Object-Level Authorization", "high", "Verify the authenticated caller owns or may access the object BEFORE returning/mutating it."),
    "CWE-284":  ("Improper Access Control", "high", "Enforce an authorization check on every sensitive operation; deny by default."),
    "CWE-862":  ("Missing Authorization", "high", "Add an authorization check to the handler; don't rely on the UI hiding the route."),
    "CWE-863":  ("Incorrect Authorization", "high", "Fix the authorization logic so it checks the acting user against the target resource's owner/role."),
    "CWE-120":  ("Buffer Overflow", "critical", "Bound every copy (snprintf/strncpy with correct sizes); validate input lengths before copying."),
    "CWE-125":  ("Out-of-Bounds Read", "high", "Bounds-check indices/offsets against the buffer length before reading."),
    "CWE-787":  ("Out-of-Bounds Write", "critical", "Bounds-check destination size before writing; avoid unbounded copies."),
    "CWE-416":  ("Use After Free", "critical", "Null the pointer after free; don't use freed memory; consider ownership/RAII."),
    "CWE-134":  ("Format String", "high", "Never pass untrusted input as a format string; use a constant format with explicit arguments."),
    "CWE-190":  ("Integer Overflow", "medium", "Range-check arithmetic on untrusted sizes; use checked or widening operations."),
    "CWE-248":  ("Uncaught Exception / Denial of Service", "medium", "Handle errors explicitly; avoid unwrap()/expect()/unchecked parses on untrusted input."),
}

# class label (the notebook/detector's coarse tag) -> a representative CWE, for when no CWE id is present
_CLASS_CWE = {
    "sqli": "CWE-89", "nosqli": "CWE-943", "cmd": "CWE-78", "xss": "CWE-79", "path": "CWE-22",
    "ssrf": "CWE-918", "deser": "CWE-502", "redirect": "CWE-601", "eval": "CWE-95", "ssti": "CWE-1336",
    "protopollution": "CWE-1321", "authz": "CWE-639", "idor": "CWE-639", "memory": "CWE-120",
    "format": "CWE-134", "panic": "CWE-248",
}

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def describe(cwe="", cls=""):
    """Return (name, severity, remediation) for a CWE id (or, failing that, a class label). Always returns
    something -- a generic entry when the class is unknown -- so the report never shows a bare id."""
    cwe = (cwe or "").upper().strip()
    if cwe in _CWE:
        return _CWE[cwe]
    mapped = _CLASS_CWE.get((cls or "").lower().strip())
    if mapped and mapped in _CWE:
        return _CWE[mapped]
    return ("Potential security issue", "unknown", "Review the flagged code: confirm whether untrusted input reaches this operation and add the appropriate validation/encoding.")


def severity(cwe="", cls=""):
    return describe(cwe, cls)[1]


def sev_rank(cwe="", cls=""):
    return _SEV_RANK.get(severity(cwe, cls), 4)
