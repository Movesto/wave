"""Per-CWE reasoning contracts — authored once, above the weak-model ceiling.

Each contract encodes, for a vulnerability family:
  - cwes      : the CWE ids that belong to the family
  - markers   : vocabulary/sink terms a CORRECT trace for this family uses
  - sink      : the canonical sink phrase (for template reasoning, Wave 2/3)
  - control   : what neutralizes it (for SAFE-trace reasoning)

Two uses:
  1. cross-CWE bleed check (now)  — a trace labelled family A must not read like
     family B (e.g. a SQLi trace describing innerHTML/XSS).
  2. template reasoning (Wave 2/3) — assemble oracle-grounded <think> deterministically.
"""
import re

CONTRACTS = {
    # markers are SPECIFIC sink/concept terms — generic cross-cutting words
    # (injection, validation, user input, url, html, hash, escape) are deliberately
    # excluded so the bleed check doesn't false-fire on incidental vocabulary.
    "xss": {
        "cwes": {"CWE-79", "CWE-80"},
        "markers": ["innerhtml", "dangerouslysetinnerhtml", "document.write",
                    "cross-site script", "xss", "into the dom", "rendered into"],
        "sink": "rendered into the page/DOM without escaping",
        "control": "output is HTML-escaped / encoded before rendering",
    },
    "sql": {
        "cwes": {"CWE-89"},
        "markers": ["sql ", "select ", "insert into", "where ", ".query(", "cursor",
                    "prepared statement", "sql query", "sql statement"],
        "sink": "concatenated into a SQL query",
        "control": "uses a parameterized query / bound placeholder",
    },
    "command": {
        "cwes": {"CWE-77", "CWE-78", "CWE-88"},
        "markers": ["os.system", "subprocess", "shell", "popen", "shell=true",
                    "/bin/sh", "command string", "os command"],
        "sink": "passed to a shell/OS command",
        "control": "uses an argument list (no shell) and validates input",
    },
    "code_injection": {
        "cwes": {"CWE-94", "CWE-95", "CWE-1321"},
        "markers": ["eval(", "exec(", "prototype pollution", "__proto__",
                    "code execution", "arbitrary code", "ast.call", "template injection"],
        "sink": "interpreted as code / merged into an object prototype",
        "control": "no dynamic code execution; safe parser / key allow-list",
    },
    "path": {
        "cwes": {"CWE-22", "CWE-23", "CWE-36"},
        "markers": ["path travers", "../", "directory travers", "os.path",
                    "filepath", "file path", "base dir"],
        "sink": "used to build a filesystem path",
        "control": "path is confined to a base dir; '..' rejected",
    },
    "ssrf": {
        "cwes": {"CWE-918"},
        "markers": ["ssrf", "server-side request", "requests.get", "urlopen",
                    "outbound request", "fetch the url", "internal address"],
        "sink": "used as the target of a server-side HTTP request",
        "control": "destination host/URL is validated against an allow-list",
    },
    "deserialization": {
        "cwes": {"CWE-502"},
        "markers": ["deserializ", "pickle", "unserialize", "yaml.load", "marshal",
                    "objectinputstream"],
        "sink": "deserialized from untrusted data",
        "control": "safe format (JSON) / signed or allow-listed deserialization",
    },
    "crypto": {
        "cwes": {"CWE-326", "CWE-327", "CWE-328", "CWE-338", "CWE-347", "CWE-916"},
        "markers": ["md5", "sha1", "3des", " des ", "ecb mode", "weak cipher",
                    "weak hash", "insecure random", "cipher", "signature verif"],
        "sink": "used in a security-sensitive cryptographic operation",
        "control": "strong, current algorithm with proper verification",
    },
    "auth": {
        "cwes": {"CWE-287", "CWE-306", "CWE-862", "CWE-863", "CWE-284", "CWE-285",
                 "CWE-639", "CWE-522", "CWE-521"},
        "markers": ["authoriz", "authentic", "access control", "permission check",
                    "privilege", "idor", "missing auth", "without auth"],
        "sink": "reached without an authorization/authentication check",
        "control": "an explicit access-control / authentication check guards it",
    },
    "redirect": {
        "cwes": {"CWE-601"},
        "markers": ["open redirect", "redirect to", "redirect target", "location header"],
        "sink": "used as a redirect target",
        "control": "redirect target validated against an allow-list",
    },
    "xxe": {
        "cwes": {"CWE-611"},
        "markers": ["xxe", "xml external entity", "doctype", "external entity",
                    "xml parser", "etree", "saxparser"],
        "sink": "parsed by an XML parser with external entities enabled",
        "control": "external entity resolution disabled",
    },
    "csrf": {
        "cwes": {"CWE-352"},
        "markers": ["csrf", "cross-site request forgery", "anti-csrf", "samesite"],
        "sink": "state-changing request without anti-CSRF protection",
        "control": "anti-CSRF token / SameSite cookie enforced",
    },
    "info_exposure": {
        "cwes": {"CWE-200", "CWE-209", "CWE-212", "CWE-532"},
        "markers": ["information exposure", "information disclosure", "leak", "exposes",
                    "stack trace", "sensitive data", "exposed in the response", "logged"],
        "sink": "written to a log / response, exposing sensitive data",
        "control": "sensitive data redacted / not logged",
    },
    "dos": {
        "cwes": {"CWE-400", "CWE-770", "CWE-1333", "CWE-834", "CWE-405"},
        "markers": ["denial of service", "redos", "catastrophic backtrack", "unbounded",
                    "resource exhaust", "without a limit", "infinite loop"],
        "sink": "consumes unbounded resources / catastrophic backtracking",
        "control": "a size/iteration limit bounds the work",
    },
    "input_validation": {
        "cwes": {"CWE-20", "CWE-74"},
        "markers": ["improper input validation", "tainted", "neutraliz special"],
        "sink": "reaches a sensitive operation without validation",
        "control": "input is validated / neutralized first",
    },
}

_CWE2FAM = {c: fam for fam, d in CONTRACTS.items() for c in d["cwes"]}


def family_of(cwe):
    if not cwe:
        return None
    return _CWE2FAM.get(cwe.upper().strip())


def _hits(text, markers):
    t = text.lower()
    return sum(1 for m in markers if m in t)


def check_bleed(text, label_cwe):
    """Flag a trace whose narrative reads like a DIFFERENT family than its label.

    Conservative: only fails when another family clearly dominates AND the trace's
    own family is absent. Returns (ok, reason).
    """
    fam = family_of(label_cwe)
    if fam is None:
        return True, "cwe-not-in-taxonomy"
    own = _hits(text, CONTRACTS[fam]["markers"])
    # strongest competing family
    best_other, best_n = None, 0
    for f, d in CONTRACTS.items():
        if f == fam:
            continue
        n = _hits(text, d["markers"])
        if n > best_n:
            best_other, best_n = f, n
    # conservative: only flag when a competing family CLEARLY dominates and the
    # trace's own family is entirely absent (avoids incidental-vocabulary trips).
    if own == 0 and best_n >= 3:
        return False, f"reads like '{best_other}' not '{fam}' (own=0, other={best_n})"
    return True, "ok"
