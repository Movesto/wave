# ============================================================
# cot/vuln_types.py
#
# Vulnerability-TYPE taxonomy. Classifies a code hunk into a vuln
# type from its sinks/patterns, so the verified pipeline can be
# organized and BALANCED by type (XSS, SQLi, cmd-injection, ...)
# instead of by language. Type transfers across languages, and the
# eval's blind spots were specific TYPES (auth/crypto/access-control),
# so balancing by type is how we fill them.
#
# Heuristic + order-sensitive (most specific / highest-confidence
# sinks first). Returns (type, representative_cwe). Pure logic.
# ============================================================
import re

# (type, cwe, regex). Order matters — first match wins.
TAXONOMY = [
    ("sql_injection",      "CWE-89",
     r"cursor\.execute|\.execute\s*\(|\.executemany|\.query\s*\(|raw_query|sequelize\.query"
     r"|(SELECT|INSERT|UPDATE|DELETE)\b[^\n;]*(\+|%s|\$\{|f[\"'])|db\.(query|raw)"),
    ("command_injection",  "CWE-78",
     r"os\.system|subprocess\.\w+\([^)]*shell\s*=\s*True|child_process\.(exec|execSync|spawn|spawnSync)"
     r"|\bexec\s*\(|\bpopen\b|Runtime\.getRuntime|ProcessBuilder|`[^`]*\$\{"),
    ("code_injection",     "CWE-94",
     r"\beval\s*\(|new Function\s*\(|\bFunction\s*\(|ast\.literal_eval|\bcompile\s*\(|vm\.runIn|setTimeout\s*\(\s*[\"']"),
    ("deserialization",    "CWE-502",
     r"pickle\.(load|loads)|yaml\.(load|unsafe_load)|marshal\.loads|cPickle|unserialize|ObjectInputStream|__reduce__|jsonpickle"),
    ("xxe",                "CWE-611",
     r"etree|XMLParser|SAXParser|DocumentBuilder|libxml|lxml|parseXml|XMLReader|expatreader"),
    ("xss",                "CWE-79",
     r"innerHTML|dangerouslySetInnerHTML|insertAdjacentHTML|document\.write|\.html\s*\(|render_template_string|mark_safe|\|\s*safe|v-html|outerHTML"),
    ("ssrf",               "CWE-918",
     r"requests\.(get|post|put|request)|urlopen|urlretrieve|\bfetch\s*\(|axios|http\.(get|request)|got\(|node-fetch|HttpClient|URLConnection"),
    ("path_traversal",     "CWE-22",
     r"send_?file|sendFile|os\.path\.join|readFile|writeFile|fs\.(read|create|write)|open\s*\([^)]*(path|file|name|dir)|static_file|\.\./|FileInputStream"),
    ("open_redirect",      "CWE-601",
     r"\bredirect\s*\(|location\.(href|assign|replace)|res\.redirect|HttpResponseRedirect|sendRedirect|window\.location"),
    ("prototype_pollution","CWE-1321",
     r"__proto__|constructor[\"'\].]*prototype|deepmerge|deep_merge|_\.merge|lodash.*merge|Object\.assign\s*\(\s*\w+\s*,\s*req"),
    ("crypto_weak",        "CWE-327",
     r"\bmd5\b|\bsha1\b|\bDES\b|\bECB\b|\bRC4\b|createCipher\b|Math\.random|random\.(random|randint)[^\n]*(token|secret|key|password)"),
    ("hardcoded_secret",   "CWE-798",
     r"(secret|password|passwd|api_?key|access_?key|token|private_?key)\s*[:=]\s*[\"'][^\"'\n]{8,}[\"']|BEGIN (RSA |EC )?PRIVATE KEY"),
    ("access_control",     "CWE-284",
     r"is_?admin|is_?superuser|has_?perm|@?login_required|@?permission|\brole\b|authorize|access_control|request\.user|current_user|isAuthenticated"),
    ("auth",               "CWE-287",
     r"authenticate|\blogin\b|\bjwt\b|\bsession\b|verify_password|check_password|bcrypt|passport|set_password|comparePassword"),
]

OTHER = ("other", None)


def classify(code: str) -> tuple:
    """Return (vuln_type, representative_cwe) for a code hunk, by first sink match."""
    for vtype, cwe, pat in TAXONOMY:
        if re.search(pat, code, re.I):
            return (vtype, cwe)
    return OTHER


ALL_TYPES = [t for t, _, _ in TAXONOMY] + ["other"]
