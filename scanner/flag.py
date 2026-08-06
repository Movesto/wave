"""Layer A — fast, deterministic vulnerability flagger (CPU, no model, no Semgrep).

Station 1 of the pipeline. Two detector types:
  1. TAINT (source->sink): only flags when untrusted input actually reaches a sink
     inside a function. Python via AST; JS/TS via lightweight regex taint.
  2. PATTERN: high-precision anti-patterns that aren't data-flow (weak crypto,
     verbose-error info-exposure, disabled TLS verify, hardcoded secrets, eval).

Precision-first: a parameterized query, a sink fed by constants, or MD5 used for a
cache key are NOT flagged. Candidates feed the 8B model (Station 2/3: triage + fix).

  python flag.py app.py | backend/ | app.jsx   [--json]
"""
import ast, re, sys, json, argparse
from pathlib import Path
from dataclasses import dataclass, asdict

EXT_LANG = {".py": "py", ".js": "js", ".ts": "js", ".jsx": "js", ".tsx": "js", ".mjs": "js"}

# ================= Python taint (AST) =================
_SRC_ATTR = re.compile(
    r"^(request|req|flask_request|self\.request)\.(args|form|json|values|data|files|"
    r"cookies|headers|GET|POST|body|params|query|url|path)$", re.I)
_SRC_CALL = re.compile(r"\.get_json$|^input$|\.getvalue$")
PY_SINKS = [
    (re.compile(r"\.execute(many|script)?$|\.raw$|\.mogrify$"), "CWE-89", "sql injection", 0),
    (re.compile(r"^os\.(system|popen)$|\.popen$"), "CWE-78", "command injection", 0),
    (re.compile(r"^subprocess\.(run|call|check_output|check_call|Popen)$"), "CWE-78", "command injection", 0),
    (re.compile(r"^(eval|exec|compile)$"), "CWE-94", "code injection", 0),
    (re.compile(r"^(pickle|cPickle|_pickle|marshal)\.loads?$|^yaml\.load$"), "CWE-502", "insecure deserialization", 0),
    (re.compile(r"^open$|\.send_file$|^send_file$|\.FileResponse$|^FileResponse$"), "CWE-22", "path traversal", 0),
    (re.compile(r"^(requests|httpx|aiohttp)\.(get|post|put|delete|request|head)$"
                r"|^urllib\.request\.(urlopen|urlretrieve)$|^urlopen$|^urlretrieve$"), "CWE-918", "ssrf", 0),
    (re.compile(r"\.render_template_string$|^render_template_string$|^Markup$"), "CWE-79", "xss", 0),
]


@dataclass
class Candidate:
    file: str
    unit: str
    line: int
    cwe: str
    family: str
    detector: str   # "taint" | "pattern"
    sink: str


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        b = _dotted(node.value)
        return f"{b}.{node.attr}" if b else node.attr
    return ""


def _is_source(node):
    if isinstance(node, ast.Attribute):
        return bool(_SRC_ATTR.match(_dotted(node)))
    if isinstance(node, ast.Subscript):
        d = _dotted(node.value)
        return bool(_SRC_ATTR.match(d)) or d.endswith("argv")
    if isinstance(node, ast.Call):
        d = _dotted(node.func)
        return bool(_SRC_CALL.search(d)) or d == "input"
    return False


def _tainted(node, taint):
    if node is None:
        return False
    if _is_source(node):
        return True
    if isinstance(node, ast.Name):
        return node.id in taint
    if isinstance(node, ast.Attribute):
        return _tainted(node.value, taint)
    if isinstance(node, ast.Subscript):
        return _tainted(node.value, taint)
    if isinstance(node, ast.Call):
        return _tainted(node.func, taint) or any(_tainted(a, taint) for a in node.args)
    if isinstance(node, ast.BinOp):
        return _tainted(node.left, taint) or _tainted(node.right, taint)
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) and _tainted(v.value, taint) for v in node.values)
    if isinstance(node, ast.BoolOp):
        return any(_tainted(v, taint) for v in node.values)
    return False


def _targets(t):
    out = []
    for n in ([t] if not isinstance(t, (list, tuple)) else t):
        if isinstance(n, ast.Name):
            out.append(n.id)
        elif isinstance(n, (ast.Tuple, ast.List)):
            for e in n.elts:
                out += _targets(e)
    return out


def _py_taint(fn, whole, filename):
    taint = set()
    assigns = [n for n in ast.walk(fn) if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign))]
    for _ in range(3):
        before = len(taint)
        for a in assigns:
            rhs = getattr(a, "value", None)
            if rhs is not None and _tainted(rhs, taint):
                tgt = a.targets if isinstance(a, ast.Assign) else [a.target]
                for t in tgt:
                    for nm in _targets(t):
                        taint.add(nm)
        if len(taint) == before:
            break
    out = []
    for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
        d = _dotted(call.func)
        if not d:
            continue
        for rx, cwe, fam, argi in PY_SINKS:
            if rx.search(d):
                arg = call.args[argi] if len(call.args) > argi else None
                kw = next((k.value for k in call.keywords if k.arg in
                          ("url", "query", "sql", "cmd", "command", "path", "filename")), None)
                if _tainted(arg, taint) or _tainted(kw, taint):
                    try:
                        txt = ast.get_source_segment(whole, call) or d
                    except Exception:
                        txt = d
                    out.append(Candidate(filename, fn.name, call.lineno, cwe, fam, "taint", txt.strip()[:120]))
                break
    return out


# ================= Non-taint PATTERN detectors (both langs) =================
# (regex, cwe, family, langs, needs_security_context)
PATTERNS = [
    (re.compile(r"hashlib\.(md5|sha1)\(|createHash\(\s*['\"](md5|sha1)['\"]", re.I), "CWE-327", "weak hashing", "any", True),
    (re.compile(r"\bDES\b|MODE_ECB|['\"]ecb['\"]", re.I), "CWE-327", "weak cipher", "any", False),
    (re.compile(r"detail\s*=\s*f?[\"'][^\"']*\{\s*(e|err|error|exc|ex)\s*\}"), "CWE-209", "info exposure via error", "py", False),
    (re.compile(r"(requests|httpx|session|urlopen|\.get|\.post|ssl|SSLContext|create_default_context)"
                r"[^)\n]*verify\s*=\s*False|rejectUnauthorized:\s*false|CERT_NONE"), "CWE-295", "TLS verification disabled", "any", False),
    (re.compile(r"\.run\([^)]*debug\s*=\s*True"), "CWE-489", "debug mode enabled", "py", False),
    (re.compile(r"(?i)(secret|passw(or)?d|api[_-]?key|private[_-]?key|access[_-]?token)\s*[:=]\s*[\"'][A-Za-z0-9+/_\-]{12,}[\"']"),
     "CWE-798", "hardcoded secret", "any", False),
    (re.compile(r"\beval\(|new Function\("), "CWE-95", "dynamic eval", "js", False),
    (re.compile(r"(random\.(random|randint|choice|randrange|getrandbits|uniform)|Math\.random)\("),
     "CWE-338", "insecure randomness for security value", "any", True),   # gated: only near token/secret/password
    (re.compile(r"resolve_entities\s*=\s*True|no_network\s*=\s*False|XMLParser\(\s*\)"),
     "CWE-611", "XXE (external entities enabled)", "any", False),
    (re.compile(r"jsonpickle\.decode|node-serialize|unserialize\(|Runtime\.getRuntime\(\)\.exec"),
     "CWE-502", "insecure deserialization / runtime exec", "any", False),
    (re.compile(r"jwt\.decode\([^)]*verify\s*=\s*False|verify_signature[\"']?\s*:\s*False|"
                r"algorithms\s*=\s*\[\s*[\"']none[\"']", re.I),
     "CWE-347", "JWT signature verification disabled", "any", False),
    (re.compile(r"allow_origins\s*=\s*\[\s*[\"']\*[\"']|Access-Control-Allow-Origin[\"']?\s*[:=,]\s*[\"']\*[\"']", re.I),
     "CWE-942", "overly permissive CORS (wildcard origin)", "any", False),
    (re.compile(r"\.(save|update|delete|get)\([^)]*\bid\s*=\s*(request|req|params|kwargs|self\.request)"
                r"|filter_by\(\s*id\s*=\s*(request|req|params)", re.I),
     "CWE-639", "object access by user-supplied id without owner check (possible IDOR)", "py", True),

    # ---- FLOW-FREE SINK PATTERNS -------------------------------------------
    # The taint engine only starts a flow at a recognised request object IN THE SAME
    # FUNCTION as the sink (_SRC_ATTR). A helper that takes the tainted value as a
    # PARAMETER is therefore invisible to it -- which is the ordinary shape of real
    # code: the route pulls request.args["x"] and hands it to a helper that does the
    # work. Measured on a planted test: 5 of 7 vulnerabilities were never surfaced,
    # including string-concatenated SQL and shell=True, so the model never saw them.
    #
    # These patterns need no flow: the CONSTRUCT itself is the defect wherever the
    # value came from. Concatenation/interpolation into the dangerous call is the
    # signal; a fully literal argument is not matched.
    (re.compile(r"(?:execute|executemany|executescript|raw|query)\s*\(\s*"
                r"(?:f[\"']|[\"'][^\"']*[\"']\s*(?:\+|%|\.format\()|[\w.]+\s*\+)",
                re.I),
     "CWE-89", "SQL built by concatenation/interpolation instead of parameters", "any", False),

    (re.compile(r"shell\s*=\s*True"),
     "CWE-78", "subprocess with shell=True", "py", False),

    (re.compile(r"(?:os\.system|os\.popen|commands\.getoutput)\s*\(\s*"
                r"(?:f[\"']|[\"'][^\"']*[\"']\s*(?:\+|%|\.format\()|[\w.]+\s*\+)"),
     "CWE-78", "shell command built by concatenation/interpolation", "py", False),

    (re.compile(r"(?:child_process\.)?(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|"
                r"[\"'][^\"']*[\"']\s*\+|[\w.]+\s*\+)"),
     "CWE-78", "shell command built by concatenation/template literal", "js", False),

    (re.compile(r"\bopen\s*\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*\+|[\w.]+\s*\+\s*[\w.]+)"
                r"|os\.path\.join\s*\([^)]*\+"),
     "CWE-22", "file path built by concatenation", "py", False),

    (re.compile(r"(?:readFile|readFileSync|createReadStream|sendFile)\s*\(\s*"
                r"(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+|[\w.]+\s*\+)"),
     "CWE-22", "file path built by concatenation", "js", False),

    (re.compile(r"(?:requests\.(?:get|post|put|head|delete)|urlopen|httpx\.(?:get|post))"
                r"\s*\(\s*(?!['\"]https?://[\w.-]+['\"]\s*[,)])[\w.]+\s*[,)]"),
     "CWE-918", "outbound request to a non-literal URL", "py", False),

    # File-serving and redirect sinks fed by a VARIABLE (not a bare string literal).
    # These often HAVE a guard -- `if (!file.includes("/"))` -- so they are exactly where
    # the witness verifier earns its keep. The taint engine misses them because the value
    # arrives as a function parameter, not a request object in the same scope.
    (re.compile(r"(?:res|response)\.(?:sendFile|download)\s*\(\s*"
                r"(?!['\"][^'\"]*['\"]\s*\))[\w.]"),
     "CWE-22", "file served from a non-literal path (check the guard)", "js", False),
    (re.compile(r"send_file\s*\(\s*(?!['\"][^'\"]*['\"]\s*\))[\w.]"),
     "CWE-22", "file served from a non-literal path (check the guard)", "py", False),
    (re.compile(r"(?:res|response)\.redirect\s*\(\s*"
                r"(?!['\"][^'\"]*['\"]\s*\))[\w.]"),
     "CWE-601", "redirect to a non-literal target (check the guard)", "js", False),

    # Prototype pollution: a recursive descent `merge(target[k], source[k])` (two
    # bracket-indexed args is the deep-merge idiom, rare elsewhere) or a deep merge/set
    # library call. These copy a user object by dynamic key, so a key of __proto__/
    # constructor reaches Object.prototype -- the witness then checks the key blocklist.
    # SAME index var on both args (backref) and a multi-char name -- so a merge over object
    # keys (`merge(target[key], source[key])`) matches, but array ops with 1-char counters
    # (`Math.max(a[i], b[i])`) or differing indices (`swap(arr[i], arr[j])`) do not.
    (re.compile(r"[\w$]+\s*\(\s*[\w$]+\[([a-zA-Z_$][\w$]+)\]\s*,\s*[\w$]+\[\1\]\s*\)"),
     "CWE-1321", "recursive merge by dynamic key (prototype pollution risk)", "any", False),
    (re.compile(r"_\.(?:merge|mergeWith|defaultsDeep|set|setWith)\s*\(|"
                r"\bdeepmerge\s*(?:\.all)?\s*\(|\$\.extend\s*\(\s*true\b"),
     "CWE-1321", "deep merge / set library call (prototype pollution risk)", "js", False),
]
_SEC_CTX = re.compile(r"password|passwd|token|secret|sign|hmac|hash_|cert|credential|auth|"
                      r"user_id|owner|current_user|permission", re.I)
_SECRET_ENV = re.compile(r"environ|getenv|process\.env|config\.|settings\.|placeholder|changeme|example|xxxx", re.I)


def _pattern_scan(code, lang, filename, unit_lookup):
    out = []
    lines = code.splitlines()
    for rx, cwe, fam, langs, need_ctx in PATTERNS:
        if langs != "any" and langs != lang:
            continue
        for m in rx.finditer(code):
            line = code[:m.start()].count("\n") + 1
            unit = unit_lookup(line)
            # security-context gate: the match's own line + its function name only
            # (a wide window bleeds into adjacent functions -> false positives).
            ctx = (lines[line - 1] if line - 1 < len(lines) else "") + " " + unit
            if need_ctx and not _SEC_CTX.search(ctx):
                continue                                   # e.g. MD5 for a cache key -> skip
            if cwe == "CWE-798" and _SECRET_ENV.search(m.group(0)):
                continue                                   # from env / placeholder -> not hardcoded
            out.append(Candidate(filename, unit_lookup(line), line, cwe, fam, "pattern",
                                 m.group(0).strip()[:120]))
    return out


# ================= JS/TS taint (regex) =================
_JS_SRC = re.compile(
    r"req(uest)?\.(query|params|body|cookies|headers)|ctx\.(query|params|request)|"
    r"event\.(body|queryStringParameters)|location\.(search|hash|href)|process\.argv|window\.location")
JS_SINKS = [
    (re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\{?\s*__html:\s*([^}]+)"), "CWE-79", "xss"),
    (re.compile(r"\.innerHTML\s*=\s*([^;\n]+)|document\.write\(([^)]+)|\.html\(([^)]+)"), "CWE-79", "xss"),
    (re.compile(r"child_process\.(exec|execSync|spawn|spawnSync)\(([^)]+)|(?<![.\w])exec(Sync)?\(([^)]+)"), "CWE-78", "command injection"),
    (re.compile(r"\.(query|execute)\(\s*([`\"'][^)]*)"), "CWE-89", "sql injection"),
    (re.compile(r"fs\.(readFile|readFileSync|createReadStream|writeFile)\(([^),]+)|res\.sendFile\(([^)]+)"), "CWE-22", "path traversal"),
    (re.compile(r"(?<![.\w])(fetch|axios(?:\.\w+)?)\(([^)]+)|http\.get\(([^)]+)"), "CWE-918", "ssrf"),
]


def _js_taint(code, filename, unit_lookup):
    # 1. tainted vars (file-wide, fixpoint)
    taint = set()
    assigns = re.findall(r"(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)", code)
    for _ in range(3):
        before = len(taint)
        for lhs, rhs in assigns:
            if _JS_SRC.search(rhs) or any(re.search(rf"\b{re.escape(t)}\b", rhs) for t in taint):
                taint.add(lhs)
        if len(taint) == before:
            break
    # 2. sinks whose argument is tainted
    out = []
    for rx, cwe, fam in JS_SINKS:
        for m in rx.finditer(code):
            arg = next((g for g in m.groups() if g), "")
            if _JS_SRC.search(arg) or any(re.search(rf"\b{re.escape(t)}\b", arg) for t in taint):
                line = code[:m.start()].count("\n") + 1
                out.append(Candidate(filename, unit_lookup(line), line, cwe, fam, "taint",
                                     m.group(0).strip().replace("\n", " ")[:120]))
    return out


# a value produced by a HAND-ROLLED sanitiser -- a string .replace() (blocklist) or
# strip_tags. Not DOMPurify / a proper encoder: those are correct and must not be flagged.
_JS_HANDROLL = re.compile(r"\.replace\s*\(\s*/|\.replace\s*\(\s*['\"]|strip_tags\s*\(", re.I)
_JS_HTML_SINK = re.compile(
    r"\.innerHTML\s*=\s*([^;\n]+)|\.outerHTML\s*=\s*([^;\n]+)|"
    r"document\.write\(\s*([^)]+)|\.html\(\s*([^)]+)|"
    r"insertAdjacentHTML\s*\([^,]+,\s*([^)]+)")


def _js_dom_xss(code, filename, unit_lookup):
    """Flow-free DOM-XSS: a hand-rolled sanitiser (a .replace() blocklist) reaching an HTML
    sink -- the completeness case the taint pass misses when the input arrives as a function
    PARAMETER (no recognised source). Scoped to a hand-rolled sanitiser so a raw innerHTML or
    a proper encoder (DOMPurify) is NOT flagged; the witness then judges the blocklist.
    """
    # vars assigned from a hand-rolled sanitiser
    sanitized = set()
    for m in re.finditer(r"(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)", code):
        if _JS_HANDROLL.search(m.group(2)):
            sanitized.add(m.group(1))
    out = []
    for m in _JS_HTML_SINK.finditer(code):
        rhs = next((g for g in m.groups() if g), "")
        # the sink is fed by a sanitised var, or sanitises inline on the sink line
        fed = _JS_HANDROLL.search(rhs) or any(
            re.search(rf"\b{re.escape(v)}\b", rhs) for v in sanitized)
        if fed:
            line = code[:m.start()].count("\n") + 1
            out.append(Candidate(filename, unit_lookup(line), line, "CWE-79",
                                 "hand-rolled sanitiser reaches an HTML sink (check completeness)",
                                 "pattern", m.group(0).strip().replace("\n", " ")[:120]))
    return out


# ================= dispatch =================
def _py_unit_lookup(tree):
    fns = [(f.lineno, getattr(f, "end_lineno", f.lineno), f.name)
           for f in ast.walk(tree) if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))]
    def look(line):
        for s, e, n in fns:
            if s <= line <= e:
                return n
        return "<module>"
    return look


def _js_unit_lookup(code):
    fns = [(code[:m.start()].count("\n") + 1, m.group(1))
           for m in re.finditer(r"function\s+([A-Za-z_$][\w$]*)|(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(", code)]
    def look(line):
        best = "<module>"
        for ln, nm in fns:
            if nm and ln <= line:
                best = nm
        return best
    return look


def scan_file(path):
    lang = EXT_LANG.get(Path(path).suffix.lower())
    if not lang:
        return []
    try:
        code = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out = []
    if lang == "py":
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []
        look = _py_unit_lookup(tree)
        for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            out += _py_taint(fn, code, str(path))
        out += _pattern_scan(code, "py", str(path), look)
    else:
        look = _js_unit_lookup(code)
        out += _js_taint(code, str(path), look)
        out += _js_dom_xss(code, str(path), look)
        out += _pattern_scan(code, "js", str(path), look)
    return out


def gather(target):
    p = Path(target)
    if p.is_file():
        return [p]
    return [f for f in p.rglob("*")
            if f.suffix.lower() in EXT_LANG
            and "/.git/" not in str(f).replace("\\", "/")
            and not any(x in str(f) for x in ("venv", "site-packages", "node_modules",
                                              "__pycache__", "/tests/", "\\tests\\", ".min."))]


def main():
    ap = argparse.ArgumentParser(description="Layer A: fast taint + pattern vulnerability flagger")
    ap.add_argument("target")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    cands = []
    for f in gather(args.target):
        cands.extend(scan_file(f))
    if args.json:
        print(json.dumps([asdict(c) for c in cands], indent=2))
        return
    if not cands:
        print("No candidates found.")
        return
    by_file = {}
    for c in cands:
        by_file.setdefault(c.file, []).append(c)
    for fname, cs in by_file.items():
        print(f"\n{fname}")
        for c in sorted(cs, key=lambda x: x.line):
            print(f"  [{c.cwe} {c.family}] ({c.detector})  line {c.line}, in {c.unit}()")
            print(f"      {c.sink}")
    print(f"\n{len(cands)} candidate(s) -> feed to the model for triage + fix.")


if __name__ == "__main__":
    main()
