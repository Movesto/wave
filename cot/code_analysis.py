# ============================================================
# cot/code_analysis.py
#
# Pre-flight analysis of source code before sending to the
# generator. Extracts:
#   - tainted-data sources (request inputs, env vars, file reads)
#   - dangerous sinks (eval, subprocess, SQL execute, fs reads)
#   - imports + library hints
#
# These get injected as explicit hints in build_prompt, so the
# generator has to engage with the SPECIFIC code rather than
# producing generic CWE-category reasoning.
# ============================================================
import ast
import re
from dataclasses import dataclass, field


# ---- Python sink/source patterns ----

PY_TAINT_PATTERNS = [
    r"\brequest\.(?:args|form|json|data|files|values|cookies|headers|GET|POST|method)\b[\.\[\w_'\"]*",
    r"\breq\.(?:body|query|params|headers|cookies|file[s]?)\b[\.\[\w_'\"]*",
    r"\bos\.environ(?:\.get)?(?:\([^)]*\)|\[[^\]]*\])?",
    r"\binput\(\)",
    r"\bsys\.argv\b\[?\d*\]?",
    r"\bself\.[a-z_]+ = .*request",
]

PY_SINK_PATTERNS = {
    "subprocess.exec":   r"\b(?:subprocess\.(?:run|call|Popen|check_output|check_call)|os\.(?:system|popen))\s*\(",
    "shell_true":        r"\bshell\s*=\s*True\b",
    "exec_eval":         r"\b(?:exec|eval|compile|__import__)\s*\(",
    "sql_execute":       r"\b(?:cur(?:sor)?|conn(?:ection)?|db)\.execute(?:many)?\s*\(",
    "sql_raw":           r"\.raw\s*\(",
    "fs_open":           r"\b(?:open|os\.path\.join|Path|send_file|FileResponse|sendfile)\s*\(",
    "fs_read":           r"\b(?:fs\.readFile|fs\.readFileSync|f\.read)\s*\(",
    "pickle_yaml":       r"\b(?:pickle\.(?:loads?|load)|yaml\.load|marshal\.loads?)\s*\(",
    "xml_parse":         r"\b(?:xml\.etree|lxml\.etree|minidom)\.[\w]+\s*\(",
    "render_template":   r"\b(?:render_template_string|render_template|jinja2\.Template|mark_safe|Markup)\s*\(",
    "http_outbound":     r"\b(?:requests\.(?:get|post|put|delete)|urlopen|urllib\.request)\s*\(",
    "redirect":          r"\b(?:redirect|HttpResponseRedirect)\s*\(",
    "hash_weak":         r"\bhashlib\.(?:md5|sha1)\s*\(",
    "random_weak":       r"\brandom\.(?:random|randint|choice|sample|shuffle)\b",
    "string_format_sql": r"f[\"\'].*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*[\"\']",
    "fstring_sql":       r"\.(?:execute|raw)\s*\(\s*f[\"\']",
    "shell_concat":      r"(?:os\.system|subprocess\.\w+)\s*\([^)]*\+",
}


# ---- JS / TS / React sink/source patterns ----

JS_TAINT_PATTERNS = [
    r"\breq\.(?:body|query|params|headers|cookies|files?)\b[\.\[\w_'\"]*",
    r"\bdocument\.(?:cookie|location)\b",
    r"\bwindow\.location\b",
    r"\bprocess\.env\.[A-Z_]+\b",
    r"\bparams\.(?:get\([^)]+\)|[\w_]+)\b",
]

JS_SINK_PATTERNS = {
    "child_process":     r"\bchild_process\.(?:exec|execSync|spawn|spawnSync|fork)\s*\(",
    "exec_eval":         r"\b(?:eval|new\s+Function|Function\s*\()\s*\(?",
    "dangerouslySIH":    r"\bdangerouslySetInnerHTML\b",
    "innerHTML":         r"\.(?:innerHTML|outerHTML)\s*=",
    "document_write":    r"\bdocument\.write(?:ln)?\s*\(",
    "shell_true":        r"\bshell\s*:\s*true\b",
    "fs_read":           r"\bfs\.(?:readFile|readFileSync|createReadStream)\s*\(",
    "send_file":         r"\bres\.(?:sendFile|download)\s*\(",
    "sql_query":         r"\b(?:pool|conn(?:ection)?|client|db)\.(?:query|execute)\s*\(",
    "mongoose_where":    r"\$where\b",
    "redirect":          r"\bres\.redirect\s*\(",
    "template_literal_sql": r"`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{",
    "require_dynamic":   r"\brequire\s*\([^)]*req\.\w+",
    "fetch_outbound":    r"\b(?:fetch|axios\.\w+|undici\.fetch)\s*\(",
}


# ---- Public API ----

@dataclass
class CodeHints:
    language: str
    taint_sources: list[str] = field(default_factory=list)
    sinks: list[tuple[str, str]] = field(default_factory=list)  # (sink_name, matched_text)
    imports: list[str] = field(default_factory=list)
    identifiers: list[str] = field(default_factory=list)  # function/class names defined

    def is_empty(self) -> bool:
        return not (self.taint_sources or self.sinks or self.identifiers)

    def render(self) -> str:
        """Format hints for prompt injection. Returns empty string if no hints."""
        if self.is_empty():
            return ""
        parts = ["CODE ANALYSIS (concrete elements you MUST reference by name in your reasoning):"]
        if self.taint_sources:
            srcs = ", ".join(f"`{s}`" for s in self.taint_sources[:6])
            parts.append(f"  - Tainted inputs: {srcs}")
        if self.sinks:
            sink_strs = []
            for name, text in self.sinks[:6]:
                snippet = text[:60].strip()
                sink_strs.append(f"`{snippet}` ({name})")
            parts.append(f"  - Dangerous sinks: {', '.join(sink_strs)}")
        if self.identifiers:
            ids = ", ".join(f"`{i}`" for i in self.identifiers[:6])
            parts.append(f"  - Functions/classes defined: {ids}")
        if self.imports:
            imps = ", ".join(self.imports[:6])
            parts.append(f"  - Imports: {imps}")
        return "\n".join(parts) + "\n"


def _extract_python_ast(code: str) -> tuple[list[str], list[str]]:
    """Use Python AST to find function/class names and imports. Best-effort —
    syntactically invalid code returns ([], [])."""
    identifiers, imports = [], []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        # Try wrapping in a function so partial-snippets parse
        try:
            tree = ast.parse(f"def _wrapper():\n    " + "\n    ".join(code.splitlines()))
        except SyntaxError:
            return identifiers, imports

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            identifiers.append(node.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
    return identifiers, imports


def _extract_js_identifiers(code: str) -> list[str]:
    """Regex-only function-name + class-name extraction for JS/TS."""
    out = []
    out += re.findall(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(", code)
    out += re.findall(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>)", code)
    out += re.findall(r"\bclass\s+([A-Za-z_$][\w$]*)\b", code)
    out += re.findall(r"\bexport\s+(?:default\s+)?(?:function\s+|class\s+|const\s+)([A-Za-z_$][\w$]*)", code)
    return list(dict.fromkeys(out))  # dedup preserve order


def _extract_js_imports(code: str) -> list[str]:
    out = []
    out += re.findall(r"\brequire\s*\(\s*[\"']([^\"']+)[\"']\s*\)", code)
    out += re.findall(r"\bimport\s+(?:[\w*\s{},]+\s+from\s+)?[\"']([^\"']+)[\"']", code)
    return list(dict.fromkeys(out))


def analyze(code: str, language: str = None) -> CodeHints:
    """Top-level analysis. language is one of {python, javascript, typescript, react}."""
    if not code or len(code) < 20:
        return CodeHints(language=language or "unknown")

    # Auto-detect if not given
    if not language:
        if "def " in code or "import " in code and ";" not in code[:200]:
            language = "python"
        elif "function " in code or "const " in code or "=>" in code:
            language = "javascript"
        else:
            language = "unknown"

    hints = CodeHints(language=language)

    if language == "python":
        for pat in PY_TAINT_PATTERNS:
            for m in re.finditer(pat, code):
                snippet = m.group(0)[:80]
                if snippet not in hints.taint_sources:
                    hints.taint_sources.append(snippet)
        for name, pat in PY_SINK_PATTERNS.items():
            m = re.search(pat, code)
            if m:
                hints.sinks.append((name, m.group(0)))
        hints.identifiers, hints.imports = _extract_python_ast(code)

    elif language in {"javascript", "typescript", "react"}:
        for pat in JS_TAINT_PATTERNS:
            for m in re.finditer(pat, code):
                snippet = m.group(0)[:80]
                if snippet not in hints.taint_sources:
                    hints.taint_sources.append(snippet)
        for name, pat in JS_SINK_PATTERNS.items():
            m = re.search(pat, code)
            if m:
                hints.sinks.append((name, m.group(0)))
        hints.identifiers = _extract_js_identifiers(code)
        hints.imports = _extract_js_imports(code)

    return hints


def extract_identifiers_only(code: str, language: str = None) -> list[str]:
    """Lightweight: just identifiers and imports, for specificity scoring."""
    h = analyze(code, language)
    return h.identifiers + h.imports
