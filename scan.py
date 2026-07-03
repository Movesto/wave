"""wave-scan — a reasoning vulnerability scanner.

Unlike grep-based linters, each finding includes the model's data-flow reasoning
(source -> sink) and a fix. Scans a file, directory, or stdin; emits human-readable,
JSON, or SARIF 2.1.0 (which plugs into GitHub Code Scanning / IDEs).

  python scan.py app.py                 # pretty terminal
  python scan.py src/ --sarif > r.sarif # SARIF for CI / GitHub
  python scan.py app.py --json
  cat snippet.py | python scan.py -      # stdin
  python scan.py app.py --explain        # include the <think> reasoning
"""
import argparse, ast, json, os, sys, hashlib
from pathlib import Path
from dataclasses import dataclass, field, asdict

EXT_LANG = {".py": "python", ".js": "javascript", ".ts": "typescript",
            ".jsx": "react", ".tsx": "react", ".php": "php", ".java": "java",
            ".go": "go", ".rb": "ruby", ".c": "c", ".cpp": "cpp", ".cs": "csharp"}
SCAN_EXTS = set(EXT_LANG)
CWE_NAME = {
    "CWE-79": "Cross-site Scripting", "CWE-89": "SQL Injection",
    "CWE-78": "OS Command Injection", "CWE-22": "Path Traversal",
    "CWE-94": "Code Injection", "CWE-502": "Insecure Deserialization",
    "CWE-918": "SSRF", "CWE-611": "XXE", "CWE-352": "CSRF",
    "CWE-601": "Open Redirect", "CWE-327": "Weak Cryptography",
    "CWE-287": "Improper Authentication", "CWE-200": "Information Exposure",
    "CWE-1321": "Prototype Pollution", "CWE-20": "Improper Input Validation",
    "CWE-117": "Log Injection", "CWE-312": "Cleartext Storage", "CWE-400": "Resource Exhaustion",
}
SEV_SCORE = {"HIGH": "8.8", "MEDIUM": "5.5", "LOW": "3.1"}
SEV_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


@dataclass
class Finding:
    file: str
    unit: str          # function name / region
    line: int          # absolute line in file (best-effort)
    status: str
    cwe: str
    severity: str
    trace: str
    fix: str
    think: str = ""


# ---- chunking: scan function-level units (matches how the model was trained) ----
def chunk_python(code):
    try:
        tree = ast.parse(code)
    except SyntaxError:
        yield ("<module>", 1, code)
        return
    lines = code.splitlines()
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if not funcs:
        yield ("<module>", 1, code)
        return
    for n in funcs:
        end = getattr(n, "end_lineno", n.lineno)
        yield (n.name, n.lineno, "\n".join(lines[n.lineno - 1:end]))


def chunk_generic(code, win=60):
    lines = code.splitlines()
    if len(lines) <= win:
        yield (f"lines 1-{len(lines)}", 1, code)
        return
    for i in range(0, len(lines), win):
        seg = lines[i:i + win]
        yield (f"lines {i+1}-{i+len(seg)}", i + 1, "\n".join(seg))


def chunks_for(path, code):
    if EXT_LANG.get(Path(path).suffix.lower()) == "python":
        yield from chunk_python(code)
    else:
        yield from chunk_generic(code)


# ---- scanning ----
def scan_file(predictor, path, parse_fn, min_chars=40, max_chars=6000):
    code = Path(path).read_text(encoding="utf-8", errors="replace")
    findings = []
    for unit, start, snippet in chunks_for(path, code):
        if not (min_chars <= len(snippet) <= max_chars):
            continue
        out = predictor.predict(f"<SCAN>\n{snippet}\n</SCAN>")
        p = parse_fn(out)
        if p.get("status") not in ("vuln", "confirmed"):
            continue
        rel = p.get("line")
        try:
            abs_line = start + int(rel) - 1     # snippet-relative line -> absolute file line
        except (TypeError, ValueError):
            abs_line = start
        findings.append(Finding(
            file=str(path), unit=unit, line=abs_line,
            status="confirmed", cwe=(p.get("cwe") or "CWE-20").upper(),
            severity=(p.get("severity") or "MEDIUM").upper(),
            trace=p.get("trace", ""), fix=p.get("fix", ""),
            think=_think(out)))
    return findings


def _think(out):
    import re
    m = re.search(r"<think>(.*?)</think>", out, re.S)
    return m.group(1).strip() if m else ""


def gather_files(target):
    if target == "-":
        return [("-", sys.stdin.read())]
    p = Path(target)
    if p.is_file():
        return [(str(p), None)]
    files = []
    for f in p.rglob("*"):
        if f.is_file() and f.suffix.lower() in SCAN_EXTS and "/.git/" not in str(f).replace("\\", "/"):
            files.append((str(f), None))
    return files


# ---- output ----
def out_pretty(findings, explain):
    C = {"error": "\033[91m", "warning": "\033[93m", "note": "\033[96m", "0": "\033[0m", "d": "\033[2m"}
    if not findings:
        print("\033[92m✓ No vulnerabilities found.\033[0m")
        return
    by_file = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)
    for fname, fs in by_file.items():
        print(f"\n\033[1m{fname}\033[0m")
        for f in fs:
            col = C[SEV_LEVEL.get(f.severity, "warning")]
            name = CWE_NAME.get(f.cwe, "")
            print(f"  {col}[{f.severity}] {f.cwe} {name}{C['0']}  (line {f.line}, in {f.unit})")
            if f.trace:
                print(f"      {C['d']}trace:{C['0']} {f.trace}")
            if f.fix and f.fix.lower() != "none":
                print(f"      {C['d']}fix:{C['0']}   {f.fix}")
            if explain and f.think:
                print(f"      {C['d']}{f.think.replace(chr(10), ' ')[:300]}{C['0']}")
    n = len(findings)
    print(f"\n\033[1m{n} issue{'s' if n != 1 else ''} found.\033[0m")


def out_json(findings):
    print(json.dumps({"tool": "wave-scan", "version": "0.1",
                      "findings": [asdict(f) for f in findings]}, indent=2))


def out_sarif(findings):
    rules, rule_ids = [], set()
    for f in findings:
        if f.cwe in rule_ids:
            continue
        rule_ids.add(f.cwe)
        num = f.cwe.split("-")[-1]
        rules.append({
            "id": f.cwe, "name": CWE_NAME.get(f.cwe, f.cwe),
            "shortDescription": {"text": CWE_NAME.get(f.cwe, f.cwe)},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{num}.html",
            "properties": {"tags": ["security", f"external/cwe/cwe-{int(num):03d}"],
                           "security-severity": SEV_SCORE.get(f.severity, "5.5")}})
    results = []
    for f in findings:
        msg = f"{f.cwe} {CWE_NAME.get(f.cwe,'')}: {f.trace}".strip()
        results.append({
            "ruleId": f.cwe, "level": SEV_LEVEL.get(f.severity, "warning"),
            "message": {"text": msg + (f"  Fix: {f.fix}" if f.fix and f.fix.lower() != 'none' else "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file.replace("\\", "/")},
                "region": {"startLine": max(1, f.line)}}}],
            "partialFingerprints": {
                "wave/v1": hashlib.sha256(f"{f.file}{f.cwe}{f.unit}".encode()).hexdigest()[:16]}})
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
             "runs": [{"tool": {"driver": {
                 "name": "wave-scan", "version": "0.1",
                 "informationUri": "https://github.com/", "rules": rules}},
                 "results": results}]}
    print(json.dumps(sarif, indent=2))


def main():
    ap = argparse.ArgumentParser(description="wave-scan: a reasoning vulnerability scanner")
    ap.add_argument("target", help="file, directory, or - for stdin")
    ap.add_argument("--sarif", action="store_true", help="emit SARIF 2.1.0")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--explain", action="store_true", help="include reasoning in pretty output")
    args = ap.parse_args()

    from eval.inference import QwenLoraPredictor       # lazy: loads the model (GPU)
    from eval.parsers import parse_shape1
    predictor = QwenLoraPredictor()

    inputs = gather_files(args.target)
    findings = []
    for path, content in inputs:
        if content is not None:                          # stdin
            tmp = Path(".wave_stdin.py"); tmp.write_text(content, encoding="utf-8")
            findings += scan_file(predictor, tmp, parse_shape1)
            tmp.unlink(missing_ok=True)
        else:
            findings += scan_file(predictor, path, parse_shape1)

    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: (f.file, sev_order.get(f.severity, 1)))
    if args.sarif:
        out_sarif(findings)
    elif args.json:
        out_json(findings)
    else:
        out_pretty(findings, args.explain)
    sys.exit(1 if any(f.severity == "HIGH" for f in findings) else 0)


if __name__ == "__main__":
    main()
