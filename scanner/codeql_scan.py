"""Station 1c: cross-file / interprocedural find via CodeQL.

Semgrep/flag.py taint are intra-file -- they never connect a source in a route/controller
to a sink in a service in ANOTHER file. CodeQL builds a database and does interprocedural,
interfile dataflow, so it catches exactly those (validated: brokencrystals 0 -> 30, 18
cross-file; xfile_bench 4/4). This wraps it and returns flag.Candidate objects the pipeline
already understands, keeping only real injection classes (drops -extended quality noise).

CodeQL is slower than the intra-file pass (a DB build up front), so it is OPT-IN (--codeql).
Point CODEQL_PATH at the codeql binary (from the codeql CLI bundle); if unset, this skips
with a message rather than failing.

    from codeql_scan import codeql_candidates
    cands = codeql_candidates("/path/to/repo")
"""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from flag import Candidate

# CodeQL JS security rule (last path segment) -> CWE. Only these become candidates; the
# -extended suite's quality checks (missing-rate-limiting, stack-trace-exposure, redos) are
# intentionally dropped -- they are not injection vulns the model should triage/fix.
_RULE_CWE = {
    "path-injection": "CWE-22", "http-to-file-access": "CWE-22", "zipslip": "CWE-22",
    "sql-injection": "CWE-89", "command-line-injection": "CWE-78",
    "reflected-xss": "CWE-79", "stored-xss": "CWE-79", "xss": "CWE-79",
    "xss-through-dom": "CWE-79", "code-injection": "CWE-94", "request-forgery": "CWE-918",
    "xxe": "CWE-611", "xpath-injection": "CWE-643", "ldap-injection": "CWE-90",
    "server-side-unvalidated-url-redirection": "CWE-601", "remote-property-injection": "CWE-1321",
    "tainted-format-string": "CWE-134", "unsafe-deserialization": "CWE-502",
    "insecure-download": "CWE-494", "template-object-injection": "CWE-1336",
}


def _codeql_bin():
    for c in (os.environ.get("CODEQL_PATH"), os.environ.get("CODEQL"), shutil.which("codeql")):
        if c and Path(c).exists():
            return c
    return None


def _parse_sarif(sarif_path, target):
    """SARIF results -> (Candidate list, {(file,line): 'src -> sink' flow summary})."""
    base = Path(target).resolve()
    data = json.loads(Path(sarif_path).read_text(encoding="utf-8"))
    cands, flows = [], {}
    for r in data["runs"][0].get("results", []):
        rule = r.get("ruleId", "").split("/")[-1]
        cwe = _RULE_CWE.get(rule)
        if not cwe:
            continue                                  # drop non-injection noise
        loc = r["locations"][0]["physicalLocation"]
        sink_file = str((base / loc["artifactLocation"]["uri"]).resolve())
        sink_line = loc["region"].get("startLine", 1)
        # source (first code-flow step) -- the cross-file provenance
        src = ""
        cf = r.get("codeFlows", [])
        if cf:
            s0 = cf[0]["threadFlows"][0]["locations"][0]["location"]["physicalLocation"]
            sname = Path(s0["artifactLocation"]["uri"]).name
            src = f"{sname}:{s0['region'].get('startLine', '?')}"
        xfile = bool(src) and Path(sink_file).name != src.split(":")[0]
        sink_desc = (f"{src} -> {rule}" if src else rule) + (" [CROSS-FILE]" if xfile else "")
        cands.append(Candidate(sink_file, f"codeql:{rule}", sink_line, cwe, rule,
                               "codeql", sink_desc[:120]))
        flows[(sink_file, sink_line)] = sink_desc
    return cands, flows


def codeql_candidates(target, suite="javascript-security-extended"):
    """Run CodeQL over `target`, return injection-class Candidate objects (detector='codeql')."""
    binp = _codeql_bin()
    if not binp:
        print("(Station 1c CodeQL skipped: set CODEQL_PATH to the codeql binary)")
        return []
    db = tempfile.mkdtemp(prefix="cqdb_")
    sarif = db + ".sarif"
    try:
        print("Station 1c: building CodeQL database (interprocedural, cross-file)...", flush=True)
        cr = subprocess.run([binp, "database", "create", db, "--language=javascript",
                             f"--source-root={target}", "--overwrite"],
                            capture_output=True, text=True)
        if not Path(db, "codeql-database.yml").exists():
            print(f"(CodeQL DB build failed: {cr.stderr.strip()[-200:]})")
            return []
        subprocess.run([binp, "database", "analyze", db,
                        f"codeql/javascript-queries:codeql-suites/{suite}.qls",
                        "--format=sarif-latest", f"--output={sarif}", "--threads=4"],
                       capture_output=True, text=True)
        if not Path(sarif).exists():
            print("(CodeQL analysis produced no output)")
            return []
        cands, _ = _parse_sarif(sarif, target)
        print(f"Station 1c: CodeQL found {len(cands)} injection finding(s) "
              f"({sum(1 for c in cands if 'CROSS-FILE' in c.sink)} cross-file).", flush=True)
        return cands
    finally:
        shutil.rmtree(db, ignore_errors=True)
        Path(sarif).unlink(missing_ok=True)


if __name__ == "__main__":
    import sys
    for c in codeql_candidates(sys.argv[1] if len(sys.argv) > 1 else "."):
        print(f"  {c.cwe:8s} {Path(c.file).name}:{c.line}  {c.sink}")
