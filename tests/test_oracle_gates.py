# Unit tests for cot/oracle.py and cot/gates.py — pure logic, no model.
# Run: python tests/test_oracle_gates.py
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cot.oracle import locate_from_diff, locate_vuln, Region
from cot.gates import all_gates_pass, correspondence, localization, cwe_consistency, substantiveness

VULN = """from flask import send_file, request
def download():
    name = request.args.get('name')
    return send_file('/var/exports/' + name)"""

FIXED = """from flask import send_file, request
import os
def download():
    name = request.args.get('name')
    safe = os.path.basename(name)
    return send_file('/var/exports/' + safe)"""

GOOD_TRACE = """<think>
The handler reads name from request.args.get('name') and passes it straight into
send_file with string concatenation. The user-controlled name flows into the file
path, enabling path traversal.
</think>
status: confirmed
cwe: CWE-22
severity: HIGH
line: 4
trace: request.args.get('name') -> name -> send_file('/var/exports/' + name)
fix: use os.path.basename"""

HEDGED_TRACE = GOOD_TRACE.replace(
    "The user-controlled name flows into the file\npath, enabling path traversal.",
    "This could be vulnerable if name were user input.")

HALLUCINATED_TRACE = """<think>
The body url is fetched via axios.get, an SSRF.
</think>
status: confirmed
cwe: CWE-918
line: 1
trace: req.body.url -> axios.get(url) -> outbound request"""

_passed = _failed = 0
def check(name, cond):
    global _passed, _failed
    if cond: _passed += 1; print(f"  PASS  {name}")
    else: _failed += 1; print(f"  FAIL  {name}")

print("=== oracle ===")
region = locate_from_diff(VULN, FIXED)
check("diff finds the vulnerable return line (line 4)", 4 in region.lines)
check("diff captures sink identifier 'send_file'", "send_file" in region.identifiers)
check("region.source == 'diff'", region.source == "diff")
check("identical code -> no region", not locate_from_diff(VULN, VULN).known())
check("locate_vuln attaches ground-truth cwe", locate_vuln(VULN, FIXED, cwe="CWE-22").cwe == "CWE-22")

print("=== gates: GOOD trace should pass all ===")
region.cwe = "CWE-22"
ok, fails, _ = all_gates_pass(GOOD_TRACE, VULN, region)
check("good trace passes all gates", ok)
if not ok: print("    unexpected fails:", fails)

print("=== gates: each failure mode caught ===")
check("hedged trace fails substantiveness", not substantiveness(HEDGED_TRACE)[0])
check("hallucinated trace fails correspondence", not correspondence(HALLUCINATED_TRACE, VULN)[0])
# mislocated: synthetic region far from the cited line/identifier
far = Region(lines={20}, identifiers={"someOtherSink"}, cwe="CWE-22", source="diff")
check("mislocated trace fails localization", not localization(GOOD_TRACE, far)[0])
# cwe mismatch
wrong = GOOD_TRACE.replace("cwe: CWE-22", "cwe: CWE-79")
check("cwe mismatch fails cwe gate", not cwe_consistency(wrong, region)[0])
# unverifiable region -> localization passes (flagged)
check("no-oracle region: localization passes (unverified)", localization(GOOD_TRACE, Region())[0])
# good trace individually clean on the other gates
check("good trace passes correspondence", correspondence(GOOD_TRACE, VULN)[0])
check("good trace passes substantiveness", substantiveness(GOOD_TRACE)[0])

print(f"\n{_passed} passed, {_failed} failed")
sys.exit(1 if _failed else 0)
