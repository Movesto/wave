import os, json
os.environ["WAVE_VERIFIED_LANGS"] = "typescript,javascript,python"
from cot.shapes import shape1_verified as S
from cot.gates import all_gates_pass
from cot.config import PILOT_DIR

tasks = S.prepare_tasks(300)
sel = [t for t in tasks if 90 < len(t["vuln_code"]) < 800]

T = {}
T[49] = """<think>
execAz takes cmd as a string and interpolates it directly into a shell command: exec(`az ${cmd} --out json`, ...). cmd is concatenated into the shell line with no quoting or validation, so a crafted cmd injects arbitrary shell commands -- command injection.
</think>
status: confirmed
cwe: CWE-78
severity: HIGH
line: 4
trace: cmd -> exec(az cmd --out json) shell command
fix: spawn az with an argument array (execFile) instead of a shell string, or strictly validate cmd"""

T[50] = """<think>
kubectlPath is the path of a downloaded executable. fs.chmodSync(kubectlPath, '777') makes the file world-writable and world-executable, so any local user can replace or tamper with the binary before it runs -- insecure file permissions.
</think>
status: confirmed
cwe: CWE-732
severity: MEDIUM
line: 4
trace: kubectlPath -> fs.chmodSync(kubectlPath, 777) world-writable
fix: set restrictive permissions (e.g. 0o755 owner-only write) on the downloaded binary"""

T[54] = """<think>
async_run builds a shell command by joining prog and args and passes it to os.system(" ".join([prog] + args)). The arguments are concatenated into a single shell string with no quoting, so any shell metacharacters in prog or args are interpreted -- command injection.
</think>
status: confirmed
cwe: CWE-78
severity: HIGH
line: 10
trace: prog args -> os.system join prog args shell command
fix: use subprocess with an argument list and shell=False instead of os.system on a joined string"""

T[55] = """<think>
args is built from metadata.hostname, metadata.profile and metadata.groups and passed to async_run(npath, args). async_run runs the command via os.system on the joined arguments, so attacker-influenced metadata fields flow into a shell command -- command injection.
</think>
status: confirmed
cwe: CWE-78
severity: HIGH
line: 6
trace: metadata.hostname -> args -> async_run -> os.system command
fix: pass arguments as a list to subprocess with shell=False and validate metadata fields"""

T[56] = """<think>
constructObject evaluates attacker-influenced message-type data: classBase = eval(data[""] + "." + data[""].title()). The message type string is concatenated and passed to eval, allowing arbitrary expression/code evaluation -- code injection.
</think>
status: confirmed
cwe: CWE-94
severity: HIGH
line: 4
trace: data -> eval(data type) -> classBase
fix: map the message type through an explicit allowlist/registry instead of eval"""

kept = 0
out = []
for idx, trace in T.items():
    task = sel[idx]
    rec = S.verify(task, trace)
    if rec:
        kept += 1
        out.append(rec)
        print(f"  [{idx}] KEPT  ({task['language']})")
    else:
        _, fails, _ = all_gates_pass(trace, task["vuln_code"], task["region"])
        print(f"  [{idx}] DROP  {fails}")

p = PILOT_DIR / "shape1_verified.jsonl"
with open(p, "a", encoding="utf-8") as f:
    for r in out:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
print(f"\nKEPT {kept} / {len(T)}")
print("TOTAL verified records now:", sum(1 for _ in open(p, encoding="utf-8")))
