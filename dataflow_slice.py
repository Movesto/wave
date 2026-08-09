"""Phase 1: dataflow slice via Semgrep taint (Docker). The general dataflow layer that
replaces whole-function regex for the neutraliser-on-path kinds (path, command, xss).

Per (file, kind) it returns one of:
  'tainted'   -- untrusted input reaches a dangerous sink WITHOUT a sanitiser on the path
  'sanitized' -- a flow exists but a sanitiser/safe-sink neutralises it (the order-of-ops win)
  'no-flow'   -- no source->dangerous-sink flow (also the safe-API case, e.g. execFile)

Mechanism (the two-rule trick): '<kind>-unsanitized' fires only when taint reaches the sink
past the sanitisers; '<kind>-flow' (path only) fires on ANY flow. So:
  unsanitized fires            -> tainted
  only flow fires (path)       -> sanitized
  nothing fires                -> no-flow (safe: sink not reached / safe API used)

compose(kind, dataflow, code): dataflow gives the safe side deterministically; on 'tainted'
we defer to the witness for the concrete bypass. This is the CPG-grounded audit, lightweight.

    python dataflow_slice.py phase1_slice        # scan a dir, print per-file verdicts
"""
import json
import subprocess
import sys
from pathlib import Path

from guard_witness import witness_scan

IMAGE = "semgrep/semgrep:latest"
RULES = "phase1_slice/rules.yaml"
# which rule ids map to which kind / role
_RULE_KIND = {"path-flow": ("path", "flow"), "path-unsanitized": ("path", "unsan"),
              "command-flow": ("command", "unsan"), "xss-flow": ("xss", "unsan")}


def run_semgrep(target_dir, rules=RULES):
    """Return semgrep JSON results over target_dir (Docker, offline rule file)."""
    cwd = Path.cwd().as_posix()
    cmd = ["docker", "run", "--rm",
           "-v", f"{cwd}/{target_dir}:/src",
           "-v", f"{cwd}/{Path(rules).parent.as_posix()}:/rules",
           IMAGE, "semgrep", f"--config=/rules/{Path(rules).name}",
           "--json", "/src"]
    env = {"MSYS_NO_PATHCONV": "1"}
    import os
    e = dict(os.environ, **env)
    raw = subprocess.run(cmd, capture_output=True, env=e).stdout      # bytes
    out = raw.decode("utf-8", errors="replace")
    return json.loads(out) if out.strip() else {"results": []}


def verdicts_by_file(results):
    """{filename: {kind: 'tainted'|'sanitized'|'no-flow'}} from semgrep findings."""
    fired = {}   # (file, kind, role) -> True
    for r in results.get("results", []):
        fname = Path(r["path"]).name
        rk = _RULE_KIND.get(r["check_id"].split(".")[-1])
        if rk:
            fired[(fname, rk[0], rk[1])] = True
    out = {}
    files = {Path(r["path"]).name for r in results.get("results", [])}
    return fired  # caller resolves per (file, kind) below


def verdict(fired, fname, kind):
    if fired.get((fname, kind, "unsan")):
        return "tainted"
    if kind == "path" and fired.get((fname, kind, "flow")):
        return "sanitized"
    return "no-flow"


def compose(kind, dataflow, code):
    """Final verdict from the dataflow slice + witness. dataflow-safe is deterministic;
    tainted defers to the witness for the concrete bypass."""
    if dataflow in ("sanitized", "no-flow"):
        return "safe", f"dataflow: {dataflow} (no untrusted value reaches the sink unsafely)"
    w = witness_scan(code, kind)
    if w:
        return "vuln", f"tainted + witness bypass {w['bypass']!r}"
    return "vuln", "tainted (untrusted reaches sink unsanitised)"


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "phase1_slice"
    print(f"running semgrep taint over {target}/ (Docker) ...", flush=True)
    res = run_semgrep(target)
    fired = verdicts_by_file(res)

    # expected labels encoded in filenames: *_vuln -> vuln, *_safe -> safe
    KINDMAP = {"path": "path", "cmd": "command", "xss": "xss"}
    rows = []
    for f in sorted(Path(target).glob("*.ts")):
        stem = f.stem
        kind = next((v for k, v in KINDMAP.items() if stem.startswith(k)), None)
        if not kind:
            continue
        truth = "vuln" if stem.endswith("vuln") else "safe"
        df = verdict(fired, f.name, kind)
        final, why = compose(kind, df, f.read_text(encoding="utf-8"))
        ok = final == truth
        rows.append(ok)
        print(f"  {f.name:16s} kind={kind:8s} truth={truth:5s} dataflow={df:9s} "
              f"-> {final:5s} {'OK' if ok else 'XX'}  ({why})")
    print(f"\n{sum(rows)}/{len(rows)} correct")


if __name__ == "__main__":
    main()
