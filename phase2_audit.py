"""Phase 2: combined router (dataflow + witness/prove_safe) as a two-directional audit,
measured over the saved agent run vs the current 5/8.

Router by kind:
  transform kinds {path, command, xss} -> Semgrep dataflow slice (neutraliser-on-path),
      then on 'tainted' check prove_safe (a recognised SUFFICIENT guard overrides taint,
      e.g. resolve+prefix), else the witness for the concrete bypass.
  structural kinds {proto, redirect, ssrf, sql} -> witness / prove_safe directly.

The audit is deterministic; where it has no verdict it defers to the model. We then apply it
as a two-directional veto over the model's saved verdicts and score pairs.
"""
import json
import re
from collections import defaultdict
from pathlib import Path

import dataflow_slice as ds
from guard_witness import witness_scan
from safe_veto import prove_safe

_WK = {"CWE-22": "path", "CWE-59": "path", "CWE-78": "command", "CWE-89": "sql",
       "CWE-918": "ssrf", "CWE-1321": "proto", "CWE-601": "redirect", "CWE-79": "xss"}
DATAFLOW_KINDS = {"path", "command", "xss"}

# phase2_slice file -> harder-case index (the dataflow-kind cases)
_FILE_CASE = {"path0_vuln": 0, "path0_safe": 1, "path2_vuln": 2, "path2_safe": 3,
              "cmd6_vuln": 6, "cmd6_safe": 7, "xss14_vuln": 14, "xss14_safe": 15}
_FILE_KIND = {"path0": "path", "path2": "path", "cmd6": "command", "xss14": "xss"}


def dataflow_verdicts():
    """{case_index: 'tainted'|'sanitized'|'no-flow'} from Semgrep over phase2_slice."""
    fired = ds.verdicts_by_file(ds.run_semgrep("phase2_slice"))
    out = {}
    for f in Path("phase2_slice").glob("*.ts"):
        ci = _FILE_CASE.get(f.stem)
        k = next((v for p, v in _FILE_KIND.items() if f.stem.startswith(p)), None)
        if ci is not None and k:
            out[ci] = ds.verdict(fired, f.name, k)
    return out


def smart_audit(code, kind, df=None):
    """Deterministic verdict 'vuln'|'safe'|None(unknown) from the router."""
    if kind in DATAFLOW_KINDS and df is not None:
        if df in ("sanitized", "no-flow"):
            return "safe"
        # tainted: a recognised sufficient guard overrides taint (control-flow guard)
        if prove_safe(code, kind):
            return "safe"
        if witness_scan(code, kind):
            return "vuln"
        return "vuln"                       # tainted, no guard proven -> vuln
    # structural kinds
    if witness_scan(code, kind):
        return "vuln"
    if prove_safe(code, kind):
        return "safe"
    return None                             # audit can't decide -> defer to model


def model_verdicts(run="merged_agent_transcript.txt"):
    """{case: 'vuln'|'safe'|'?'} model's pre-audit verdict from a saved run."""
    t = open(run, encoding="utf-8", errors="replace").read()
    out = {}
    for b in re.split(r"={80}", t):
        h = re.search(r"CASE (\d+) CWE=", b)
        if not h:
            continue
        fins = re.findall(r"VERDICT:\s*(\w+)", b)
        v = fins[-1].lower() if fins else "?"
        out[int(h.group(1))] = "vuln" if v.startswith("vuln") else "safe" if v == "safe" else "?"
    return out


def main():
    cases = [json.loads(l) for l in open("harder_cases.jsonl", encoding="utf-8")]
    df = dataflow_verdicts()
    mv = model_verdicts()

    rows = []
    for i, c in enumerate(cases):
        kind = _WK.get((c["cwe"] or "").upper())
        audit = smart_audit(c["code"], kind, df.get(i))
        model = mv.get(i, "?")
        # two-directional veto: audit (deterministic) overrides the model where it has a verdict
        final = audit if audit else model
        rows.append({"i": i, "cwe": c["cwe"], "truth": c["label"], "pair": c["pair_id"],
                     "model": model, "audit": audit, "final": final,
                     "df": df.get(i, "-")})

    def score(key):
        per = sum(1 for r in rows if r[key] == r["truth"])
        pp = defaultdict(list)
        for r in rows:
            pp[r["pair"]].append(r[key] == r["truth"])
        pairs = sum(1 for v in pp.values() if len(v) == 2 and all(v))
        return per, len(rows), pairs, len(pp)

    print(f"{'case':4s} {'cwe':9s} {'truth':5s} {'df':9s} {'model':5s} {'audit':6s} {'final':5s}")
    for r in rows:
        mark = "OK" if r["final"] == r["truth"] else "XX"
        print(f"{r['i']:<4d} {r['cwe']:9s} {r['truth']:5s} {str(r['df']):9s} "
              f"{r['model']:5s} {str(r['audit']):6s} {r['final']:5s} {mark}")
    b = score("model"); f = score("final")
    print(f"\nMODEL ALONE       : record {b[0]}/{b[1]}  pair {b[2]}/{b[3]}")
    print(f"MODEL + SMART AUDIT: record {f[0]}/{f[1]}  pair {f[2]}/{f[3]}")


if __name__ == "__main__":
    main()
