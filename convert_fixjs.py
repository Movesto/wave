"""Wave 5: mine FixJS (66K JS bug-fix before/after pairs) for SECURITY fixes only.
FixJS is general bugs, so we pair before=vuln/after=fixed and run the template
assembler — it declines anything without a security sink+CWE, which IS the filter.
Vuln side only (a general bug-fix 'after' is not a security-safe guarantee).
"""
import os, io, json, hashlib, argparse
from pathlib import Path
from collections import Counter

from cot.vuln_types import classify
from cot.template_reason import build_vuln_trace

ROOT = "data/downloads/FixJS/input"
OUT = Path("data/cot/pilot/shape1_fixjs.jsonl")


def rec(code, reasoning, cwe):
    return {"messages": [{"role": "user", "content": f"<SCAN>\n{code.strip()}\n</SCAN>"},
                         {"role": "assistant", "content": reasoning}],
            "_meta": {"shape": "shape1", "source": "fixjs", "language": "javascript",
                      "label": "vuln", "cwes": [cwe], "ground_truth_cwe": cwe}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-chars", type=int, default=80)
    ap.add_argument("--max-chars", type=int, default=6000)
    args = ap.parse_args()

    seen = set()
    pairs = vuln_ok = skip = 0
    by_cwe = Counter()
    with io.open(OUT, "w", encoding="utf-8") as out:
        for bucket in os.listdir(ROOT):
            bdir = os.path.join(ROOT, bucket, "before")
            adir = os.path.join(ROOT, bucket, "after")
            if not os.path.isdir(bdir):
                continue
            for fn in os.listdir(bdir):
                if not fn.endswith(".js"):
                    continue
                ap_ = os.path.join(adir, fn)
                if not os.path.exists(ap_):
                    continue
                pairs += 1
                try:
                    vuln = open(os.path.join(bdir, fn), encoding="utf-8", errors="replace").read()
                    fixed = open(ap_, encoding="utf-8", errors="replace").read()
                except Exception:
                    continue
                if not (args.min_chars <= len(vuln) <= args.max_chars):
                    continue
                h = hashlib.sha256(vuln.encode()).hexdigest()
                if h in seen:
                    continue
                seen.add(h)
                _, cwe = classify(vuln)
                if not cwe:
                    skip += 1
                    continue
                txt, ok = build_vuln_trace(vuln, fixed, cwe)
                if ok:
                    out.write(json.dumps(rec(vuln, txt, cwe), ensure_ascii=False) + "\n")
                    vuln_ok += 1
                    by_cwe[cwe] += 1
                else:
                    skip += 1

    print(f"before/after pairs scanned: {pairs}")
    print(f"grounded SECURITY vuln traces: {vuln_ok}  | non-security/ungroundable skipped: {skip}")
    print(f"-> {OUT}")
    print(f"top CWEs: {dict(by_cwe.most_common(10))}")


if __name__ == "__main__":
    main()
