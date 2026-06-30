"""Wave 3A: turn JS/TS/React patch fix-pairs into traces via the template
assembler (no model). Grounded vuln traces + safe traces from the fixed code.
Output is a pilot-format file; run clean_and_verify.py --pilot on it next.
"""
import io, json, hashlib, argparse
from pathlib import Path
from collections import Counter

from cot.fix_pairs import iter_fix_pairs
from cot.template_reason import build_vuln_trace, build_safe_trace

LANGS = {"javascript", "typescript", "react"}   # default; override with --langs
OUT = Path("data/cot/pilot/shape1_wave3_jsts.jsonl")


def rec(code, reasoning, label, cwe, lang):
    return {
        "messages": [
            {"role": "user", "content": f"<SCAN>\n{code.strip()}\n</SCAN>"},
            {"role": "assistant", "content": reasoning},
        ],
        "_meta": {"shape": "shape1", "source": "wave3_patch", "language": lang,
                  "label": label, "cwes": [cwe] if cwe else [],
                  "ground_truth_cwe": cwe},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--langs", default=None, help="comma list, e.g. php,c,java,go")
    ap.add_argument("--sources", default="patches", help="patches,morefixes,cve_fix_pairs")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    langs = set(args.langs.split(",")) if args.langs else LANGS
    sources = tuple(args.sources.split(","))
    global OUT
    if args.out:
        OUT = Path(args.out)

    seen = set()
    n_in = vuln_ok = vuln_skip = safe_ok = 0
    by_cwe = Counter()
    by_lang = Counter()
    with io.open(OUT, "w", encoding="utf-8") as out:
        for fp in iter_fix_pairs(languages=langs, sources=sources):
            n_in += 1
            cwe = fp.get("cwe")
            vuln_code = fp["vuln_code"]
            fixed_code = fp.get("fixed_code") or ""
            h = hashlib.sha256(vuln_code.encode("utf-8")).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            lang = fp.get("language") or "javascript"

            txt, ok = build_vuln_trace(vuln_code, fixed_code, cwe)
            if ok:
                out.write(json.dumps(rec(vuln_code, txt, "vuln", cwe, lang), ensure_ascii=False) + "\n")
                vuln_ok += 1
                by_cwe[cwe] += 1
                by_lang[lang] += 1
                # matched safe trace from the FIXED code (balances FPR)
                if fixed_code and len(fixed_code.split("\n")) >= 3:
                    st, sok = build_safe_trace(fixed_code, cwe)
                    if sok:
                        out.write(json.dumps(rec(fixed_code, st, "safe", None, lang), ensure_ascii=False) + "\n")
                        safe_ok += 1
            else:
                vuln_skip += 1
            if args.limit and (vuln_ok + safe_ok) >= args.limit:
                break

    print(f"patches scanned (JS/TS/React fix-pairs): {n_in}")
    print(f"grounded vuln traces: {vuln_ok}  | ungroundable skipped: {vuln_skip}  "
          f"(yield {vuln_ok*100//max(n_in,1)}%)")
    print(f"safe traces (from fixed code): {safe_ok}")
    print(f"total written: {vuln_ok + safe_ok} -> {OUT}")
    print(f"by language: {dict(by_lang)}")
    print(f"top CWEs: {dict(by_cwe.most_common(12))}")


if __name__ == "__main__":
    main()
