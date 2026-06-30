"""Wave 4: mine CVEfixes (code/language/safety, NO CWE, NO oracle) into traces.
Lower fidelity than patches -> classify() supplies the CWE, template grounds the
sink; ungroundable rows are declined. Safe side capped to protect corpus balance.
Output pilot-format; run clean_and_verify.py --pilot next.
"""
import csv, io, json, hashlib, argparse
from pathlib import Path
from collections import Counter

from cot.vuln_types import classify
from cot.template_reason import build_vuln_trace, build_safe_trace

CSV_PATH = "data/downloads/CVEfixes/CVEFixes.csv"
OUT = Path("data/cot/pilot/shape1_cvefixes.jsonl")
LANG_MAP = {"py": "python", "js": "javascript", "rb": "ruby", "cc": "cpp", "h": "c"}
SKIP_LANG = {"other", "html", ""}


def rec(code, reasoning, label, cwe, lang):
    return {"messages": [{"role": "user", "content": f"<SCAN>\n{code.strip()}\n</SCAN>"},
                         {"role": "assistant", "content": reasoning}],
            "_meta": {"shape": "shape1", "source": "cvefixes", "language": lang,
                      "label": label, "cwes": [cwe] if cwe else [],
                      "ground_truth_cwe": cwe}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-safe", type=int, default=4000, help="cap safe traces (balance)")
    ap.add_argument("--min-chars", type=int, default=80)
    ap.add_argument("--max-chars", type=int, default=6000)
    args = ap.parse_args()
    csv.field_size_limit(10 ** 8)

    seen = set()
    n = vuln_ok = vuln_skip = safe_ok = safe_capped = 0
    by_lang = Counter(); by_cwe = Counter()
    with io.open(OUT, "w", encoding="utf-8") as out:
        for row in csv.DictReader(io.open(CSV_PATH, encoding="utf-8", errors="replace")):
            n += 1
            code = (row.get("code") or "").strip()
            if not (args.min_chars <= len(code) <= args.max_chars):
                continue
            lang = (row.get("language") or "").strip().lower()
            lang = LANG_MAP.get(lang, lang)
            if lang in SKIP_LANG:
                continue
            h = hashlib.sha256(code.encode()).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            safety = (row.get("safety") or "").strip().lower()
            _, cwe = classify(code)

            if safety == "vulnerable":
                if not cwe:
                    vuln_skip += 1; continue
                txt, ok = build_vuln_trace(code, "", cwe)
                if ok:
                    out.write(json.dumps(rec(code, txt, "vuln", cwe, lang), ensure_ascii=False) + "\n")
                    vuln_ok += 1; by_lang[lang] += 1; by_cwe[cwe] += 1
                else:
                    vuln_skip += 1
            elif safety == "safe":
                if safe_ok >= args.max_safe:
                    safe_capped += 1; continue
                st, ok = build_safe_trace(code, cwe)
                if ok:
                    out.write(json.dumps(rec(code, st, "safe", None, lang), ensure_ascii=False) + "\n")
                    safe_ok += 1

    print(f"rows scanned: {n}")
    print(f"grounded vuln: {vuln_ok}  | skipped (no cwe/sink): {vuln_skip}")
    print(f"safe: {safe_ok}  (capped/dropped {safe_capped} over --max-safe={args.max_safe})")
    print(f"total: {vuln_ok + safe_ok} -> {OUT}")
    print(f"by language: {dict(by_lang.most_common(10))}")
    print(f"top CWEs: {dict(by_cwe.most_common(10))}")


if __name__ == "__main__":
    main()
