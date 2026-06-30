"""Wave 6: mine the remaining SFT <SCAN> pairs into traces for v11.

Lower fidelity (bandit=analyzer-noise, kaggle=synthetic) — tagged by source,
low weight, so v11 is a clean A/B vs v10 on whether dumping everything helps.
Label is read from the verdict text; CWE from the text or classify(); trace
assembled by the template (ungroundable vuln declined). <GENERATE>/<EXPLAIN>
pairs and already-mined raw sources are skipped.
"""
import io, json, re, glob, os, hashlib, argparse
from pathlib import Path
from collections import Counter

from cot.vuln_types import classify
from cot.template_reason import build_vuln_trace, build_safe_trace

OUT = Path("data/cot/pilot/shape1_sft.jsonl")
# already mined as raw sources, or off-task (generate/explain) -> skip
SKIP = {"morefixes_pairs", "cvefixes_pairs", "all_sft_pairs",
        "alpaca_generate_pairs", "codefeedback_pairs", "glaive_explain_pairs",
        "rstarcoder_pairs", "generate_pairs", "explain_pairs"}
_SAFE = re.compile(r"no vulnerab|not vulnerable|no (security )?issue|is safe|securely|"
                   r"no exploit|appears safe|properly", re.I)
_CWE = re.compile(r"CWE-\d+", re.I)
_SCAN = re.compile(r"<SCAN>\s*(.*?)\s*</SCAN>", re.S)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-chars", type=int, default=60)
    ap.add_argument("--max-chars", type=int, default=6000)
    args = ap.parse_args()

    seen = set()
    by_src = Counter(); vuln_ok = safe_ok = skip = 0
    with io.open(OUT, "w", encoding="utf-8") as out:
        for p in sorted(glob.glob("data/sft/*.jsonl")):
            src = os.path.basename(p)[:-6]
            if src in SKIP:
                continue
            for line in io.open(p, encoding="utf-8", errors="replace"):
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                    u = r["messages"][0]["content"]
                    a = r["messages"][1]["content"]
                except Exception:
                    continue
                m = _SCAN.search(u)
                if not m:
                    continue  # not a scan pair
                code = m.group(1).strip()
                if not (args.min_chars <= len(code) <= args.max_chars):
                    continue
                h = hashlib.sha256(code.encode()).hexdigest()
                if h in seen:
                    continue
                seen.add(h)
                # verdict from the assistant text
                cwe_m = _CWE.search(a)
                is_safe = bool(_SAFE.search(a)) and not cwe_m
                if is_safe:
                    st, ok = build_safe_trace(code, None)
                    if ok:
                        rec = {"messages": [{"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
                                            {"role": "assistant", "content": st}],
                               "_meta": {"shape": "shape1", "source": f"sft:{src}",
                                         "language": None, "label": "safe", "cwes": [],
                                         "ground_truth_cwe": None}}
                        out.write(json.dumps(rec, ensure_ascii=False) + "\n"); safe_ok += 1; by_src[src] += 1
                else:
                    cwe = (cwe_m.group(0).upper() if cwe_m else None) or classify(code)[1]
                    if not cwe:
                        skip += 1; continue
                    txt, ok = build_vuln_trace(code, "", cwe)
                    if ok:
                        rec = {"messages": [{"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
                                            {"role": "assistant", "content": txt}],
                               "_meta": {"shape": "shape1", "source": f"sft:{src}",
                                         "language": None, "label": "vuln", "cwes": [cwe],
                                         "ground_truth_cwe": cwe}}
                        out.write(json.dumps(rec, ensure_ascii=False) + "\n"); vuln_ok += 1; by_src[src] += 1
                    else:
                        skip += 1

    print(f"vuln {vuln_ok}  safe {safe_ok}  skipped {skip}  -> {OUT}")
    print(f"by source: {dict(by_src.most_common())}")


if __name__ == "__main__":
    main()
