"""Wave 1: clean + verify + quarantine the existing trace corpus. No model.

For each trace: deterministic cleanup -> label-branched verifier (status matches
label, CWE correct, real reasoning, no cross-CWE bleed) -> PASS / FIXED / FAIL.
PASS+FIXED written to pilot_clean/ (training format); FAIL quarantined with reasons.
"""
import io, json, re, argparse
from pathlib import Path
from collections import Counter, defaultdict

from cot.postprocess import clean_scan_output
from cot.oracle import Region
from cot.gates import cwe_consistency
from cot.cwe_contracts import check_bleed
from cot.vuln_types import classify

SRC = Path("data/cot/all_v8_traces.jsonl")
OUT = Path("data/cot/pilot_clean")
QUAR = Path("data/cot/quarantine")
OUT.mkdir(parents=True, exist_ok=True)
QUAR.mkdir(parents=True, exist_ok=True)

_FIELD = lambda name, t: (re.search(rf"^\s*{name}\s*:\s*(.+)$", t, re.I | re.M) or [None, ""])[1].strip()
_CONTROL = re.compile(r"parameteriz|escap|encode|sanitiz|validat|allow-?list|bound|"
                      r"neutraliz|safe|placeholder|prepared statement|disabled|guard|"
                      r"no untrusted|not user|benign|constant|literal|hardcoded value|"
                      r"trusted|internal|fixed value|already|properly", re.I)
_THINK = re.compile(r"<think>(.*?)</think>", re.S)


def norm_label(lbl):
    if lbl in ("vuln", "confirmed"):
        return "vuln"
    if lbl == "safe":
        return "safe"
    return "context"  # synthesis / needs_context / other


def verify(text, code, label, cwe):
    """Return (ok, reasons[])."""
    reasons = []
    status = _FIELD("status", text).lower()
    kind = norm_label(label)

    if kind == "context":
        return True, []  # shape2/3/4 — clean only, no vuln/safe verifier

    # well-formedness: a real <think> block must exist (catches stubs/empties).
    tm = _THINK.search(text)
    think = tm.group(1).strip() if tm else ""
    if len(think) < 40:
        reasons.append("stub: <think> missing/too short")

    if kind == "vuln":
        # Verdict + CWE + semantics. NOT correspondence/hedge — those false-fire on
        # legitimate expert prose (label is ground truth; we don't re-litigate it).
        if status not in ("vuln", "confirmed"):
            reasons.append(f"status '{status}' != vuln-label")
        cwe_f = _FIELD("cwe", text)
        if not re.search(r"CWE-\d+", cwe_f, re.I):
            reasons.append("vuln_no_cwe (unclassifiable)")  # CWE-UNK/none, classify failed too
        tr = _FIELD("trace", text)
        if not tr or tr.lower() == "none" or len(tr) < 12:
            reasons.append("weak_trace")
        if _FIELD("fix", text).lower() in ("", "none"):
            reasons.append("vuln_missing_fix")
        if _FIELD("severity", text).lower() not in ("low", "medium", "high"):
            reasons.append("vuln_bad_severity")
        ok, why = check_bleed(text, cwe)
        if not ok:
            reasons.append(f"bleed:{why}")
    else:  # safe
        if status != "safe":
            reasons.append(f"status '{status}' != safe-label")
        pc = _FIELD("cwe", text).lower()
        if pc and pc not in ("none", "n/a", "-", ""):
            reasons.append(f"safe-trace names cwe '{pc}'")
        if not _CONTROL.search(text):
            reasons.append("safe-trace cites no concrete control")
    return (len(reasons) == 0), reasons


def _load_records(args):
    """Yield normalized records from either the flat consolidated file (--src)
    or a pilot-format messages jsonl (--pilot, shape = filename stem)."""
    if args.pilot:
        shape = Path(args.pilot).stem
        for line in io.open(args.pilot, "r", encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            m = r.get("_meta", {})
            cwes = m.get("cwes") or ([m["ground_truth_cwe"]] if m.get("ground_truth_cwe") else [])
            yield {
                "shape": shape, "prompt": r["messages"][0]["content"],
                "current_reasoning": r["messages"][1]["content"],
                "label": m.get("label"), "cwe": cwes[0] if cwes else None,
                "source": m.get("source"), "language": m.get("language"),
            }
    else:
        for line in io.open(args.src, "r", encoding="utf-8"):
            line = line.strip()
            if line:
                yield json.loads(line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=str(SRC))
    ap.add_argument("--pilot", default=None, help="a pilot-format messages jsonl to clean")
    ap.add_argument("--append", action="store_true", help="append to pilot_clean instead of overwrite")
    args = ap.parse_args()

    out_f = {}
    quar_f = {}
    stats = defaultdict(Counter)
    fail_reasons = Counter()

    mode = "a" if args.append else "w"

    def writer(d, shape):
        store = out_f if d is OUT else quar_f
        if shape not in store:
            store[shape] = io.open(d / f"{shape}.jsonl", mode, encoding="utf-8")
        return store[shape]

    if True:
        for r in _load_records(args):
            shape = r["shape"]
            code = r["prompt"]
            original = r["current_reasoning"]
            cleaned = clean_scan_output(original)
            eff_cwe = r.get("cwe")

            # Salvage vuln records with no/unknown CWE: classify the code to assign one.
            if norm_label(r.get("label")) == "vuln":
                cf = _FIELD("cwe", cleaned)
                if not re.search(r"CWE-\d+", cf, re.I) or cf.upper() == "CWE-UNK":
                    _, guessed = classify(code)
                    if guessed:
                        cleaned = re.sub(r"(?im)^(\s*cwe\s*:\s*).*$",
                                         lambda m: m.group(1) + guessed, cleaned, count=1)
                        eff_cwe = guessed

            changed = cleaned.strip() != original.strip()
            ok, reasons = verify(cleaned, code, r.get("label"), eff_cwe)

            rec = {
                "messages": [
                    {"role": "user", "content": code},
                    {"role": "assistant", "content": cleaned},
                ],
                "_meta": {
                    "shape": "shape1" if shape.startswith("shape1") else shape,
                    "source": r.get("source"), "language": r.get("language"),
                    "label": r.get("label"),
                    "cwes": [eff_cwe] if eff_cwe else [],
                    "ground_truth_cwe": eff_cwe,
                    "cleaned": changed,
                },
            }
            if ok:
                bucket = "FIXED" if changed else "PASS"
                writer(OUT, shape).write(json.dumps(rec, ensure_ascii=False) + "\n")
            else:
                bucket = "FAIL"
                rec["_meta"]["quarantine_reasons"] = reasons
                writer(QUAR, shape).write(json.dumps(rec, ensure_ascii=False) + "\n")
                for rs in reasons:
                    fail_reasons[rs.split(":")[0]] += 1
            stats[shape][bucket] += 1

    for fh in list(out_f.values()) + list(quar_f.values()):
        fh.close()

    print(f"{'shape':<24}{'PASS':>7}{'FIXED':>7}{'FAIL':>7}")
    tot = Counter()
    for shape in sorted(stats):
        s = stats[shape]
        tot.update(s)
        print(f"{shape:<24}{s['PASS']:>7}{s['FIXED']:>7}{s['FAIL']:>7}")
    print(f"{'TOTAL':<24}{tot['PASS']:>7}{tot['FIXED']:>7}{tot['FAIL']:>7}")
    kept = tot['PASS'] + tot['FIXED']
    print(f"\nkept (clean): {kept}  | quarantined: {tot['FAIL']}  "
          f"({tot['FAIL']*100//max(kept+tot['FAIL'],1)}% dropped)")
    print(f"cleaned/repaired: {tot['FIXED']}")
    print("\ntop quarantine reasons:")
    for k, v in fail_reasons.most_common():
        print(f"  {k:<10}{v}")
    print(f"\nclean corpus -> {OUT}/   quarantine -> {QUAR}/")


if __name__ == "__main__":
    main()
