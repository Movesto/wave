"""Label scanner findings on YOUR real code — builds the real-world eval this project lacks.

WHY THIS EXISTS
Every evaluation in this project is CVE-derived: code that is KNOWN to contain a planted
vulnerability. Real code is different — it is almost entirely safe, and the failure that
actually matters is a false positive on innocent code. That is the headline metric, and it
has never been measured on real code beyond a single application.

You are the only one who can build this set, because it needs your code and your judgment
about whether a finding is real.

WORKFLOW
    python scanner/flag.py ~/projects/myapp --json > findings.json    # CPU, no GPU needed
    python label_findings.py findings.json                            # label them
    python label_findings.py --report                                 # see the damage

Labels are saved after every answer, so stopping halfway loses nothing, and re-running
skips what you already judged. Findings are keyed by content, so re-scanning after a code
change does not lose your earlier labels.

    y = real vulnerability      n = false positive
    u = unsure / needs thought  s = skip for now
    q = save and quit
"""
import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

STORE = Path("data/real_world_eval.jsonl")
CONTEXT = 6


def finding_id(f: dict) -> str:
    """Content-keyed so labels survive line-number drift after edits."""
    basis = f"{Path(f.get('file','')).name}|{f.get('unit')}|{f.get('cwe')}|{f.get('sink')}"
    return hashlib.sha1(basis.encode()).hexdigest()[:16]


def load_labels() -> dict:
    out = {}
    if STORE.exists():
        for line in open(STORE, encoding="utf-8"):
            try:
                rec = json.loads(line)
                out[rec["id"]] = rec
            except Exception:
                continue
    return out


def show_code(path: str, line: int) -> None:
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as e:
        print(f"    (could not read {path}: {e})")
        return
    lo, hi = max(0, line - 1 - CONTEXT), min(len(lines), line + CONTEXT)
    for i in range(lo, hi):
        marker = ">>" if i == line - 1 else "  "
        print(f"    {marker} {i+1:5} | {lines[i]}")


def report() -> None:
    labels = load_labels()
    if not labels:
        raise SystemExit(f"nothing labelled yet — run: python label_findings.py findings.json")
    verdicts = Counter(r["label"] for r in labels.values())
    judged = verdicts["real"] + verdicts["false_positive"]

    print(f"\n=== real-world findings: {len(labels)} labelled ===")
    print(f"  real vulnerabilities  {verdicts['real']}")
    print(f"  false positives       {verdicts['false_positive']}")
    print(f"  unsure                {verdicts['unsure']}")
    if judged:
        fp_rate = verdicts["false_positive"] / judged * 100
        print(f"\n  PRECISION  {verdicts['real']/judged*100:.1f}%   "
              f"(false-positive rate {fp_rate:.1f}% on {judged} judged findings)")

    by_cwe = defaultdict(lambda: Counter())
    by_det = defaultdict(lambda: Counter())
    for r in labels.values():
        by_cwe[r.get("cwe")][r["label"]] += 1
        by_det[r.get("detector")][r["label"]] += 1

    print("\n  by CWE (worst first):")
    rows = [(c[ "false_positive"] / max(1, c["real"] + c["false_positive"]), k, c)
            for k, c in by_cwe.items()]
    for rate, cwe, c in sorted(rows, reverse=True):
        print(f"    {str(cwe):12} real={c['real']:3}  FP={c['false_positive']:3}  "
              f"({rate*100:.0f}% FP)")

    print("\n  by detector:")
    for det, c in sorted(by_det.items()):
        tot = c["real"] + c["false_positive"]
        rate = c["false_positive"] / tot * 100 if tot else 0
        print(f"    {str(det):12} real={c['real']:3}  FP={c['false_positive']:3}  ({rate:.0f}% FP)")

    print("\n  Every false positive here is a fixable rule in scanner/flag.py — these are")
    print("  hand-written detectors, so improvements land without retraining anything.")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("findings", nargs="?", help="JSON from: python scanner/flag.py <path> --json")
    ap.add_argument("--report", action="store_true", help="summarise what is already labelled")
    args = ap.parse_args()

    if args.report or not args.findings:
        report()
        return

    findings = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    labels = load_labels()
    todo = [f for f in findings if finding_id(f) not in labels]

    print(f"{len(findings)} findings, {len(findings)-len(todo)} already labelled, {len(todo)} to go.")
    if not todo:
        report()
        return
    print("  y=real  n=false positive  u=unsure  s=skip  q=quit\n")

    STORE.parent.mkdir(parents=True, exist_ok=True)
    answered = 0
    with open(STORE, "a", encoding="utf-8") as store:
        for i, f in enumerate(todo, 1):
            print("=" * 72)
            print(f"[{i}/{len(todo)}]  {f.get('cwe')}  {f.get('family')}   "
                  f"(detector: {f.get('detector')})")
            print(f"  {f.get('file')}:{f.get('line')}  in {f.get('unit')}")
            print(f"  sink: {f.get('sink')}")
            print()
            show_code(f.get("file", ""), f.get("line", 1))
            print()

            try:
                ans = input("  real vulnerability? [y/n/u/s/q] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\n  stopped.")
                break
            if ans == "q":
                break
            if ans == "s":
                continue
            label = {"y": "real", "n": "false_positive", "u": "unsure"}.get(ans)
            if not label:
                print("  (unrecognised — skipping)")
                continue

            note = ""
            if label == "false_positive":
                try:
                    note = input("  why is it safe? (one line, optional) ").strip()
                except (EOFError, KeyboardInterrupt):
                    pass

            rec = {"id": finding_id(f), "label": label, "note": note,
                   "cwe": f.get("cwe"), "detector": f.get("detector"),
                   "family": f.get("family"), "unit": f.get("unit"),
                   "file": Path(f.get("file", "")).name, "sink": f.get("sink")}
            store.write(json.dumps(rec, ensure_ascii=False) + "\n")
            store.flush()
            answered += 1

    print(f"\nsaved {answered} labels -> {STORE}")
    report()


if __name__ == "__main__":
    main()
