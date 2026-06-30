"""Full label-correctness & structural-consistency audit of the clean corpus.

Catches the failure modes that make a model GUESS:
  1. status field disagreeing with the record's label
  2. safe records carrying vuln-only fields (cwe/fix/severity/line/CWE-in-trace)
  3. vuln records missing required fields (cwe/severity/trace/fix)
  4. predicted cwe != the labeled cwe
  5. CROSS-RECORD CONTRADICTION: the same code labelled both safe AND vuln
  6. exact-duplicate code (redundancy / near-identical safe-vuln pairs with no diff)
Reports everything; writes offending ids to corpus_audit_report.json.
"""
import io, json, re, hashlib, glob
from collections import defaultdict, Counter

CLEAN = "data/cot/pilot_clean"
_F = lambda name, t: (re.search(rf"^\s*{name}\s*:\s*(.+)$", t, re.I | re.M) or [None, ""])[1].strip()
_CWE = re.compile(r"CWE-\d+", re.I)
_FLOW = re.compile(r"->|→|neutraliz|bound|parameter|escap|validat|safe", re.I)


def norm(lbl):
    if lbl in ("vuln", "confirmed"):
        return "vuln"
    if lbl == "safe":
        return "safe"
    return "context"


def main():
    issues = defaultdict(list)
    code_labels = defaultdict(set)     # code-hash -> set of labels seen
    code_seen = Counter()
    total = 0
    by_label = Counter()

    for path in sorted(glob.glob(f"{CLEAN}/*.jsonl")):
        shape = path.split("/")[-1].replace(".jsonl", "")
        for i, line in enumerate(io.open(path, "r", encoding="utf-8")):
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            total += 1
            m = r["_meta"]
            rid = f"{shape}:{i}"
            code = r["messages"][0]["content"]
            txt = r["messages"][1]["content"]
            lbl = norm(m.get("label"))
            by_label[lbl] += 1
            ch = hashlib.sha256(code.strip().encode()).hexdigest()
            code_seen[ch] += 1
            code_labels[ch].add(lbl)

            status = _F("status", txt).lower()
            cwe_f = _F("cwe", txt).lower()
            fix_f = _F("fix", txt).lower()
            sev_f = _F("severity", txt).lower()
            trace_f = _F("trace", txt)

            if lbl == "vuln":
                if status not in ("vuln", "confirmed"):
                    issues["status_mismatch"].append(rid)
                if not _CWE.search(cwe_f):
                    issues["vuln_missing_cwe"].append(rid)
                elif m.get("ground_truth_cwe") and cwe_f.upper() != str(m["ground_truth_cwe"]).upper():
                    issues["cwe_field_ne_label"].append(rid)
                if fix_f in ("", "none"):
                    issues["vuln_missing_fix"].append(rid)
                # weak trace = empty/none/trivially short (a prose summary is fine,
                # even without a literal arrow — don't false-flag R2Vul descriptions).
                if not trace_f or trace_f.lower() == "none" or len(trace_f) < 12:
                    issues["vuln_weak_trace"].append(rid)
                if sev_f not in ("low", "medium", "high"):
                    issues["vuln_bad_severity"].append(rid)
            elif lbl == "safe":
                if status != "safe":
                    issues["status_mismatch"].append(rid)
                if cwe_f and cwe_f not in ("none", "n/a", "-"):
                    issues["safe_has_cwe"].append(rid)
                if fix_f and fix_f != "none":
                    issues["safe_has_fix"].append(rid)
                if _CWE.search(trace_f):
                    issues["safe_cwe_in_trace"].append(rid)
                if sev_f and sev_f != "none":
                    issues["safe_has_severity"].append(rid)

    # cross-record contradiction: same code, both safe and vuln
    contradictions = [h for h, labs in code_labels.items() if "safe" in labs and "vuln" in labs]
    dup_codes = sum(1 for h, c in code_seen.items() if c > 1)

    print(f"=== CORPUS AUDIT — {total} records ===")
    print(f"by label: {dict(by_label)}")
    print()
    print("INTERNAL CONSISTENCY ISSUES:")
    if not any(issues.values()):
        print("  (none)")
    for k in sorted(issues, key=lambda x: -len(issues[x])):
        print(f"  {k:<22}{len(issues[k])}")
    print()
    print("CROSS-RECORD:")
    print(f"  same code labelled BOTH safe & vuln (contradiction): {len(contradictions)}")
    print(f"  exact-duplicate code blocks: {dup_codes}")

    json.dump({"issues": {k: v for k, v in issues.items()},
               "contradiction_hashes": contradictions[:200],
               "n_contradictions": len(contradictions), "dup_codes": dup_codes,
               "total": total, "by_label": dict(by_label)},
              open("corpus_audit_report.json", "w"), indent=1)
    print("\nfull report -> corpus_audit_report.json")


if __name__ == "__main__":
    main()
