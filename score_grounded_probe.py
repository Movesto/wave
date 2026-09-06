"""Score the grounded-prompt probe. Works on partial output.

    python score_grounded_probe.py
"""
import collections
import json
import os
import sys

PROBE = "data/eval_runs/grounded_prompt_probe.jsonl"
V2L = {"exploitable": "vuln", "control_incomplete": "vuln",
       "not_exploitable": "safe", "insufficient_context": "abstain"}


def main():
    if not os.path.exists(PROBE):
        print("no probe output yet")
        return 1
    rows = [json.loads(l) for l in open(PROBE, encoding="utf-8") if l.strip()]
    print(f"scored records: {len(rows)}\n")

    # --- 1. did it emit the format at all? -------------------------------
    nf = collections.Counter(r["n_fields"] for r in rows)
    all5 = sum(1 for r in rows if r["n_fields"] == 5)
    print("FORMAT COMPLIANCE")
    print(f"  emitted all 5 fields      : {all5}/{len(rows)} ({all5/len(rows):.0%})")
    print(f"  field-count distribution  : {dict(sorted(nf.items()))}")
    print(f"  mean raw output length    : {sum(r['raw_len'] for r in rows)//len(rows)} chars")

    # --- 2. GROUNDING: is the quoted text really in the code? ------------
    print("\nGROUNDING (is the quoted value actually in the input?)")
    for f in ("sink", "source", "guard"):
        have = [r for r in rows if r["fields"].get(f)]
        ok = sum(1 for r in have if r[f + "_grounded"])
        if have:
            print(f"  {f:7s} quoted {len(have):3d}/{len(rows):3d}   grounded "
                  f"{ok:3d}/{len(have):3d} ({ok/len(have):.0%})")
        else:
            print(f"  {f:7s} quoted   0/{len(rows)}")

    # --- 3. verdicts ------------------------------------------------------
    print("\nVERDICTS")
    vc = collections.Counter(r["verdict"] for r in rows)
    for v, c in vc.most_common():
        print(f"  {v or '(none)':24s} {c}")
    mapped = [(r, V2L.get(r["verdict"])) for r in rows]
    scored = [(r, m) for r, m in mapped if m in ("vuln", "safe")]
    if scored:
        corr = sum(1 for r, m in scored if m == r["label"])
        print(f"\n  decisive answers          : {len(scored)}/{len(rows)}")
        print(f"  accuracy on those         : {corr}/{len(scored)} ({corr/len(scored):.0%})")
    abst = sum(1 for r, m in mapped if m == "abstain")
    print(f"  abstentions               : {abst}/{len(rows)} ({abst/len(rows):.0%})")

    # --- 4. PAIR ACCURACY: both sides right ------------------------------
    byp = collections.defaultdict(dict)
    for r in rows:
        byp[r["pair_id"]][r["label"]] = r
    full = {k: v for k, v in byp.items() if len(v) == 2}
    both = 0
    for k, v in full.items():
        ok = all(V2L.get(v[lab]["verdict"]) == lab for lab in ("vuln", "safe"))
        both += ok
    print("\nPAIR ACCURACY (both sides correct)")
    print(f"  complete pairs            : {len(full)}")
    if full:
        print(f"  both sides correct        : {both}/{len(full)} ({both/len(full):.0%})")
    print("  recorded baselines        : 2% bare prompt, 12% checklist prompt (v11)")

    # --- 5. does it distinguish the two sides at all? --------------------
    same = sum(1 for v in full.values()
               if v["vuln"]["verdict"] == v["safe"]["verdict"])
    if full:
        print(f"\n  pairs given the SAME verdict on both sides: {same}/{len(full)} "
              f"({same/len(full):.0%})  <- 100% means it is not reading the difference")

    # --- 6. completeness pairs specifically ------------------------------
    comp = [r for r in rows if r["kind"] in ("partial_fix_vuln", "complete_fix_safe")]
    if comp:
        ci = sum(1 for r in comp if r["verdict"] == "control_incomplete")
        print(f"\n  on guard-completeness records ({len(comp)}): "
              f"used 'control_incomplete' {ci} times")
    return 0


if __name__ == "__main__":
    sys.exit(main())
