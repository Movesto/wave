"""Select a diversity- and complexity-weighted worklist from data/bridge.jsonl.

Targeting (per plan): match the real-world distribution, WEIGHT multi-file up, and FILL the
gap classes (authz / csrf / upload thin -> take whole; xss / memory abundant -> cap). Output a
round-robin ordering across family x language x complexity so no class dominates the authoring
queue. Also emits a small pilot subset (multi-file authz + xss) to validate the pipeline first.

  python select_worklist.py --n 1200 --pilot 12
"""
import argparse, json
from collections import defaultdict, Counter

BRIDGE = "data/bridge.jsonl"
OUT    = "data/cot/staging/regen_worklist.jsonl"
PILOT  = "data/cot/staging/regen_pilot.jsonl"

_FAM = {  # CWE id -> family bucket
    "CWE-862":"authz","CWE-284":"authz","CWE-863":"authz","CWE-306":"authz","CWE-285":"authz",
    "CWE-287":"authn","CWE-79":"xss","CWE-80":"xss","CWE-352":"csrf","CWE-434":"upload",
    "CWE-89":"sqli","CWE-22":"path","CWE-23":"path","CWE-78":"cmd-inj","CWE-77":"cmd-inj",
    "CWE-94":"code-inj","CWE-95":"code-inj","CWE-918":"ssrf","CWE-601":"redirect",
    "CWE-502":"deser","CWE-611":"xxe","CWE-125":"memory","CWE-787":"memory","CWE-416":"memory",
    "CWE-119":"memory","CWE-120":"memory","CWE-121":"memory","CWE-122":"memory","CWE-476":"npd",
    "CWE-190":"intoverflow","CWE-400":"dos","CWE-770":"dos","CWE-20":"input-val","CWE-74":"injection",
    "CWE-200":"info-exposure","CWE-707":"injection",
}
# thin gap families -> take ALL; abundant -> cap
CAP = {"xss":220,"memory":150,"input-val":120,"info-exposure":80,"injection":90,"npd":80,"dos":80}
GAP = {"authz","csrf","upload","authn","ssrf","deser","xxe","redirect"}  # take whole


def family(cwes):
    for c in cwes:
        f = _FAM.get(c)
        if f:
            return f
    return "other"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1200)
    ap.add_argument("--pilot", type=int, default=12)
    args = ap.parse_args()

    rows = [json.loads(l) for l in open(BRIDGE, encoding="utf-8") if l.strip()]
    rows = [r for r in rows if r.get("cwes")]

    # bucket by family; within a family prefer multi-file, then more hunks (richer)
    by_fam = defaultdict(list)
    for r in rows:
        r["family"] = family(r["cwes"])
        r["primary_lang"] = (r["langs"] or ["?"])[0]
        by_fam[r["family"]].append(r)
    for f in by_fam:
        by_fam[f].sort(key=lambda r: (r["multi_file"], r["n_hunks"]), reverse=True)

    # pick per family: whole for gaps, capped for abundant, default cap for the rest
    picked = []
    for f, lst in by_fam.items():
        if f in GAP:
            take = lst
        else:
            take = lst[:CAP.get(f, 60)]
        picked.extend(take)

    # round-robin across (family, primary_lang) so the authoring queue stays diverse
    queues = defaultdict(list)
    for r in picked:
        queues[(r["family"], r["primary_lang"])].append(r)
    order, keys = [], list(queues)
    while any(queues[k] for k in keys) and len(order) < args.n:
        for k in keys:
            if queues[k]:
                order.append(queues[k].pop())
                if len(order) >= args.n:
                    break

    with open(OUT, "w", encoding="utf-8") as f:
        for r in order:
            f.write(json.dumps(r) + "\n")

    # pilot: multi-file authz + xss, a couple of langs
    pilot = [r for r in order if r["family"] in ("authz","xss") and r["multi_file"]][:args.pilot]
    with open(PILOT, "w", encoding="utf-8") as f:
        for r in pilot:
            f.write(json.dumps(r) + "\n")

    fam_ct = Counter(r["family"] for r in order)
    lang_ct = Counter(r["primary_lang"] for r in order)
    mf = sum(1 for r in order if r["multi_file"])
    print(f"WORKLIST {len(order)} -> {OUT}  (multi-file {mf}, {100*mf//max(len(order),1)}%)")
    print(f"families: {fam_ct.most_common()}")
    print(f"langs: {lang_ct.most_common()}")
    print(f"\nPILOT {len(pilot)} -> {PILOT}:")
    for r in pilot:
        print(f"  {r['family']:6s} {r['primary_lang']:10s} files={r['n_files']:2d} {r['cwes']} {r['patch'][:60]}")


if __name__ == "__main__":
    main()
