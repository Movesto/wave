"""Post-audit cleanup of the regen corpus. Two surgical passes (backs up first):

 1. strip corruption -- control bytes and the U+FFFD replacement char echoed from source -- from
    every assistant trace, in place.
 2. drop VACUOUS-SAFE junk -- safe verdicts reached by "there is nothing here / the weakness does
    not apply" on a metadata/inert extraction (an unmodelled-CWE case the sink-filter can't catch).
    Only from SINGLES (never breaks a contrastive pair); moved to regen_dropped.jsonl for the record.

  python cleanup_regen.py           # report + apply
  python cleanup_regen.py --dry     # report only
"""
import json, os, re, sys, shutil
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

STAGING = "data/cot/staging"
FILES = ["regen_deepseek", "regen_singles", "regen_unsure", "regen_suspect"]
DROPPED = f"{STAGING}/regen_dropped.jsonl"

_CTRL = re.compile("[�\x00-\x08\x0b\x0c\x0e-\x1f]")
# TIGHT: only the genuine metadata/inert-code junk (unmodelled-CWE extractions the sink-filter
# can't catch). Broader phrasings ("weakness does not apply", "there is nothing to") also fire on
# LEGIT safes that locate a control, so they are deliberately excluded to avoid false drops.
_VACUOUS = re.compile(
    r"not used in any computation|version numbers and commit|does not apply to this content|"
    r"as written,? this code is inert|packaging and build metadata|entirely metadata|"
    r"these constants are immutable", re.I)


def _fix_garbage(t):
    """Strip control/replacement chars and the stray ')Skip' token DeepSeek sometimes injects."""
    t = _CTRL.sub("", t)
    t = t.replace(")Skip", ")")
    return t


def load(name):
    p = f"{STAGING}/{name}.jsonl"
    return [json.loads(l) for l in open(p, encoding="utf-8")] if os.path.exists(p) else []


def main():
    dry = "--dry" in sys.argv
    dropped, cleaned = [], 0
    stats = {}
    for name in FILES:
        recs = load(name)
        keep, ndrop, nclean = [], 0, 0
        for r in recs:
            t = r["messages"][1]["content"]
            t2 = _fix_garbage(t)
            if t2 != t:
                r["messages"][1]["content"] = t2
                nclean += 1
            m = r["_meta"]
            is_single = name == "regen_singles"
            vac = (m["label"] == "safe" and m.get("model_verdict") == "safe"
                   and _VACUOUS.search(r["messages"][1]["content"]))
            if vac and is_single:                 # drop vacuous-safe singles only
                dropped.append(r); ndrop += 1
                continue
            if vac and name == "regen_deepseek":  # a vacuous side inside a KEPT pair -> flag, keep
                print(f"  PAIR-VACUOUS (review, not dropped): {m['cve']} {m['label']}")
            keep.append(r)
        cleaned += nclean
        stats[name] = (len(recs), nclean, ndrop, len(keep))
        if not dry:
            shutil.copy(f"{STAGING}/{name}.jsonl", f"{STAGING}/{name}.jsonl.precleanup_bak")
            with open(f"{STAGING}/{name}.jsonl", "w", encoding="utf-8") as f:
                for r in keep:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
    if dropped and not dry:
        with open(DROPPED, "a", encoding="utf-8") as f:
            for r in dropped:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"\n{'DRY ' if dry else ''}cleanup:")
    for name, (n0, nc, nd, n1) in stats.items():
        print(f"  {name:16s}: {n0} -> {n1}  (chars-cleaned {nc}, vacuous-dropped {nd})")
    print(f"total corruption-cleaned: {cleaned} | vacuous-safe dropped: {len(dropped)} -> {DROPPED}")


if __name__ == "__main__":
    main()
