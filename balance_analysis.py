"""Balance analysis of the hardened corpus. A slice that is all-vuln or all-safe
can't teach discrimination (-> over/under-flagging). Reports per-language and
per-family balance + thin slices. Analysis only, no removal."""
import io, json, glob
from collections import Counter, defaultdict
from cot.cwe_contracts import family_of

CLEAN = "data/cot/pilot_clean"


def nlabel(l):
    return "vuln" if l in ("vuln", "confirmed") else ("safe" if l == "safe" else "context")


def bar(v, s):
    tot = v + s
    if tot == 0:
        return ""
    vp = v * 20 // tot
    return "V" * vp + "S" * (20 - vp)


def main():
    lang = defaultdict(Counter)       # language -> {vuln, safe}
    fam_vuln = Counter()              # family -> vuln count
    fam_lang = defaultdict(Counter)   # family -> language counts
    shape = defaultdict(Counter)

    for p in sorted(glob.glob(f"{CLEAN}/*.jsonl")):
        sh = p.split("/")[-1][:-6]
        for line in io.open(p, encoding="utf-8"):
            if not line.strip():
                continue
            r = json.loads(line); m = r["_meta"]
            lb = nlabel(m.get("label"))
            lg = m.get("language") or "unknown"
            lang[lg][lb] += 1
            shape[sh][lb] += 1
            if lb == "vuln":
                fam = family_of(m.get("ground_truth_cwe")) or "other"
                fam_vuln[fam] += 1
                fam_lang[fam][lg] += 1

    print("=== PER-LANGUAGE balance (V=vuln S=safe) ===")
    print(f"{'language':<12}{'vuln':>6}{'safe':>6}{'V:S':>8}  bar")
    for lg in sorted(lang, key=lambda x: -(lang[x]['vuln'] + lang[x]['safe'])):
        v, s = lang[lg]["vuln"], lang[lg]["safe"]
        ratio = f"{v/max(s,1):.1f}:1" if s else "all-V"
        flag = "  <-- skew" if (s == 0 or v == 0 or v > 5 * max(s, 1) or s > 5 * max(v, 1)) else ""
        print(f"{lg:<12}{v:>6}{s:>6}{ratio:>8}  {bar(v,s)}{flag}")

    print("\n=== PER-FAMILY vuln volume (recall depends on this) ===")
    print(f"{'family':<18}{'vuln':>6}  thin?")
    for fam, n in fam_vuln.most_common():
        print(f"{fam:<18}{n:>6}  {'THIN (<30)' if n < 30 else ''}")

    print("\n=== PER-SHAPE balance ===")
    for sh in sorted(shape):
        v, s, c = shape[sh]["vuln"], shape[sh]["safe"], shape[sh]["context"]
        print(f"  {sh:<26} vuln={v:<5} safe={s:<5} context={c}")

    tv = sum(l['vuln'] for l in lang.values()); ts = sum(l['safe'] for l in lang.values())
    print(f"\nOVERALL vuln={tv}  safe={ts}  ({tv*100//(tv+ts)}% vuln) — balanced is ~50%")


if __name__ == "__main__":
    main()
