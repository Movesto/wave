"""Auxiliary multi-task data (2026-07-24) — VulLLM ([2406.03718]) shows adding
LOCALIZATION ("which line?") and FIX-GENERATION ("produce the patch") objectives
alongside detection forces the model past surface pattern-matching. We already
have the supervision for free: the patch diff marks the vuln line + the fix.

Emits two instruction-tuned shapes to data/cot/staging/:
  shape1_localize.jsonl  — locate the vulnerable line + sink (grounded in oracle)
  shape1_fixgen.jsonl    — given the vuln + CWE, produce the fix (grounded in patch)

Distinct instruction prefixes so the tasks are learned as separate skills that
transfer back to detection. Reuses the contrastive extraction helpers.
"""
import argparse, json, os, re, hashlib, collections
from cot.fix_pairs import iter_fix_pairs
from cot.oracle import locate_from_diff
from cot.cwe_contracts import family_of, CONTRACTS
from cot.template_reason import _find_sink, _find_source
from cot.deep_trace import FAMILY_DEPTH
from build_contrastive import (_added_lines, _pick_guard, _cwe_from_guard,
                               _fallback_sink, _better_source, _norm)

LOC_OUT = "data/cot/staging/shape1_localize.jsonl"
FIX_OUT = "data/cot/staging/shape1_fixgen.jsonl"
EVAL = "data/cot/eval"

LOC_INSTR = ("Identify the single line where the vulnerability is triggered and "
             "name the dangerous sink.\n")
FIX_INSTR = "The code below has a {cwe} vulnerability. Provide the fix.\n"


def _leak():
    h = set()
    import glob
    for p in glob.glob(f"{EVAL}/*.jsonl"):
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if not line: continue
            try: r = json.loads(line)
            except: continue
            m = r.get("messages") or []
            if m:
                mm = re.search(r"<SCAN>\n?(.*?)\n?</SCAN>", m[0].get("content", ""), re.S)
                if mm: h.add(_norm(mm.group(1)))
    return h


def _rec(user, asst, lang, cwe, shape):
    return {"messages": [{"role": "user", "content": user},
                         {"role": "assistant", "content": asst}],
            "_meta": {"shape": shape, "source": shape.replace("shape1_", ""),
                      "language": lang, "label": "vuln", "cwes": [cwe],
                      "ground_truth_cwe": cwe, "cleaned": True}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=3500, help="max records PER shape")
    ap.add_argument("--langs", default="python,javascript,typescript,java,php,go,c,ruby,csharp,cpp,react")
    args = ap.parse_args()
    langs = {l.strip() for l in args.langs.split(",") if l.strip()}
    os.makedirs("data/cot/staging", exist_ok=True)
    leak = _leak()
    seen = set()
    nloc = nfix = 0
    by_cwe = collections.Counter()
    with open(LOC_OUT, "w", encoding="utf-8") as loc, open(FIX_OUT, "w", encoding="utf-8") as fix:
        for fp in iter_fix_pairs(langs):
            if nloc >= args.target and nfix >= args.target:
                break
            v, fx, cwe = fp.get("vuln_code", ""), fp.get("fixed_code", ""), fp.get("cwe")
            lang = fp.get("language", "?")
            if not v or not fx or v == fx or not (60 <= len(v) <= 1500): continue
            if _norm(v) == _norm(fx): continue
            added = _added_lines(v, fx)
            guard = _pick_guard(added)
            if not guard: continue
            if len(guard) > 200: guard = guard[:200]
            if len(_norm(guard)) > 8 and _norm(guard) in _norm(v): continue
            fam = family_of(cwe)
            if fam is None:
                cwe = _cwe_from_guard(guard, added); fam = family_of(cwe)
                if fam is None: continue
            region = locate_from_diff(v, fx)
            sink, sink_line = _find_sink(v, CONTRACTS[fam]["markers"], region.lines)
            if sink is None:
                sink, sink_line = _fallback_sink(v, region)
                if sink is None: continue
            source = _better_source(_find_source(v, fx, region), sink, v)
            nv = _norm(v)
            if nv in seen or nv in leak: continue
            seen.add(nv)
            d = FAMILY_DEPTH.get(fam, {})
            # --- localization record ---
            if nloc < args.target and sink_line:
                asst = (f"vulnerable line: {sink_line}\nsink: {sink}\n"
                        f"why: `{source}` reaches `{sink}` here, which {d.get('role','is a sensitive sink')}, "
                        f"with no guard on the path — {cwe}.")
                loc.write(json.dumps(_rec(LOC_INSTR + f"<SCAN>\n{v}\n</SCAN>", asst, lang, cwe,
                                          "shape1_localize"), ensure_ascii=False) + "\n")
                nloc += 1
            # --- fix-generation record ---
            if nfix < args.target:
                why = d.get("guard_why", "validates/neutralizes the input before the sink")
                asst = (f"fix: {guard}\nexplanation: this adds a control on the `{source}` -> `{sink}` "
                        f"path that {why}, so the input can no longer subvert the sink.")
                fix.write(json.dumps(_rec(FIX_INSTR.format(cwe=cwe) + f"<SCAN>\n{v}\n</SCAN>", asst,
                                          lang, cwe, "shape1_fixgen"), ensure_ascii=False) + "\n")
                nfix += 1
            by_cwe[cwe] += 1
    print(f"localization: {nloc} -> {LOC_OUT}")
    print(f"fix-generation: {nfix} -> {FIX_OUT}")
    print(f"top CWEs: {dict(by_cwe.most_common(10))}")


if __name__ == "__main__":
    main()
