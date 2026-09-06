"""V2P smoke: the Semantic-Trap test (arXiv 2601.22655).

For each real (vulnerable, patched) pair we scan BOTH versions:
  - the vulnerable code   -> the model should say VULN
  - its patched version   -> the model should say SAFE

The headline number is **patched-FPR**: how often the model still flags the
FIX as vulnerable. A high patched-FPR means the model is pattern-matching on
"this looks like the vuln class" rather than reasoning about whether the flaw
is actually present — i.e. it's in the semantic trap. Standard smokes (vuln vs
unrelated-safe) hide this; V2P (vuln vs its own patch) exposes it.

Pairs come from cot.fix_pairs (patch diffs). We tag each pair seen/unseen vs the
training corpus so the run also speaks to generalization on unseen fixes.

Usage:
  WAVE_ADAPTER_PATH=data/qwen_cot_best python smoke_v2p.py
  python smoke_v2p.py --stub     # validate plumbing without loading the model
"""
import argparse
import glob
import hashlib
import json
import os
import random

from cot.fix_pairs import iter_fix_pairs
from eval.parsers import parse_shape1

PILOT_DIR = "data/cot/pilot_clean"


# Checklist-guided variant (2026-07-24 experiment). The autopsy showed the model
# is GUARD-BLIND: it re-narrates source->sink on both the vuln and its patch and
# never evaluates the guard the fix added. This prefix forces an explicit
# "find the guard or state its absence" step, to test whether guard-blindness is
# a prompting problem (H1: model can look, wasn't asked) or a data problem
# (H2: won't look regardless). Kept OUT of _hash so leak-tagging is unaffected.
# v1 (2026-07-24): proved guard-reading is latent (5/5 correct pairs quoted the
# real added guard) but CRATERED recall 87->20 — step 1 kept returning "untrusted
# inputs: None" on isolated functions, so it never reached a flag.
GUIDE_V1 = (
    "Analyze the code for a security vulnerability. Reason in these steps:\n"
    "1. List every untrusted/attacker-controlled input.\n"
    "2. Trace each one to any dangerous sink.\n"
    "3. For EACH source->sink path, look for a guard on that path — input "
    "validation, sanitization/encoding, parameterization, or an authorization "
    "check. Quote the exact guard line if one exists.\n"
    "4. Report 'vuln' ONLY if a tainted source reaches a sink with NO effective "
    "guard. If a guard neutralizes the flow, report 'safe'.\n\n"
)

# v2 (2026-07-24): fix v1's recall collapse. (a) Force taint assumption so step 1
# stops returning "None"; (b) drop the "ONLY if" caution that over-primed safe;
# (c) require a QUOTED guard line to call safe, so the guard-read is the pivot.
GUIDE_V2 = (
    "Analyze the code for a security vulnerability. This is one function shown "
    "without its callers, so treat EVERY function parameter, request/HTTP field, "
    "and external read as attacker-controlled unless the code itself proves "
    "otherwise. Reason in these steps:\n"
    "1. List the attacker-controlled inputs (parameters count).\n"
    "2. Trace each to any dangerous sink (query, exec, file path, HTML, redirect, "
    "auth decision, deserialization).\n"
    "3. For each source->sink path, decide: is there a specific guard ON THAT "
    "PATH — validation, sanitization/encoding, parameterization, or an "
    "authorization check? If yes, QUOTE the exact guard line.\n"
    "4. Verdict: if a tainted input can reach a sink and you cannot quote a guard "
    "that stops it, report 'vuln'. Report 'safe' only when you can quote the "
    "guard that neutralizes the flow, or there is genuinely no sink.\n\n"
)

_GUIDES = {"v1": GUIDE_V1, "v2": GUIDE_V2}


def scan_prompt(code: str, guided: bool = False, guide: str = "v2") -> str:
    # The exact inference prompt the model is trained/evaluated on (shape1),
    # optionally prefixed with a guard-checking checklist (v1 or v2).
    body = f"<SCAN>\n{code}\n</SCAN>"
    return (_GUIDES[guide] + body) if guided else body


def _hash(code: str) -> str:
    # Always hashes the BARE prompt (guided prefix excluded) so seen/unseen
    # tagging matches the training corpus regardless of experiment mode.
    return hashlib.sha256(scan_prompt(code).encode("utf-8")).hexdigest()


def _seen_hashes() -> set[str]:
    """sha256 of every training <SCAN> prompt, so we can flag leaked pairs. Covers pilot_clean AND
    the staging shapes that actually train (the regen corpus lives there) -- otherwise a V2P pair
    that overlaps a regen training pair would be mislabelled 'unseen' and inflate the number."""
    seen = set()
    paths = (glob.glob(os.path.join(PILOT_DIR, "*.jsonl"))
             + glob.glob(os.path.join("data/cot/staging", "regen_*.jsonl")))
    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                msgs = rec.get("messages") or []
                if msgs:
                    seen.add(hashlib.sha256(msgs[0].get("content", "").encode("utf-8")).hexdigest())
    return seen


def collect_pairs(n: int, langs: set[str], seed: int, tagged_only: bool = False) -> list[dict]:
    """Deterministic sample of usable (vuln, fixed) pairs, preferring pairs whose
    patched side is UNSEEN in training (that's the interesting trap+generalization
    case). Returns pairs tagged with seen/unseen for each side."""
    seen = _seen_hashes()
    # Enough candidates to sort/prefer-unseen and sample from, without draining
    # the whole 32K-patch corpus (that generator is slow).
    cap = max(n * 40, 1500)
    pool = []
    for fp in iter_fix_pairs(langs):
        v, fx = fp.get("vuln_code", ""), fp.get("fixed_code", "")
        if not v or not fx or v == fx:
            continue
        if not (60 <= len(v) <= 1500 and 60 <= len(fx) <= 1500):
            continue
        if tagged_only and not fp.get("cwe"):
            continue
        fp["_vuln_seen"] = _hash(v) in seen
        fp["_fixed_seen"] = _hash(fx) in seen
        pool.append(fp)
        if len(pool) >= cap:
            break
    random.Random(seed).shuffle(pool)
    # Prefer pairs whose patched side is unseen (0 = best), then by vuln unseen.
    pool.sort(key=lambda p: (p["_fixed_seen"], p["_vuln_seen"]))
    return pool[:n]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=int(os.environ.get("WAVE_V2P_N", "40")))
    ap.add_argument("--langs", default=os.environ.get(
        "WAVE_V2P_LANGS", "python,javascript,typescript,java,php,go,c"))
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--stub", action="store_true",
                    help="assemble pairs and print stats without loading the model")
    ap.add_argument("--tagged-only", action="store_true",
                    default=os.environ.get("WAVE_V2P_TAGGED", "") == "1",
                    help="only pairs with a known CWE tag (autopsy 2026-07-24: untagged "
                         "pairs include collateral hunks — comment shifts, refactors — "
                         "that aren't security fixes and muddy the trap metric)")
    ap.add_argument("--guided", action="store_true",
                    default=os.environ.get("WAVE_V2P_GUIDED", "") == "1",
                    help="prefix each scan with the guard-checking checklist (tests "
                         "whether guard-blindness is fixable at inference time)")
    ap.add_argument("--guide", default=os.environ.get("WAVE_V2P_GUIDE", "v2"),
                    choices=["v1", "v2"],
                    help="which checklist variant (v1=strict/low-recall, v2=taint-"
                         "assuming/recall-recovering)")
    args = ap.parse_args()

    langs = {l.strip() for l in args.langs.split(",") if l.strip()}
    pairs = collect_pairs(args.n, langs, args.seed, tagged_only=args.tagged_only)
    if not pairs:
        print("No usable pairs found — check cot.fix_pairs sources.")
        return

    if args.guided:
        print(f"MODE: guided (guard-checking checklist prefix, {args.guide})")
    fixed_unseen = sum(1 for p in pairs if not p["_fixed_seen"])
    both_unseen = sum(1 for p in pairs if not p["_fixed_seen"] and not p["_vuln_seen"])
    print(f"V2P pairs: {len(pairs)}  (patched-side unseen: {fixed_unseen}/{len(pairs)}, "
          f"both-sides unseen: {both_unseen}/{len(pairs)})")

    if args.stub:
        # Plumbing check only — no GPU/model needed.
        ex = pairs[0]
        print(f"[stub] sample lang={ex.get('language')} cwe={ex.get('cwe')} "
              f"type={ex.get('vuln_type')} vuln_len={len(ex['vuln_code'])} "
              f"fixed_len={len(ex['fixed_code'])}")
        print(f"[stub] prompts assemble OK; parse_shape1 self-test: "
              f"{parse_shape1('status: safe').get('status')}")
        print("[stub] ready — run without --stub (GPU free) for live numbers.")
        return

    from eval.inference import QwenLoraPredictor
    p = QwenLoraPredictor()

    # Raw per-pair dump so failures can be autopsied without re-running the GPU.
    adapter = os.environ.get("WAVE_ADAPTER_PATH", "base")
    raw_path = os.environ.get(
        "WAVE_V2P_RAW",
        os.path.join("data", "eval_runs",
                     f"v2p_{os.path.basename(adapter.rstrip('/\\')) or 'base'}.raw.jsonl"))
    os.makedirs(os.path.dirname(raw_path), exist_ok=True)

    def verdict(code: str) -> tuple[str, str]:
        raw = p.predict(scan_prompt(code, guided=args.guided, guide=args.guide))
        st = parse_shape1(raw).get("status")
        return ("vuln" if st in ("vuln", "confirmed") else "safe"), raw

    vuln_recall = patched_fp = pair_correct = parse_ok = 0
    with open(raw_path, "w", encoding="utf-8") as rf:
        for pr in pairs:
            vv, vraw = verdict(pr["vuln_code"])    # expect vuln
            fv, fraw = verdict(pr["fixed_code"])   # expect safe
            parse_ok += 2  # parse_shape1 always returns a dict; status None -> safe
            vuln_recall += (vv == "vuln")
            patched_fp += (fv == "vuln")           # THE trap metric
            pair_correct += (vv == "vuln" and fv == "safe")
            rf.write(json.dumps({
                "language": pr.get("language"), "cwe": pr.get("cwe"),
                "vuln_type": pr.get("vuln_type"),
                "vuln_code": pr["vuln_code"], "fixed_code": pr["fixed_code"],
                "vuln_verdict": vv, "fixed_verdict": fv,
                "vuln_raw": vraw, "fixed_raw": fraw,
            }, ensure_ascii=False) + "\n")
    print(f"raw outputs -> {raw_path}")

    n = len(pairs)
    print(f"ADAPTER={os.environ.get('WAVE_ADAPTER_PATH')}")
    print(f"  vuln recall     = {vuln_recall}/{n} = {vuln_recall*100//n}%")
    print(f"  patched-FPR     = {patched_fp}/{n} = {patched_fp*100//n}%   <-- semantic-trap metric (lower=better)")
    print(f"  pair accuracy   = {pair_correct}/{n} = {pair_correct*100//n}%   (both sides correct)")


if __name__ == "__main__":
    main()
