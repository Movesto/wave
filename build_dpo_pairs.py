"""Turn the contrastive pairs into DPO preference triples.

Two SFT runs (v13, v14) failed to teach the pairwise distinction. The reason is
structural: in SFT the two sides of a pair are separate examples, seen hundreds of steps
apart at ~17% of sampling, and the model can satisfy each independently -- which is
exactly what it did (v14 sits at chance on real pairs, MCC 0.039).

DPO makes the contrast the objective instead of an emergent property. And our data
supplies the hard negative for free:

    prompt   = the VULNERABLE code
    chosen   = its own answer          "status: confirmed ... nothing constrains it"
    rejected = its PARTNER'S answer    "status: safe ... constrained by `<guard>`"

The partner's code differs only by the guard, so its answer is the maximally confusable
wrong answer for this prompt. Both directions, so each pair yields 2 triples.

TWO GUARDS AGAINST TEACHING A NEW SHORTCUT:

  * `--verdict-only` also emits triples where chosen and rejected are IDENTICAL except
    the verdict token. Without these the model can learn to prefer the phrasing of a
    confirmed answer ("nothing constrains") over a safe one ("constrained by"), which is
    wording, not reading. That is the same class of mistake as the authored codeql guard.
  * eval_v3 holdout pairs are EXCLUDED. Anything held is excluded, so a pair retired for
    any earlier reason cannot re-enter through this door.

    python build_dpo_pairs.py --write
"""
import argparse
import collections
import json
import os
import re
import sys
from pathlib import Path

OUT = "data/cot/dpo/dpo_pairs.jsonl"


def wired_shapes():
    src = re.sub(r"#[^\n]*", "", open("train_qwen_cot.py", encoding="utf-8").read())
    return re.findall(r'"([\w]+)"',
                      re.search(r'"shapes":\s*\[(.*?)\]', src, re.S).group(1))


def path_of(shape):
    for d in ("pilot", "staging"):
        p = f"data/cot/{d}/{shape}.jsonl"
        if os.path.exists(p):
            return p
    return None


def swap_verdict(answer: str, to_safe: bool) -> str | None:
    """Same answer text with only the verdict flipped, or None if not cleanly possible."""
    if to_safe:
        out = re.sub(r"^status:\s*\w+", "status: safe", answer, count=1, flags=re.M)
        out = re.sub(r"^cwe:\s*\S+", "cwe: none", out, count=1, flags=re.M)
        out = re.sub(r"^severity:\s*\w+", "severity: none", out, count=1, flags=re.M)
    else:
        out = re.sub(r"^status:\s*\w+", "status: confirmed", answer, count=1, flags=re.M)
        out = re.sub(r"^severity:\s*\w+", "severity: HIGH", out, count=1, flags=re.M)
    return out if out != answer else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--verdict-only", action="store_true", default=True)
    args = ap.parse_args()

    # every code excerpt that appears in the eval set, so nothing leaks in
    evalcodes = set()
    for p in Path("data/cot/eval_v2").glob("*.jsonl"):
        for line in open(p, encoding="utf-8"):
            if line.strip():
                r = json.loads(line)
                evalcodes.add(re.sub(r"\s+", " ",
                                     r["messages"][0]["content"]).strip().lower())

    out, f = [], collections.Counter()
    for shape in wired_shapes():
        path = path_of(shape)
        if not path:
            continue
        by_pair = collections.defaultdict(list)
        for line in open(path, encoding="utf-8"):
            if not line.strip():
                continue
            r = json.loads(line)
            m = r["_meta"]
            if m.get("held") or not m.get("pair_id"):
                continue
            if m.get("label") in ("vuln", "safe"):
                by_pair[m["pair_id"]].append(r)

        for pid, sides in by_pair.items():
            if len(sides) != 2:
                continue
            by_label = {s["_meta"]["label"]: s for s in sides}
            if set(by_label) != {"vuln", "safe"}:
                f["not_a_vuln_safe_pair"] += 1
                continue
            if any(re.sub(r"\s+", " ", s["messages"][0]["content"]).strip().lower()
                   in evalcodes for s in sides):
                f["eval_leak"] += 1
                continue

            for label, rec in by_label.items():
                other = by_label["safe" if label == "vuln" else "vuln"]
                prompt = rec["messages"][0]["content"]
                chosen = rec["messages"][1]["content"]
                # the partner's full answer: right shape, wrong verdict, and written
                # about code that differs only by the guard
                out.append({"prompt": prompt, "chosen": chosen,
                            "rejected": other["messages"][1]["content"],
                            "_meta": {"pair_id": pid, "shape": shape, "label": label,
                                      "kind": "partner_answer"}})
                f["partner"] += 1

                if args.verdict_only:
                    flipped = swap_verdict(chosen, to_safe=(label == "vuln"))
                    if flipped:
                        out.append({"prompt": prompt, "chosen": chosen,
                                    "rejected": flipped,
                                    "_meta": {"pair_id": pid, "shape": shape,
                                              "label": label, "kind": "verdict_only"}})
                        f["verdict_only"] += 1
                    else:
                        f["verdict_swap_failed"] += 1

    for k, v in f.most_common():
        print(f"  {k:24s} {v:5d}")
    print(f"\ntriples: {len(out)}  from {len({r['_meta']['pair_id'] for r in out})} pairs")
    print("  by kind :", dict(collections.Counter(r["_meta"]["kind"] for r in out)))
    print("  by shape:", dict(collections.Counter(r["_meta"]["shape"]
                                                  for r in out).most_common(6)))
    if args.write and out:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "w", encoding="utf-8") as fh:
            for r in out:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"-> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
