"""Cross-file PAIR smoke — the counterpart smoke_crossfile.py cannot be.

smoke_crossfile.py scores 40 held-out CodeQL records that are ALL vuln, so it
only ever asks "did the model say vuln". An always-say-vuln stub scores 100% on
it, which is exactly what v11 scored. That number cannot be failed, so it cannot
be evidence.

This scores harvested cross-file PAIRS: the same caller->sink flow before and
after the fix. Three numbers, and the third is the one that matters:

  recall       vuln side called vuln      (does it still catch cross-file bugs)
  FPR          safe side called vuln      (never measured before this)
  pair-acc     BOTH sides right           (does it read the guard, or the shape)

A model that flags cross-file shape on sight gets recall 100 / FPR 100 /
pair-acc 0 — indistinguishable from v11's headline under the old smoke, and
obviously worthless here.

  WAVE_ADAPTER_PATH=data/runs/v12/best/qwen_cot_v12_best python smoke_crossfile_pairs.py
"""
import json
import os
import random
from collections import defaultdict
from pathlib import Path

SRC = Path(os.environ.get("WAVE_XPAIRS", "data/cot/eval/shape3_crossfile_pairs.jsonl"))


def main() -> None:
    if not SRC.exists():
        raise SystemExit(f"no pair file at {SRC} — run build_crossfile_pairs.py and carve_crossfile_eval.py")

    by_pair: dict[str, dict] = defaultdict(dict)
    for line in open(SRC, encoding="utf-8"):
        rec = json.loads(line)
        by_pair[rec["_meta"]["pair_id"]][rec["_meta"]["label"]] = rec
    pairs = [p for p in by_pair.values() if "vuln" in p and "safe" in p]
    random.seed(7)
    random.shuffle(pairs)
    n_req = int(os.environ.get("WAVE_XPAIR_N", "40"))
    pairs = pairs[:n_req]
    if not pairs:
        raise SystemExit("no complete pairs found")

    from eval.inference import QwenLoraPredictor
    from eval.parsers import parse_shape1

    predictor = QwenLoraPredictor()
    caught = flagged_safe = both_right = parse_ok = 0
    raw_path = Path("data/eval_runs") / f"xpairs_{Path(os.environ.get('WAVE_ADAPTER_PATH','base')).name}.raw.jsonl"
    raw_path.parent.mkdir(parents=True, exist_ok=True)

    with open(raw_path, "w", encoding="utf-8") as raw:
        for pair in pairs:
            verdicts = {}
            for label in ("vuln", "safe"):
                out = predictor.predict(pair[label]["messages"][0]["content"])
                status = parse_shape1(out).get("status")
                parse_ok += status is not None
                verdicts[label] = "vuln" if status in ("vuln", "confirmed") else "safe"
                raw.write(json.dumps({"pair_id": pair[label]["_meta"]["pair_id"],
                                      "side": label, "cwe": pair[label]["_meta"]["ground_truth_cwe"],
                                      "pred": verdicts[label], "raw": out}) + "\n")
            caught += verdicts["vuln"] == "vuln"
            flagged_safe += verdicts["safe"] == "vuln"
            both_right += verdicts["vuln"] == "vuln" and verdicts["safe"] == "safe"

    n = len(pairs)
    print(f"ADAPTER={os.environ.get('WAVE_ADAPTER_PATH')}  (cross-file pairs, n={n})")
    print(f"  recall    {caught*100//n}%  ({caught}/{n})   vuln side caught")
    print(f"  FPR       {flagged_safe*100//n}%  ({flagged_safe}/{n})   patched side wrongly flagged")
    print(f"  pair-acc  {both_right*100//n}%  ({both_right}/{n})   <- the real number")
    print(f"  parse     {parse_ok}/{n*2}")
    print(f"  raw -> {raw_path}")
    if flagged_safe == n and caught == n:
        print("\n  NOTE: flags every cross-file record regardless of the guard — "
              "identical behaviour to an always-vuln stub.")


if __name__ == "__main__":
    main()
