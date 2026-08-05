"""Carve the TypeScript/React contrastive pairs into their own shape file.

WHY: `WAVE_SHAPE_WEIGHTS` reweights whole SHAPES, and the 292 TS + 32 React
contrastive records are buried inside shape1_contrastive.jsonl (12,200 records).
That makes them impossible to upweight without also upweighting php/python/c.
Contrastive pairs are the signal that demonstrably works in this corpus
(non-TS/React MCC 0.783), and TS is the one language starved of them — 2.4% of
the contrastive set, and the only language sitting at MCC 0.000 on the 369-bench.

Carving them into shape1_contrastive_ts makes them a weightable lever for the
v12->v12.1 continued-training run.

Splits by PAIR ID, never by record: a contrastive pair is only useful if the
model sees both the vulnerable and the fixed side of the same code. Moving one
side and leaving the other behind would destroy exactly the guard-discrimination
signal we are trying to concentrate.

Idempotent: re-running rebuilds both files from the union of the two.
"""
from __future__ import annotations

import json
import shutil
from collections import Counter
from pathlib import Path

PILOT = Path("data/cot/pilot_clean")
SRC = PILOT / "shape1_contrastive.jsonl"
DST = PILOT / "shape1_contrastive_ts.jsonl"
TARGET_LANGS = {"typescript", "react"}


def _load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def main() -> None:
    records = _load(SRC) + _load(DST)  # union => idempotent re-run
    print(f"source pool: {len(records)} records")

    # Decide per PAIR, not per record: if any side of the pair is TS/React the
    # whole pair moves, so a pair is never split across the two files.
    pair_lang: dict[str, bool] = {}
    for r in records:
        m = r.get("_meta") or {}
        pid = m.get("pair_id")
        if pid is None:
            continue
        pair_lang[pid] = pair_lang.get(pid, False) or (m.get("language") in TARGET_LANGS)

    ts, rest, orphan = [], [], 0
    for r in records:
        m = r.get("_meta") or {}
        pid = m.get("pair_id")
        if pid is None:
            orphan += 1
            rest.append(r)
            continue
        (ts if pair_lang[pid] else rest).append(r)

    # A carved pair must keep BOTH sides or it teaches nothing.
    sides = Counter((r.get("_meta") or {}).get("pair_id") for r in ts)
    broken = {p: n for p, n in sides.items() if n != 2}
    if broken:
        raise SystemExit(f"ABORT: {len(broken)} carved pairs are not 2-sided: "
                         f"{list(broken.items())[:5]}")

    for path, rows in ((DST, ts), (SRC, rest)):
        if path.exists():
            shutil.copy2(path, path.with_suffix(".jsonl.pre_carve_bak"))
        with open(path, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    lang = Counter((r.get("_meta") or {}).get("language") for r in ts)
    label = Counter((r.get("_meta") or {}).get("label") for r in ts)
    print(f"carved -> {DST.name}: {len(ts)} records / {len(sides)} pairs  "
          f"langs={dict(lang)} labels={dict(label)}")
    print(f"remaining {SRC.name}: {len(rest)} records (orphans kept: {orphan})")


if __name__ == "__main__":
    main()
