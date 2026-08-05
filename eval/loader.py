# ============================================================
# eval/loader.py
#
# Load the held-out eval set and extract ground truth for each
# example. Eval set lives in data/cot/eval/<shape>.jsonl with
# the same schema as training (messages + _meta).
# ============================================================
import json
import re
from pathlib import Path
from typing import Iterator

from .config import EVAL_SET_DIR


SHAPES = ("shape1", "shape2", "shape3", "shape4",
          "shape1_ts", "shape1_react", "shape_react_syn",
          "shape1_ts_safe", "shape1_react_safe", "shape1_verified", "shape1_verified_safe",
          "shape3_codeql",           # CodeQL cross-file holdout (ALL vuln — recall only)
          "shape3_crossfile_pairs")  # cross-file pairs: the only cross-file SAFE records,
                                     # so the only way to measure cross-file FPR


def iter_jsonl(path: Path) -> Iterator[dict]:
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def load_eval_set(eval_dir: Path = EVAL_SET_DIR) -> dict[str, list[dict]]:
    """Return {bucket: [records...]} for EVERY jsonl in the eval dir.

    This used to build `eval_dir/{shape}.jsonl` from a hardcoded SHAPES list. The
    eval_v2 files are named for their SOURCE, not a shape -- `shape1_eval_primevul`,
    `shape1_eval_v3_matched` -- so none of them matched and the loader silently
    returned empty lists for every shape. The trainer had the identical bug on its
    exclusion set: an eval file whose name is not a shape name excluded nothing.

    Bucketing is by the record's own `_meta.shape` where present, falling back to the
    filename stem, so stratified planning still works without a name registry.
    """
    out: dict[str, list[dict]] = {}
    for path in sorted(eval_dir.glob("*.jsonl")):
        for rec in iter_jsonl(path):
            bucket = (rec.get("_meta") or {}).get("shape") or path.stem
            out.setdefault(bucket, []).append(rec)
    return out


_CWE_RE = re.compile(r"\bCWE-(\d{1,4})\b")


def extract_ground_truth(record: dict) -> dict:
    """Pull ground truth from a record. Uses _meta primarily, falls back to parsing the
    assistant verdict for fields _meta might not carry."""
    meta = record.get("_meta", {})
    msgs = record.get("messages", [])
    asst = msgs[1].get("content", "") if len(msgs) >= 2 else ""

    gt = {
        "shape":      meta.get("shape"),
        "source":     meta.get("source"),
        "language":   meta.get("language"),
        "label":      meta.get("label"),
        "cwes":       list(meta.get("cwes") or []),
        # shape-specific
        "helper_fn":   meta.get("helper_fn"),
        "file_path":   meta.get("file_path"),
        "disposition": meta.get("disposition"),
        "multi_hop":   meta.get("multi_hop"),
        "category":    meta.get("category"),
        "num_findings": meta.get("num_findings"),
    }

    # Backfill CWE from the verdict text if _meta missed it
    if not gt["cwes"]:
        m = _CWE_RE.search(asst)
        if m:
            gt["cwes"] = [f"CWE-{m.group(1)}"]

    return gt
