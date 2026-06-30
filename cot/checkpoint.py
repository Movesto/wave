# ============================================================
# cot/checkpoint.py
#
# Resumable JSONL writing. Each input "task" carries a stable
# task_id; we keep a sidecar set of completed task_ids on disk
# so a crash mid-run only loses the in-flight call.
#
# Usage:
#     w = CheckpointWriter("data/cot/pilot/shape1.jsonl")
#     for task in tasks:
#         if task["task_id"] in w.done:
#             continue
#         result = generate(task)
#         w.write(task["task_id"], result)
# ============================================================
import json
from pathlib import Path
from typing import Iterable


class CheckpointWriter:
    """Append-only JSONL writer with a sidecar .done file of task_ids."""

    def __init__(self, output_path: str | Path):
        self.output_path = Path(output_path)
        self.done_path = self.output_path.with_suffix(self.output_path.suffix + ".done")
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.done: set[str] = self._load_done()
        # Buffered append; we flush on every write so crash loses at most one record.
        self._out = open(self.output_path, "a", encoding="utf-8")
        self._done_fh = open(self.done_path, "a", encoding="utf-8")

    def _load_done(self) -> set[str]:
        if not self.done_path.exists():
            return set()
        with open(self.done_path, "r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip()}

    def write(self, task_id: str, record: dict) -> None:
        if task_id in self.done:
            return  # idempotent
        self._out.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._out.flush()
        self._done_fh.write(task_id + "\n")
        self._done_fh.flush()
        self.done.add(task_id)

    def skip_completed(self, tasks: Iterable[dict], id_key: str = "task_id") -> list[dict]:
        """Filter out tasks whose id is already in self.done."""
        return [t for t in tasks if t[id_key] not in self.done]

    def close(self):
        self._out.close()
        self._done_fh.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
