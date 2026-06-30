# ============================================================
# cot/runner.py
#
# Generic shape-runner. Each shape implements three things:
#   prepare_tasks() -> list[task]
#   build_prompt(task) -> (system_str, user_str)
#   verify(task, generated_text) -> Optional[dict_record_or_None]
#
# The runner takes care of: cost preview, checkpoint, retry, the
# call loop, per-shape statistics (discard rate, CWE/language
# spread, kept count). It is intentionally shape-agnostic.
# ============================================================
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol
from collections import Counter

from .generator import call_generator
from .checkpoint import CheckpointWriter
from .cost import estimate_cost
from .config import GENERATOR_MODEL


class Shape(Protocol):
    """Each shape module must expose these three functions."""
    name: str

    def prepare_tasks(self, limit: int) -> list[dict]: ...
    def build_prompt(self, task: dict) -> tuple[Optional[str], str]: ...
    def verify(self, task: dict, generated_text: str) -> Optional[dict]: ...


@dataclass
class RunStats:
    shape: str
    attempted: int = 0
    kept: int = 0
    discarded: int = 0
    api_errors: int = 0
    elapsed_sec: float = 0.0
    actual_input_tokens: int = 0
    actual_output_tokens: int = 0
    cwe_kept: Counter = field(default_factory=Counter)
    language_kept: Counter = field(default_factory=Counter)
    label_kept: Counter = field(default_factory=Counter)

    @property
    def discard_rate(self) -> float:
        denom = self.attempted - self.api_errors
        return self.discarded / denom if denom > 0 else 0.0

    def render(self) -> str:
        return (
            f"\n  STATS for {self.shape}\n"
            f"  -------------------------------\n"
            f"  attempted:          {self.attempted:,}\n"
            f"  kept:               {self.kept:,}\n"
            f"  discarded (verify): {self.discarded:,}  ({self.discard_rate:.1%})\n"
            f"  api errors:         {self.api_errors:,}\n"
            f"  wall time:          {self.elapsed_sec:.1f}s\n"
            f"  actual input tok:   {self.actual_input_tokens:,}\n"
            f"  actual output tok:  {self.actual_output_tokens:,}\n"
            f"  CWE spread (kept):  {dict(self.cwe_kept.most_common(8))}\n"
            f"  language spread:    {dict(self.language_kept.most_common())}\n"
            f"  label spread:       {dict(self.label_kept.most_common())}\n"
        )


def run_shape(
    shape: Shape,
    output_path: str,
    target: int,
    *,
    cost_preview_only: bool = False,
    avg_output_tokens: int = 1500,
) -> RunStats:
    """Drive one shape end-to-end.

    target: how many KEPT examples we want. We'll attempt more than this because
    of the verify discard rate. The shape's prepare_tasks(limit) is given a
    slightly inflated limit; if discard rate is high we may still fall short
    and that's surfaced in stats.
    """
    # 1. Prepare tasks. Inflate the request by 30% to absorb discards.
    inflated = int(target * 1.3) + 10
    tasks = shape.prepare_tasks(inflated)
    if not tasks:
        raise RuntimeError(f"{shape.name}.prepare_tasks() returned 0 tasks")

    # 2. Cost / time preview.
    import os
    backend = os.environ.get("WAVE_GENERATOR_BACKEND", "local").lower()
    print(f"\n[{shape.name}] Prepared {len(tasks):,} tasks for target={target}")

    if backend == "local":
        # Time estimate based on a conservative ~20 tok/s and avg_output_tokens.
        TOK_PER_SEC = 20
        secs_per_call = avg_output_tokens / TOK_PER_SEC
        total_min = (len(tasks) * secs_per_call) / 60
        print(f"  Backend:           local model ({os.environ.get('WAVE_LOCAL_MODEL','<default>')})")
        print(f"  Time estimate:     ~{total_min:.0f} min total at {TOK_PER_SEC} tok/s")
        print(f"  Per-call estimate: ~{secs_per_call:.0f}s (avg_output_tokens={avg_output_tokens})")
    else:
        # Anthropic-backed run: print API cost estimate.
        sample_prompts = []
        for t in tasks[: min(5, len(tasks))]:
            _, user = shape.build_prompt(t)
            sample_prompts.append(user)
        est = estimate_cost(sample_prompts, num_calls=len(tasks), avg_output_tokens=avg_output_tokens)
        print(est.render())

    if cost_preview_only:
        return RunStats(shape=shape.name)

    # 3. Run.
    stats = RunStats(shape=shape.name)
    started = time.time()

    with CheckpointWriter(output_path) as w:
        remaining = w.skip_completed(tasks)
        already_done = len(tasks) - len(remaining)
        if already_done:
            print(f"[{shape.name}] Resuming: {already_done:,} task_ids already complete.")

        for i, task in enumerate(remaining, 1):
            if stats.kept >= target:
                break
            stats.attempted += 1

            system, user = shape.build_prompt(task)
            try:
                resp = call_generator(user, system=system)
            except Exception as e:
                stats.api_errors += 1
                print(f"[{shape.name}] API error on {task.get('task_id')}: {e}")
                continue

            stats.actual_input_tokens += resp["input_tokens"]
            stats.actual_output_tokens += resp["output_tokens"]

            record = shape.verify(task, resp["text"])
            if record is None:
                stats.discarded += 1
                continue

            w.write(task["task_id"], record)
            stats.kept += 1
            # Bookkeeping for spread reporting.
            for c in record.get("_meta", {}).get("cwes", []):
                stats.cwe_kept[c] += 1
            lang = record.get("_meta", {}).get("language")
            if lang:
                stats.language_kept[lang] += 1
            label = record.get("_meta", {}).get("label")
            if label:
                stats.label_kept[label] += 1

            if i % 10 == 0:
                print(f"[{shape.name}] {i}/{len(remaining)}  kept={stats.kept}  discarded={stats.discarded}  errors={stats.api_errors}")

    stats.elapsed_sec = time.time() - started
    print(stats.render())
    return stats
