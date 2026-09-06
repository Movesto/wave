"""Trace-logger -- capture harness-VERIFIED proof drives as training data.

Every model-driven investigation that reaches a TOOL-GROUNDED verdict is a "certified drive": the model drove
the harness (ran commands, wrote a PoC, injected a marker, stood up a 2-identity harness) and a REAL observed
effect settled it. These are the gold traces for teaching a local model to USE the harness -- the parent
(a strong model like deepseek) demonstrating, the harness acting as the driving instructor that certifies
each drive. See agent/docs/trace_training.md.

THE FILTER IS THE VERIFIER. Only tool-grounded verdicts are saved:
  - confirmed        -- a witnessed exploit (a positive: "how to drive to a real proof")
  - refuted          -- a witnessed clear via an actual run (a negative/contrastive: "how to correctly clear")
  - anomalous_state  -- a witnessed state delta (IDOR/business-logic, human-review)
`believed` and `blocked` are NEVER saved -- nothing was witnessed, so they are exactly the drives we do NOT
want the kid to imitate. And a DETERMINISTIC canary drive (no model transcript) teaches nothing -- skipped.

Opt-in, so it never bloats a normal run:
  WAVE_TRACE=1              -> traces go to <wave_repo>/traces/wave_traces.jsonl
  WAVE_TRACE_DIR=<path>     -> traces go there instead
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

_VERIFIED = {"confirmed", "refuted", "anomalous_state"}


def _dir():
    d = os.environ.get("WAVE_TRACE_DIR")
    if d:
        return Path(d)
    if os.environ.get("WAVE_TRACE", "").lower() in ("1", "true", "yes", "on"):
        return Path(__file__).resolve().parents[2] / "traces"   # <wave repo root>/traces
    return None


def enabled():
    return _dir() is not None


def save(*, target, file, line, cls, cwe, verdict, evidence, oracle, model, mode, ran, transcript):
    """Append one certified-drive trace as JSONL. No-op unless enabled AND the verdict is tool-verified AND
    there is a model transcript (a deterministic canary drive has nothing to teach). Never raises -- a
    logging glitch must not break a run."""
    d = _dir()
    if d is None or verdict not in _VERIFIED or not transcript:
        return
    try:
        d.mkdir(parents=True, exist_ok=True)
        # a `refuted`/`anomalous_state` is a NEGATIVE/contrastive example; `confirmed` is a POSITIVE.
        label = "positive" if verdict == "confirmed" else ("review" if verdict == "anomalous_state" else "negative")
        rec = {
            "id": f"{Path(str(target)).name}:{file}:{line}:{cls}",
            "target": str(target), "file": file, "line": line, "class": cls, "cwe": cwe,
            "verdict": verdict, "label": label, "verified": True,
            "evidence": (evidence or "")[:800], "oracle": oracle, "proof_mode": mode,
            "model": model, "ran": ran, "ts": time.time(),
            "messages": transcript,                         # the full drive: system + brief + tool-calls + results
        }
        with (d / "wave_traces.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
    except Exception:
        pass
