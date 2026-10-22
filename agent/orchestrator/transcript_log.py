"""Diagnostic transcript log -- what the model actually RAN and OBSERVED, for EVERY proved candidate.

Unlike traces.py (opt-in TRAINING data, tool-verified verdicts only), this is a DIAGNOSTIC record written on
every normal run so a `believed`/`blocked` lead can be EXPLAINED after the fact without re-running the scan:
which runtime IMAGE the sandbox launched, every command the model ran, and the (truncated) result it saw.
It answers questions the casefile cannot -- e.g. "did the Bun runtime actually execute, or did the model only
read code?" -- which otherwise needed the live terminal stdout (lost once the run ends).

Written to <out_dir>/wave_transcripts.jsonl, one JSON record per candidate. ON by default; set
WAVE_NO_TRANSCRIPT=1 to disable (to keep a run's artifacts minimal). Never raises -- a logging glitch must not
break a run.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

_MAX_RESULT = 2000      # per-command observed-output cap (keep the file readable, not a raw dump)
_MAX_STEPS = 80         # safety cap on trail length (a runaway loop can't bloat the file)
_FILENAME = "wave_transcripts.jsonl"


def enabled() -> bool:
    """On by default; WAVE_NO_TRANSCRIPT=1/true/yes/on turns it off."""
    return os.environ.get("WAVE_NO_TRANSCRIPT", "").strip().lower() not in ("1", "true", "yes", "on")


def _step(cmd, result):
    return {"cmd": str(cmd), "result": (str(result or ""))[:_MAX_RESULT]}


def save(out_dir, *, file, line, cls, cwe, verdict, image, oracle, ran, mode, trail):
    """Append one diagnostic transcript record (image launched + the command/result trail). No-op if disabled.
    `trail` is the investigate loop's [(command, result_summary)] list. Never raises."""
    if not enabled():
        return
    try:
        d = Path(out_dir)
        d.mkdir(parents=True, exist_ok=True)
        steps = [_step(c, r) for c, r in list(trail or [])[:_MAX_STEPS]]
        rec = {"file": file, "line": line, "class": cls, "cwe": cwe, "verdict": verdict,
               "image": image, "oracle": oracle, "ran": ran, "proof_mode": mode,
               "steps": steps, "ts": time.time()}
        with (d / _FILENAME).open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
    except Exception:
        pass
