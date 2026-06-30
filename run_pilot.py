"""Pilot orchestrator for the CoT conversion pipeline.

Picks the generator backend from WAVE_GENERATOR_BACKEND (default: local).
Only requires ANTHROPIC_API_KEY when backend == "anthropic".

Usage:
    python run_pilot.py                          # all four shapes (local model)
    python run_pilot.py shape2 shape3 shape4     # only the named shapes
    python run_pilot.py --target 50              # different per-shape target
    python run_pilot.py --preview-only           # estimate cost/time, no calls
"""
import argparse
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from cot.config import PILOT_PER_SHAPE, PILOT_DIR, GENERATOR_MODEL, require_api_key
from cot.runner import run_shape
from cot.shapes import shape1, shape2, shape3, shape4
from cot.shapes import shape1_ts, shape1_react, shape_react_syn
from cot.shapes import shape1_ts_safe, shape1_react_safe
from cot.shapes import shape1_verified, shape1_verified_safe


ALL_SHAPES = {
    "shape1": shape1, "shape2": shape2, "shape3": shape3, "shape4": shape4,
    # Language-coverage variants (R2Vul has no TS/React).
    "shape1_ts": shape1_ts,          # real TypeScript, VULN-only (teacher over-flags safe)
    "shape1_react": shape1_react,    # real React, target ~200 (hard ceiling)
    "shape_react_syn": shape_react_syn,  # synthetic React top-up, target ~500
    # Safe-only generators (teacher never judges, so it can't over-flag).
    "shape1_ts_safe": shape1_ts_safe,
    "shape1_react_safe": shape1_react_safe,
    # Verified vuln regeneration — gated against the patch oracle, drops failures.
    "shape1_verified": shape1_verified,
    # Verified-safe: the patched (safe) code side, to balance the verified vuln.
    "shape1_verified_safe": shape1_verified_safe,
}


def _backend() -> str:
    return os.environ.get("WAVE_GENERATOR_BACKEND", "local").lower()


def _resolved_model_name() -> str:
    """Return a printable model id for the active backend."""
    if _backend() == "anthropic":
        return GENERATOR_MODEL
    return os.environ.get("WAVE_LOCAL_MODEL", "openai/gpt-oss-20b")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("shapes", nargs="*", choices=list(ALL_SHAPES.keys()),
                        help="Specific shapes to run (default: all).")
    parser.add_argument("--preview-only", action="store_true",
                        help="Estimate cost/time without making any model calls.")
    parser.add_argument("--target", type=int, default=PILOT_PER_SHAPE,
                        help=f"Target kept records per shape (default {PILOT_PER_SHAPE}).")
    args = parser.parse_args()

    selected = args.shapes if args.shapes else list(ALL_SHAPES.keys())
    backend = _backend()

    # Anthropic backend needs an API key. Local backend doesn't.
    if not args.preview_only and backend == "anthropic":
        try:
            require_api_key()
        except RuntimeError as e:
            print(f"\nERROR: {e}", file=sys.stderr)
            print("Re-run with --preview-only for a cost estimate without the API.", file=sys.stderr)
            print("Or set WAVE_GENERATOR_BACKEND=local to use the local model.", file=sys.stderr)
            sys.exit(1)

    print(f"\nBackend:         {backend}")
    print(f"Model:           {_resolved_model_name()}")
    print(f"Pilot output:    {PILOT_DIR}")
    print(f"Shapes to run:   {selected}")
    print(f"Target per shape: {args.target}")
    print(f"Mode:            {'PREVIEW (no model calls)' if args.preview_only else 'LIVE'}")
    if backend == "local":
        dtype = os.environ.get("WAVE_LOCAL_DTYPE", "4bit")
        max_t = os.environ.get("WAVE_LOCAL_MAX_TOKENS", "2048")
        print(f"Local dtype:     {dtype}   max_tokens: {max_t}")
    print()

    all_stats = []
    for sname in selected:
        shape = ALL_SHAPES[sname]
        out_path = PILOT_DIR / f"{sname}.jsonl"
        try:
            stats = run_shape(
                shape,
                str(out_path),
                target=args.target,
                cost_preview_only=args.preview_only,
            )
            all_stats.append(stats)
        except Exception as e:
            print(f"\n[{sname}] FAILED: {e}", file=sys.stderr)
            raise

    if not args.preview_only:
        print("\n" + "=" * 70)
        print("PILOT COMPLETE — SUMMARY")
        print("=" * 70)
        total_kept = sum(s.kept for s in all_stats)
        total_attempted = sum(s.attempted for s in all_stats)
        total_in = sum(s.actual_input_tokens for s in all_stats)
        total_out = sum(s.actual_output_tokens for s in all_stats)
        total_elapsed = sum(s.elapsed_sec for s in all_stats)
        print(f"  total kept:              {total_kept:,} / {total_attempted:,} attempts")
        print(f"  total input tokens:      {total_in:,}")
        print(f"  total output tokens:     {total_out:,}")
        if total_elapsed > 0 and total_kept > 0:
            print(f"  wall time:               {total_elapsed/60:.1f} min ({total_kept/total_elapsed*60:.1f} kept/min)")
        print()
        for s in all_stats:
            print(f"  {s.shape}: kept {s.kept}  discarded {s.discarded}  errors {s.api_errors}")
        print(f"\nReview pilot output in: {PILOT_DIR}")
        if backend == "local":
            print("Pipeline is resumable — .done sidecar files track completed task_ids.")


if __name__ == "__main__":
    main()
