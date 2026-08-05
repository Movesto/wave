#!/usr/bin/env bash
# Full evaluation battery for a finished model. Runs unattended.
#
# Ordered by decision value, so if it is interrupted you already have the number that
# matters most:
#   1. PrimeVul     — external, curated, comparable to published results (the headline)
#   2. v2p tagged   — our guard-discrimination test, direct comparison to the 2% baseline
#   3. cross-file   — recall AND the never-before-measured cross-file FPR
#   4. eval_bench   — 369 records, paired McNemar vs v10 (needs v10's run too)
#   5. smoke_eval   — the historical 42-record number, for continuity only
#
# Every step caches per record, so a power cut costs one record and a re-run resumes.
#
#   bash run_v12_evals.sh data/qwen_cot_v12_best v12
set -u
ADAPTER="${1:-data/qwen_cot_v12_best}"
LABEL="${2:-v12}"
LOG="evals_${LABEL}.log"

if [ ! -f "$ADAPTER/adapter_model.safetensors" ]; then
  echo "no adapter at $ADAPTER — is training finished?" ; exit 1
fi

{
echo "=============================================================="
echo "eval battery: $LABEL   adapter=$ADAPTER   started $(date)"
echo "=============================================================="

echo; echo "### 1/5  PrimeVul paired (external benchmark + VD-S)"
WAVE_ADAPTER_PATH="$ADAPTER" python -u bench_primevul.py --label "$LABEL"

echo; echo "### 2/5  v2p guard discrimination (baseline pair-acc = 2%)"
WAVE_ADAPTER_PATH="$ADAPTER" python -u smoke_v2p.py --tagged-only

echo; echo "### 3/5  cross-file pairs (recall AND FPR — FPR never measured before)"
WAVE_ADAPTER_PATH="$ADAPTER" WAVE_XPAIRS=data/cot/eval/shape3_crossfile_pairs.jsonl \
  python -u smoke_crossfile_pairs.py

echo; echo "### 4/5  eval_bench 369-record stratified run"
python -u eval_bench.py run --label "$LABEL" --adapter "$ADAPTER"
python -u eval_bench.py score --label "$LABEL"
if [ -f "data/eval_runs/bench_v10.raw.jsonl" ]; then
  python -u eval_bench.py compare --a v10 --b "$LABEL"
else
  echo "(no v10 bench run yet — for the paired comparison, run:"
  echo "   python eval_bench.py run --label v10 --adapter data/qwen_cot_best )"
fi

echo; echo "### 5/5  legacy 42-record smoke (continuity with v8-v11 only)"
WAVE_ADAPTER_PATH="$ADAPTER" python -u smoke_eval.py

echo; echo "=============================================================="
echo "battery finished $(date)"
echo "Promotion rule: PrimeVul P-C and v2p pair-acc decide it. Recall alone does not —"
echo "an always-say-vuln stub scores 100% recall and 0% on both of those."
echo "=============================================================="
} 2>&1 | tee "$LOG"
