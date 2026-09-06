# Relaunch v12.1 (TS-targeted continued training) from the step-200 rescue adapter.
# Warm start => LR must stay low (3e-5); a 2e-4 re-peak cost run2 ~2,000 steps.
# Shape weights are the exact set the original v12.1 launch used (train_v12_1.log:1).
# NOT "Stop": PowerShell 5.1 wraps a native exe's stderr in ErrorRecords, and
# transformers writes its weight-loading progress bar to stderr. Under "Stop"
# that benign progress output aborts the run during model load.
$ErrorActionPreference = "Continue"
Set-Location "C:\Users\pscad\Documents\wave"

$env:WAVE_PILOT_DIR             = "data/cot/pilot_clean"
$env:WAVE_OUTPUT_DIR            = "data/qwen_cot_v12_1b"
$env:WAVE_BEST_DIR              = "data/qwen_cot_v12_1b_best"
$env:WAVE_EPOCHS                = "1"
$env:WAVE_INIT_ADAPTER          = "data/qwen_cot_v12_1_step200_rescue"
$env:WAVE_LR                    = "3e-5"
$env:WAVE_WARMUP_RATIO          = "0.01"
$env:WAVE_MAX_SAMPLES_PER_EPOCH = "11400"
$env:WAVE_SHAPE_WEIGHTS         = '{"shape1_contrastive_ts":40.0,"shape1_ts":20.0,"shape1_ts_safe":20.0,"shape1_react":20.0,"shape1_react_safe":20.0,"shape_react_syn":8.0}'

python -u train_qwen_cot.py *> train_v12_1b.log
