"""DPO on the contrastive pairs, starting from the v14 SFT adapter.

Why this and not more SFT: v13 and v14 both sit at chance on paired discrimination
(7/52 and 6/52 real pairs, MCC 0.039 and 0.132, McNemar p>0.6 against v12.1b). In SFT
the two sides of a pair are separate examples seen hundreds of steps apart, so the model
can satisfy each independently -- and did. DPO makes the contrast the objective.

The reference model is the SAME model with the LoRA adapter disabled, which PEFT gives
us for free: no second 8B in VRAM.

Start point is the v14 adapter, not the base model. DPO sharpens a policy that can
already produce the output format; run from base it would spend its budget on formatting.

    python train_dpo.py
"""
import json
import os
from pathlib import Path

import torch
from datasets import Dataset
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

# trl 0.27.1 + transformers 5.9.0 incompatibility, patched before trl's lazy modules
# load. transformers' `_is_package_available()` now returns a TUPLE `(False, None)`;
# trl's `is_weave_available()` returns it unchanged, and a non-empty tuple is truthy --
# so `trl/trainer/callbacks.py` does `if is_weave_available(): import weave` and blows
# up precisely because weave is NOT installed. Forcing the optional integrations off is
# correct here: we log nothing to W&B.
import trl.import_utils as _trl_iu

for _name in ("is_weave_available", "is_wandb_available", "is_mergekit_available"):
    if hasattr(_trl_iu, _name):
        setattr(_trl_iu, _name, lambda: False)

from trl import DPOConfig, DPOTrainer  # noqa: E402

CONFIG = {
    "model_name": os.environ.get("WAVE_MODEL_NAME", "Qwen/Qwen3-8B"),
    "init_adapter": os.environ.get("WAVE_DPO_INIT", "data/runs/v14/best/qwen_cot_v14_best"),
    "pairs": os.environ.get("WAVE_DPO_PAIRS", "data/cot/dpo/dpo_pairs.jsonl"),
    "output_dir": Path(os.environ.get("WAVE_OUTPUT_DIR", "data/runs/v15_dpo/final/qwen_dpo_v15")),
    # beta controls how far the policy may drift from the reference. 0.1 is the usual
    # starting point; lower lets it move further and risks losing the SFT formatting.
    "beta": float(os.environ.get("WAVE_DPO_BETA", "0.1")),
    # DPO learning rates are 1-2 orders below SFT. 2e-4 (our SFT rate) would blow the
    # policy away from the reference in a few dozen steps on 1,540 examples.
    "lr": float(os.environ.get("WAVE_DPO_LR", "5e-6")),
    "epochs": float(os.environ.get("WAVE_DPO_EPOCHS", "2")),
    "batch_size": 1,
    "grad_accum": 16,
    # 1280, not 1792. DPO holds FOUR forward passes per example (chosen+rejected x
    # policy+reference), so a grad_accum window containing several long sequences
    # spiked VRAM and the OS hard-killed the process -- four runs, every one dying at
    # step 31 with NO Python traceback, which is the signature of an OS kill rather
    # than an exception. At 1280 it cleared step 31 with 15.9/16.3 GB in use.
    "max_length": int(os.environ.get("WAVE_DPO_MAXLEN", "1280")),
    "max_prompt_length": int(os.environ.get("WAVE_DPO_MAXPROMPT", "1024")),
    "seed": 42,
}


def log(msg):
    print(msg, flush=True)


def main():
    rows = [json.loads(l) for l in open(CONFIG["pairs"], encoding="utf-8") if l.strip()]
    log(f"triples: {len(rows)}")
    kinds = {}
    for r in rows:
        kinds[r["_meta"]["kind"]] = kinds.get(r["_meta"]["kind"], 0) + 1
    log(f"  by kind: {kinds}")

    # Conversational format so trl applies the SAME chat template the SFT used. Passing
    # raw strings would train on a different prompt shape than the model was taught.
    ds = Dataset.from_list([{
        "prompt": [{"role": "user", "content": r["prompt"]}],
        "chosen": [{"role": "assistant", "content": r["chosen"]}],
        "rejected": [{"role": "assistant", "content": r["rejected"]}],
    } for r in rows])

    tok = AutoTokenizer.from_pretrained(CONFIG["model_name"], trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    log(f"loading {CONFIG['model_name']} in 4-bit nf4...")
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.bfloat16,
                             bnb_4bit_use_double_quant=True)
    base = AutoModelForCausalLM.from_pretrained(
        CONFIG["model_name"], quantization_config=bnb, device_map={"": 0},
        trust_remote_code=True)

    log(f"loading SFT adapter: {CONFIG['init_adapter']}")
    model = PeftModel.from_pretrained(base, CONFIG["init_adapter"], is_trainable=True)
    model.print_trainable_parameters()

    # trl 0.27.1 expects `model.warnings_issued`, which transformers 5.9.0 no longer
    # defines. The attribute lookup falls through PeftModel -> base_model -> the inner
    # Qwen3ForCausalLM and raises. Same root cause as the weave patch above: trl is
    # built against an older transformers.
    for _m in (base, getattr(model, "base_model", None),
               getattr(getattr(model, "base_model", None), "model", None)):
        if _m is not None and not hasattr(_m, "warnings_issued"):
            _m.warnings_issued = {}

    args = DPOConfig(
        output_dir=str(CONFIG["output_dir"]),
        per_device_train_batch_size=CONFIG["batch_size"],
        gradient_accumulation_steps=CONFIG["grad_accum"],
        num_train_epochs=CONFIG["epochs"],
        learning_rate=CONFIG["lr"],
        beta=CONFIG["beta"],
        max_length=CONFIG["max_length"],
        max_prompt_length=CONFIG["max_prompt_length"],
        logging_steps=5,
        # Step-level saves, not epoch-level: the first attempt died at step 31/194 with
        # no traceback and `save_strategy="epoch"` meant 21 minutes of training was lost
        # because the first checkpoint would not have landed until step 97.
        save_strategy="steps",
        save_steps=15,
        save_total_limit=3,
        bf16=True,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        report_to=[],
        seed=CONFIG["seed"],
        remove_unused_columns=False,
    )

    # ref_model=None + a PEFT model => trl uses the adapter-disabled model as reference.
    trainer = DPOTrainer(model=model, ref_model=None, args=args,
                         train_dataset=ds, processing_class=tok)
    log(f"steps/epoch ~= {len(ds) // (CONFIG['batch_size'] * CONFIG['grad_accum'])}")
    # Resume from the newest step checkpoint if one exists.
    ckpts = sorted(CONFIG["output_dir"].glob("checkpoint-*"),
                   key=lambda d: int(d.name.split("-")[-1]))         if CONFIG["output_dir"].exists() else []
    if ckpts:
        log(f"resuming from {ckpts[-1]}")
        trainer.train(resume_from_checkpoint=str(ckpts[-1]))
    else:
        trainer.train()
    trainer.save_model(str(CONFIG["output_dir"]))
    tok.save_pretrained(str(CONFIG["output_dir"]))
    log(f"\nDPO complete -> {CONFIG['output_dir']}")


if __name__ == "__main__":
    main()
