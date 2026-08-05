"""DPO written directly, without trl. Memory-bounded so it can actually finish.

Why not trl: five runs killed by the OS with no Python traceback. trl batches four
sequences per example (chosen + rejected, policy + reference) and 16 GB cannot hold that
for our longest excerpts. Two of the five deaths happened during model LOAD, before any
training, which no hyperparameter fixes.

Two changes make this fit:

  1. THE REFERENCE IS FROZEN, SO ITS LOG-PROBS ARE CONSTANT. Compute them once up front
     with the adapter disabled, cache to disk, and training never runs the reference
     again. That removes half the forward passes outright.
  2. ONE SEQUENCE AT A TIME. Peak memory is a single forward+backward, not four.

The loss is standard DPO (Rafailov et al.):

    L = -log sigmoid( beta * [ (logp_pol(chosen)  - logp_ref(chosen))
                             - (logp_pol(rejected) - logp_ref(rejected)) ] )

Log-probs are summed over the ASSISTANT tokens only, masking the prompt exactly the way
train_qwen_cot.py masks its SFT loss -- otherwise the model is rewarded for the prompt
it was given rather than the answer it produced.

    python train_dpo_manual.py --precompute      # phase 1, reference log-probs
    python train_dpo_manual.py --train           # phase 2, policy
"""
import argparse
import json
import math
import os
import random
import time
from pathlib import Path

import torch
import torch.nn.functional as F
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

CONFIG = {
    "model_name": os.environ.get("WAVE_MODEL_NAME", "Qwen/Qwen3-8B"),
    "init_adapter": os.environ.get("WAVE_DPO_INIT", "data/qwen_cot_v14_best"),
    "pairs": os.environ.get("WAVE_DPO_PAIRS", "data/cot/dpo/dpo_pairs.jsonl"),
    "ref_cache": Path(os.environ.get("WAVE_DPO_REFCACHE", "data/cot/dpo/ref_logps.jsonl")),
    "out_dir": Path(os.environ.get("WAVE_OUTPUT_DIR", "data/qwen_dpo_v15m")),
    "beta": float(os.environ.get("WAVE_DPO_BETA", "0.1")),
    "lr": float(os.environ.get("WAVE_DPO_LR", "5e-6")),
    "epochs": int(os.environ.get("WAVE_DPO_EPOCHS", "2")),
    "grad_accum": int(os.environ.get("WAVE_DPO_ACCUM", "16")),
    "max_len": int(os.environ.get("WAVE_DPO_MAXLEN", "1280")),
    "save_every": int(os.environ.get("WAVE_DPO_SAVE_EVERY", "10")),
    "seed": 42,
}


def log(m):
    print(m, flush=True)


def load_rows():
    return [json.loads(l) for l in open(CONFIG["pairs"], encoding="utf-8") if l.strip()]


def build_model(trainable: bool):
    tok = AutoTokenizer.from_pretrained(CONFIG["model_name"], trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.bfloat16,
                             bnb_4bit_use_double_quant=True)
    base = AutoModelForCausalLM.from_pretrained(
        CONFIG["model_name"], quantization_config=bnb, device_map={"": 0},
        trust_remote_code=True)
    model = PeftModel.from_pretrained(base, CONFIG["init_adapter"],
                                      is_trainable=trainable)
    return tok, model


def encode(tok, prompt: str, answer: str):
    """(input_ids, labels) with the PROMPT masked out of the loss."""
    def tmpl(msgs, gen):
        try:
            return tok.apply_chat_template(msgs, tokenize=False,
                                           add_generation_prompt=gen,
                                           enable_thinking=True)
        except TypeError:
            return tok.apply_chat_template(msgs, tokenize=False,
                                           add_generation_prompt=gen)
    p_text = tmpl([{"role": "user", "content": prompt}], True)
    full_text = tmpl([{"role": "user", "content": prompt},
                      {"role": "assistant", "content": answer}], False)
    full = tok(full_text, truncation=True, max_length=CONFIG["max_len"],
               return_tensors="pt")
    p_len = int(tok(p_text, truncation=True, max_length=CONFIG["max_len"],
                    return_tensors="pt")["input_ids"].shape[1])
    ids = full["input_ids"]
    labels = ids.clone()
    labels[:, :min(p_len, labels.shape[1])] = -100      # mask the prompt
    return ids, labels


def seq_logp(model, ids, labels, device):
    """Summed log-prob of the unmasked (assistant) tokens."""
    ids, labels = ids.to(device), labels.to(device)
    out = model(input_ids=ids, attention_mask=torch.ones_like(ids))
    logits = out.logits[:, :-1, :]
    tgt = labels[:, 1:]
    mask = tgt != -100
    if mask.sum() == 0:
        return None
    logp = torch.log_softmax(logits.float(), dim=-1)
    picked = logp.gather(2, tgt.clamp(min=0).unsqueeze(-1)).squeeze(-1)
    return (picked * mask).sum()


@torch.no_grad()
def precompute():
    """Phase 1: reference log-probs, adapter DISABLED. Frozen, so compute once."""
    rows = load_rows()
    tok, model = build_model(trainable=False)
    model.eval()
    device = next(model.parameters()).device
    CONFIG["ref_cache"].parent.mkdir(parents=True, exist_ok=True)

    done = {}
    if CONFIG["ref_cache"].exists():
        for line in open(CONFIG["ref_cache"], encoding="utf-8"):
            if line.strip():
                r = json.loads(line)
                done[r["i"]] = r
    log(f"reference cache: {len(done)}/{len(rows)} already computed")

    with open(CONFIG["ref_cache"], "a", encoding="utf-8") as fh:
        with model.disable_adapter():           # <- this is the reference model
            for i, r in enumerate(rows):
                if i in done:
                    continue
                cid, clb = encode(tok, r["prompt"], r["chosen"])
                rid, rlb = encode(tok, r["prompt"], r["rejected"])
                lc = seq_logp(model, cid, clb, device)
                lr = seq_logp(model, rid, rlb, device)
                if lc is None or lr is None:
                    continue
                fh.write(json.dumps({"i": i, "chosen": float(lc),
                                     "rejected": float(lr)}) + "\n")
                fh.flush()
                if (i + 1) % 50 == 0:
                    log(f"  {i+1}/{len(rows)}")
                    torch.cuda.empty_cache()
    log("reference log-probs done")


def train():
    """Phase 2: policy only. The reference values come from the cache."""
    rows = load_rows()
    ref = {}
    for line in open(CONFIG["ref_cache"], encoding="utf-8"):
        if line.strip():
            r = json.loads(line)
            ref[r["i"]] = r
    usable = [i for i in range(len(rows)) if i in ref]
    log(f"trainable examples: {len(usable)}/{len(rows)}")

    tok, model = build_model(trainable=True)
    model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={
        "use_reentrant": False})
    model.enable_input_require_grads()
    model.train()
    device = next(model.parameters()).device
    params = [p for p in model.parameters() if p.requires_grad]
    opt = torch.optim.AdamW(params, lr=CONFIG["lr"])
    CONFIG["out_dir"].mkdir(parents=True, exist_ok=True)

    state_path = CONFIG["out_dir"] / "state.json"
    start_epoch, start_pos = 0, 0
    if state_path.exists() and (CONFIG["out_dir"] / "adapter_model.safetensors").exists():
        st = json.loads(state_path.read_text())
        start_epoch, start_pos = st["epoch"], st["pos"]
        log(f"resuming at epoch {start_epoch} pos {start_pos}")
        model.load_adapter(str(CONFIG["out_dir"]), adapter_name="default",
                           is_trainable=True)

    rng = random.Random(CONFIG["seed"])
    step = 0
    for epoch in range(start_epoch, CONFIG["epochs"]):
        order = list(usable)
        rng.shuffle(order)
        pos0 = start_pos if epoch == start_epoch else 0
        agg_loss, agg_acc, agg_margin, n_in_batch = 0.0, 0, 0.0, 0
        t0 = time.time()
        for pos in range(pos0, len(order)):
            i = order[pos]
            r = rows[i]
            cid, clb = encode(tok, r["prompt"], r["chosen"])
            rid, rlb = encode(tok, r["prompt"], r["rejected"])
            lc = seq_logp(model, cid, clb, device)
            lr = seq_logp(model, rid, rlb, device)
            if lc is None or lr is None:
                continue
            margin = (lc - ref[i]["chosen"]) - (lr - ref[i]["rejected"])
            loss = -F.logsigmoid(CONFIG["beta"] * margin) / CONFIG["grad_accum"]
            loss.backward()
            agg_loss += float(loss) * CONFIG["grad_accum"]
            agg_margin += float(margin)
            agg_acc += int(float(margin) > 0)
            n_in_batch += 1

            if n_in_batch == CONFIG["grad_accum"]:
                torch.nn.utils.clip_grad_norm_(params, 1.0)
                opt.step()
                opt.zero_grad(set_to_none=True)
                step += 1
                if step % 5 == 0:
                    log(f"  epoch {epoch+1} step {step} pos {pos+1}/{len(order)}  "
                        f"loss={agg_loss/n_in_batch:.4f}  "
                        f"acc={agg_acc/n_in_batch:.3f}  "
                        f"margin={agg_margin/n_in_batch:+.3f}  "
                        f"{(time.time()-t0)/max(step,1):.1f}s/step")
                if step % CONFIG["save_every"] == 0:
                    model.save_pretrained(str(CONFIG["out_dir"]))
                    state_path.write_text(json.dumps({"epoch": epoch, "pos": pos + 1}))
                    torch.cuda.empty_cache()
                agg_loss, agg_acc, agg_margin, n_in_batch = 0.0, 0, 0.0, 0
        start_pos = 0
        model.save_pretrained(str(CONFIG["out_dir"]))
        state_path.write_text(json.dumps({"epoch": epoch + 1, "pos": 0}))
        log(f"epoch {epoch+1} complete")

    tok.save_pretrained(str(CONFIG["out_dir"]))
    log(f"DPO complete -> {CONFIG['out_dir']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--precompute", action="store_true")
    ap.add_argument("--train", action="store_true")
    a = ap.parse_args()
    if a.precompute:
        precompute()
    if a.train:
        train()
    if not (a.precompute or a.train):
        ap.error("pass --precompute or --train")


if __name__ == "__main__":
    main()
