"""QLoRA fine-tune Qwen3-8B on the CoT pilot data (shape1..shape4).

Differences vs train_qwen_sft.py:
  - 4-bit nf4 quantization (Qwen3-8B fp16 = 16 GB, doesn't fit with optimizer state)
  - Excludes eval records by hashing user-content against data/cot/eval/*.jsonl
  - Weighted sampling so shape2/3/4 are not drowned by shape1's 4k records
  - Loss masked to assistant tokens only (don't waste capacity learning the prompt)
  - max_len 2048 (shape4 multi-finding output needs the room)
  - Gradient checkpointing on (slower but lets the 8B model breathe in 16 GB VRAM)

Usage:
  python train_qwen_cot.py
"""
import hashlib
import json
import math
import os
import random
import time
from pathlib import Path

import torch
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training


# ---- config ----
CONFIG = {
    # Model + output dirs are env-overridable so we can train a different student
    # (e.g. DeepSeek-R1-Distill-Qwen-14B) without disturbing the 8B setup.
    "model_name":      os.environ.get("WAVE_MODEL_NAME", "Qwen/Qwen3-8B"),
    "pilot_dir":       Path(os.environ.get("WAVE_PILOT_DIR", "data/cot/pilot")),
    "eval_dir":        Path("data/cot/eval"),
    "output_dir":      Path(os.environ.get("WAVE_OUTPUT_DIR", "data/qwen_cot")),
    "best_dir":        Path(os.environ.get("WAVE_BEST_DIR", "data/qwen_cot_best")),

    "shapes":          ["shape1", "shape2", "shape3", "shape4",
                        "shape1_ts", "shape1_react", "shape_react_syn",
                        "shape1_ts_safe", "shape1_react_safe",
                        "shape1_verified", "shape1_verified_safe",
                        "shape1_r2vul_ml", "shape1_wave3_jsts",
                        "shape1_wave3_other", "shape1_cvefixes",
                        "shape1_cvefixpairs", "shape1_fixjs",
                        "shape1_r2vul_valtest", "shape1_sft",
                        "shape3_codeql"],   # + Wave 6 SFT + CodeQL verified cross-file
    # Effective sampling weight per shape. shape1 has ~4k records, the others
    # ~170-300. With weights [1,4,4,4] each minibatch sees roughly equal
    # representation despite the 14x raw imbalance. shape1_ts is now vuln-only;
    # its safe counterpart comes from shape1_ts_safe (and react likewise), so
    # together they restore the safe:vuln balance the FPR metric needs.
    # shape2 lowered 4.0->2.0: it has only ~88 unique snippets after dedup, so a
    # high weight would just memorize them. shape3/4 keep 4.0 (more diverse / small).
    "shape_weights":   {"shape1": 1.0, "shape2": 2.0, "shape3": 4.0, "shape4": 4.0,
                        "shape1_ts": 1.0, "shape1_react": 3.0, "shape_react_syn": 2.0,
                        "shape1_ts_safe": 1.5, "shape1_react_safe": 3.0,
                        "shape1_verified": 2.0, "shape1_verified_safe": 2.0,
                        "shape1_r2vul_ml": 1.0, "shape1_wave3_jsts": 2.0,
                        "shape1_wave3_other": 1.5,
                        "shape1_cvefixes": 1.0,
                        "shape1_cvefixpairs": 2.0, "shape1_fixjs": 1.0,
                        "shape1_r2vul_valtest": 1.0,
                        "shape1_sft": 0.5,
                        "shape3_codeql": 2.5},   # CodeQL verified cross-file: high value, fills the multi-hop gap

    # LoRA — attention-only to keep VRAM headroom on the 8B base. Add gate/up/
    # down_proj if you have memory to spare and want more capacity.
    "lora_r":          16,
    "lora_alpha":      32,
    "lora_dropout":    0.05,
    # Added MLP targets (gate/up/down) for more capacity — the attention-only v2
    # under-detected vulns (50% FNR). max_len reduced to 1664 to fit the extra
    # adapter params in 16GB (v2 peaked at 15.85/16GB attention-only).
    "lora_targets":    os.environ.get("WAVE_LORA_TARGETS",
                        "q_proj,k_proj,v_proj,o_proj,gate_proj,up_proj,down_proj").split(","),

    # Training
    "epochs":          int(os.environ.get("WAVE_EPOCHS", "3")),
    "batch_size":      1,
    "grad_accum":      16,        # effective batch = 16
    "lr":              2e-4,
    "max_len":         int(os.environ.get("WAVE_MAX_LEN", "1664")),  # 14B needs less (VRAM)
    "warmup_ratio":    0.03,
    "val_frac":        0.05,      # 5% of TRAIN split set aside for in-loop val
    "patience":        2,
    "seed":            42,
}

# Optional per-run override of shape sampling weights, e.g. v8 rebalance toward
# vuln recall: WAVE_SHAPE_WEIGHTS='{"shape1_ts":2.0,"shape1_verified_safe":1.5}'
# Merged onto the defaults so you only specify the shapes you change.
if os.environ.get("WAVE_SHAPE_WEIGHTS"):
    import json as _json
    _ov = _json.loads(os.environ["WAVE_SHAPE_WEIGHTS"])
    CONFIG["shape_weights"].update({k: float(v) for k, v in _ov.items()})
    log_msg = "  [config] shape_weights overridden: " + str(_ov)
    print(log_msg, flush=True)


def log(msg: str) -> None:
    print(msg, flush=True)


# ---- data loading ----

def _user_hash(rec: dict) -> str:
    msgs = rec.get("messages") or []
    if not msgs:
        return ""
    return hashlib.sha256(msgs[0].get("content", "").encode("utf-8")).hexdigest()


def _iter_jsonl(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def load_train_records() -> list[dict]:
    """Load pilot/*.jsonl, drop any record whose user content matches an eval
    record (by sha256). Tags each record with its `_shape` so the sampler can
    apply per-shape weights."""
    excluded = set()
    for shape in CONFIG["shapes"]:
        eval_path = CONFIG["eval_dir"] / f"{shape}.jsonl"
        if eval_path.exists():
            for rec in _iter_jsonl(eval_path):
                excluded.add(_user_hash(rec))
    log(f"Eval exclusion set: {len(excluded)} hashes")

    records = []
    per_shape: dict[str, int] = {}
    for shape in CONFIG["shapes"]:
        pilot_path = CONFIG["pilot_dir"] / f"{shape}.jsonl"
        if not pilot_path.exists():
            log(f"  WARN: {pilot_path} missing — skipped")
            continue
        kept = 0
        for rec in _iter_jsonl(pilot_path):
            if _user_hash(rec) in excluded:
                continue
            rec["_shape"] = shape
            records.append(rec)
            kept += 1
        per_shape[shape] = kept
        log(f"  {shape}: kept {kept} training records")
    log(f"Total training pool: {len(records)} records ({per_shape})")
    return records


# ---- dataset ----

class CoTDataset(Dataset):
    """Tokenizes (user, assistant) pairs with the chat template and masks loss
    on the user portion so the model only learns to *produce* the assistant
    response, not to predict the user prompt."""

    def __init__(self, records: list[dict], tokenizer, max_len: int):
        self.records = records
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, idx: int) -> dict:
        rec = self.records[idx]
        msgs = rec["messages"]
        user_msg = msgs[0]["content"]
        asst_msg = msgs[1]["content"]

        # Render with chat template; we need user-only and full versions so we
        # know where assistant tokens begin. enable_thinking is Qwen3-only — fall
        # back without it for other students (e.g. R1-Distill on Qwen2.5).
        def _tmpl(msgs, add_gen):
            try:
                return self.tokenizer.apply_chat_template(
                    msgs, tokenize=False, add_generation_prompt=add_gen, enable_thinking=True)
            except TypeError:
                return self.tokenizer.apply_chat_template(
                    msgs, tokenize=False, add_generation_prompt=add_gen)
        user_only_text = _tmpl([{"role": "user", "content": user_msg}], True)
        full_text = _tmpl([{"role": "user", "content": user_msg},
                           {"role": "assistant", "content": asst_msg}], False)

        # Dynamic padding: tokenize WITHOUT padding here; the collate_fn pads each
        # batch to its own longest sequence. With short records (shape2/3/ts/react
        # are ~400-700 tokens) this is ~2-4x faster than padding everything to 2048.
        full = self.tokenizer(full_text, truncation=True, max_length=self.max_len,
                              return_tensors="pt")
        user_ids = self.tokenizer(user_only_text, truncation=True,
                                  max_length=self.max_len, return_tensors="pt")["input_ids"]
        user_len = int(user_ids.shape[1])

        input_ids = full["input_ids"].squeeze(0)
        attention_mask = full["attention_mask"].squeeze(0)
        labels = input_ids.clone()
        # Mask user portion + padding -> loss only on assistant tokens
        labels[:user_len] = -100
        labels[attention_mask == 0] = -100

        return {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "labels": labels,
        }


def make_collate_fn(pad_token_id: int):
    """Pad a batch to its own longest sequence (dynamic padding). Padded
    positions get attention_mask=0 and labels=-100 (ignored in loss)."""
    def collate(batch: list[dict]) -> dict:
        maxlen = max(x["input_ids"].size(0) for x in batch)
        input_ids, attn, labels = [], [], []
        for x in batch:
            n = x["input_ids"].size(0)
            pad = maxlen - n
            input_ids.append(torch.cat([x["input_ids"], torch.full((pad,), pad_token_id, dtype=x["input_ids"].dtype)]))
            attn.append(torch.cat([x["attention_mask"], torch.zeros(pad, dtype=x["attention_mask"].dtype)]))
            labels.append(torch.cat([x["labels"], torch.full((pad,), -100, dtype=x["labels"].dtype)]))
        return {
            "input_ids": torch.stack(input_ids),
            "attention_mask": torch.stack(attn),
            "labels": torch.stack(labels),
        }
    return collate


# ---- model setup ----

def build_model_and_tokenizer():
    log(f"Loading tokenizer: {CONFIG['model_name']}")
    tokenizer = AutoTokenizer.from_pretrained(CONFIG["model_name"], trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    log(f"Loading {CONFIG['model_name']} in 4-bit nf4...")
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
        bnb_4bit_quant_type="nf4",
    )
    model = AutoModelForCausalLM.from_pretrained(
        CONFIG["model_name"],
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True,
    )
    model.config.use_cache = False

    log("Preparing model for k-bit training (gradient checkpointing on, non-reentrant)")
    model = prepare_model_for_kbit_training(
        model,
        use_gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
    )

    log(f"Adding LoRA adapters (r={CONFIG['lora_r']}, targets={CONFIG['lora_targets']})")
    lora = LoraConfig(
        r=CONFIG["lora_r"],
        lora_alpha=CONFIG["lora_alpha"],
        lora_dropout=CONFIG["lora_dropout"],
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=CONFIG["lora_targets"],
    )
    model = get_peft_model(model, lora)

    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total = sum(p.numel() for p in model.parameters())
    log(f"Trainable: {trainable:,} / {total:,} ({trainable/total*100:.2f}%)")
    return model, tokenizer


# ---- training ----

@torch.no_grad()
def evaluate(model, val_loader, device) -> float:
    model.eval()
    losses = []
    for batch in val_loader:
        input_ids = batch["input_ids"].to(device)
        attention_mask = batch["attention_mask"].to(device)
        labels = batch["labels"].to(device)
        out = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
        loss_val = out.loss.item()
        if not math.isnan(loss_val) and not math.isinf(loss_val):
            losses.append(loss_val)
    model.train()
    return sum(losses) / max(len(losses), 1) if losses else float("nan")


def _existing_checkpoint(d: Path) -> bool:
    """Treat a dir as 'occupied' if it has adapter files. An empty dir is fine."""
    if not d.exists():
        return False
    for marker in ("adapter_config.json", "adapter_model.safetensors", "adapter_model.bin"):
        if (d / marker).exists():
            return True
    return False


def main():
    random.seed(CONFIG["seed"])
    torch.manual_seed(CONFIG["seed"])
    device = "cuda" if torch.cuda.is_available() else "cpu"
    log(f"Device: {device}")

    # Safety net: refuse to clobber an existing checkpoint. Force the operator to
    # rename it (e.g., qwen_cot_best -> qwen_cot_v1_best) before training v2/v3.
    # Override with WAVE_OVERWRITE=1 when you genuinely want to overwrite.
    if os.environ.get("WAVE_OVERWRITE", "").lower() not in ("1", "true", "yes"):
        existing = [d for d in (CONFIG["best_dir"], CONFIG["output_dir"]) if _existing_checkpoint(d)]
        if existing:
            log("\nABORT: existing checkpoint(s) found — refusing to overwrite.")
            for d in existing:
                log(f"  {d}")
            log("\nRename the directory before re-training, e.g.:")
            log(f"  Move-Item {CONFIG['best_dir']} {CONFIG['best_dir'].parent / (CONFIG['best_dir'].name + '_vN')}")
            log(f"  Move-Item {CONFIG['output_dir']} {CONFIG['output_dir'].parent / (CONFIG['output_dir'].name + '_vN')}")
            log("\nOr force overwrite with: $env:WAVE_OVERWRITE = '1'")
            raise SystemExit(2)

    CONFIG["output_dir"].mkdir(parents=True, exist_ok=True)
    CONFIG["best_dir"].mkdir(parents=True, exist_ok=True)

    records = load_train_records()
    if not records:
        raise SystemExit("No training records loaded — check pilot/eval dirs.")

    random.shuffle(records)
    val_size = max(1, int(len(records) * CONFIG["val_frac"]))
    val_records = records[:val_size]
    train_records = records[val_size:]
    log(f"In-loop split: train={len(train_records)}  val={len(val_records)}")

    model, tokenizer = build_model_and_tokenizer()

    train_ds = CoTDataset(train_records, tokenizer, CONFIG["max_len"])
    val_ds = CoTDataset(val_records, tokenizer, CONFIG["max_len"])

    # Weighted sampler — each training record's draw probability ~= shape weight
    weights = [CONFIG["shape_weights"][r["_shape"]] for r in train_records]
    sampler = WeightedRandomSampler(weights, num_samples=len(train_records), replacement=True)
    collate_fn = make_collate_fn(tokenizer.pad_token_id)
    train_loader = DataLoader(train_ds, batch_size=CONFIG["batch_size"], sampler=sampler, collate_fn=collate_fn)
    val_loader = DataLoader(val_ds, batch_size=CONFIG["batch_size"], shuffle=False, collate_fn=collate_fn)
    log(f"Train batches: {len(train_loader)}  Val batches: {len(val_loader)}")

    optimizer = torch.optim.AdamW(
        [p for p in model.parameters() if p.requires_grad],
        lr=CONFIG["lr"], weight_decay=0.01,
    )

    total_optim_steps = (len(train_loader) * CONFIG["epochs"]) // CONFIG["grad_accum"]
    warmup_steps = int(total_optim_steps * CONFIG["warmup_ratio"])
    log(f"Total optimizer steps: {total_optim_steps}  Warmup: {warmup_steps}")

    def get_lr(step: int) -> float:
        if step < warmup_steps:
            return CONFIG["lr"] * (step + 1) / max(1, warmup_steps)
        progress = (step - warmup_steps) / max(1, total_optim_steps - warmup_steps)
        return CONFIG["lr"] * 0.5 * (1 + math.cos(math.pi * progress))

    best_val_loss = float("inf")
    patience = 0
    global_step = 0
    nan_streak = 0          # consecutive batches with NaN/inf loss
    NAN_ABORT_THRESHOLD = 5  # abort if 5 in a row -> something is fundamentally broken
    model.train()

    for epoch in range(CONFIG["epochs"]):
        epoch_start = time.time()
        running_loss = 0.0
        running_count = 0
        optimizer.zero_grad(set_to_none=True)

        for i, batch in enumerate(train_loader):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            # No autocast wrapper: bnb_4bit_compute_dtype=bf16 already handles
            # dtype inside the model. Stacking autocast on top of QLoRA +
            # gradient checkpointing produces NaN gradients on bf16.
            out = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
            loss = out.loss / CONFIG["grad_accum"]
            loss_val = loss.item() * CONFIG["grad_accum"]

            if math.isnan(loss_val) or math.isinf(loss_val):
                nan_streak += 1
                log(f"  WARN: NaN/inf loss at batch {i} (streak={nan_streak})")
                if nan_streak >= NAN_ABORT_THRESHOLD:
                    log(f"\nABORT: loss has been NaN/inf for {nan_streak} batches. "
                        f"Something is fundamentally wrong — stopping to save your time.")
                    raise SystemExit(1)
                # Skip backward/optimizer step on bad loss
                optimizer.zero_grad(set_to_none=True)
                continue
            nan_streak = 0

            loss.backward()
            running_loss += loss_val
            running_count += 1

            if (i + 1) % CONFIG["grad_accum"] == 0:
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                optimizer.zero_grad(set_to_none=True)
                global_step += 1
                lr = get_lr(global_step)
                for g in optimizer.param_groups:
                    g["lr"] = lr
                if global_step % 25 == 0:
                    avg = running_loss / max(running_count, 1)
                    log(f"  step {global_step:>5}/{total_optim_steps}  train_loss={avg:.4f}  lr={lr:.2e}")

        avg_train = running_loss / max(running_count, 1)
        val_loss = evaluate(model, val_loader, device)
        elapsed = time.time() - epoch_start
        log(f"Epoch {epoch+1}/{CONFIG['epochs']}  train={avg_train:.4f}  val={val_loss:.4f}  "
            f"time={elapsed:.0f}s")

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience = 0
            model.save_pretrained(CONFIG["best_dir"])
            tokenizer.save_pretrained(CONFIG["best_dir"])
            log(f"  -> new best (val={val_loss:.4f}), saved to {CONFIG['best_dir']}")
        else:
            patience += 1
            log(f"  -> no improvement ({patience}/{CONFIG['patience']})")
            if patience >= CONFIG["patience"]:
                log("Early stopping.")
                break

    model.save_pretrained(CONFIG["output_dir"])
    tokenizer.save_pretrained(CONFIG["output_dir"])
    log(f"\nTraining complete.")
    log(f"Best (val={best_val_loss:.4f}): {CONFIG['best_dir']}")
    log(f"Final epoch:                  {CONFIG['output_dir']}")


if __name__ == "__main__":
    main()
