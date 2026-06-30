# ============================================================
# eval/inference.py
#
# Predictor interface + three implementations:
# 1) GoldStubPredictor — returns the training assistant text;
#    a harness sanity check (must score ~100% on Layer 1).
# 2) PerturbedStubPredictor — flips a fraction of verdicts;
#    a metric-sensitivity sanity check.
# 3) QwenLoraPredictor — real inference (Qwen3-8B + LoRA).
#    Imports torch/transformers/peft lazily so the rest of the
#    harness runs without them installed.
# ============================================================
import random
from typing import Protocol

from .config import (
    BASE_MODEL,
    ADAPTER_PATH,
    GEN_TEMPERATURE,
    GEN_SEED,
    GEN_MAX_NEW_TOKENS,
    ENABLE_THINKING,
)


class Predictor(Protocol):
    name: str

    def predict(self, user_prompt: str) -> str: ...


# -----------------------------
# Stub: returns the gold answer
# -----------------------------

class GoldStubPredictor:
    """Echoes the eval record's assistant text. Lets us validate the harness
    end-to-end (parsers, scorers, slicers, report) without a trained model.
    A perfect run on this stub means the harness is correctly wired up."""

    name = "gold_stub"

    def __init__(self, eval_records_by_shape: dict[str, list[dict]]):
        self._lookup: dict[str, str] = {}
        for records in eval_records_by_shape.values():
            for r in records:
                msgs = r.get("messages", [])
                if len(msgs) < 2:
                    continue
                self._lookup[msgs[0]["content"]] = msgs[1]["content"]

    def predict(self, user_prompt: str) -> str:
        # If not in lookup, return malformed text so it's recorded as a parse miss.
        return self._lookup.get(user_prompt, "")


# -----------------------------
# Stub: flip a fraction of verdicts to test scoring sensitivity
# -----------------------------

class PerturbedStubPredictor:
    """Gold answer with `flip_rate` fraction of confirmed↔safe swaps. Used to
    sanity-check that scoring detects deltas — the perturbed run should land
    measurably below the gold run."""

    name = "perturbed_stub"

    def __init__(self, eval_records_by_shape: dict[str, list[dict]], flip_rate: float = 0.2, seed: int = 0):
        rng = random.Random(seed)
        self._lookup: dict[str, str] = {}
        for records in eval_records_by_shape.values():
            for r in records:
                msgs = r.get("messages", [])
                if len(msgs) < 2:
                    continue
                asst = msgs[1]["content"]
                if rng.random() < flip_rate:
                    if "status: confirmed" in asst:
                        asst = asst.replace("status: confirmed", "status: safe")
                    elif "status: safe" in asst:
                        asst = asst.replace("status: safe", "status: confirmed")
                self._lookup[msgs[0]["content"]] = asst
        self.flip_rate = flip_rate

    def predict(self, user_prompt: str) -> str:
        return self._lookup.get(user_prompt, "")


# -----------------------------
# Real: Qwen3-8B + LoRA
# -----------------------------

class QwenLoraPredictor:
    """Real inference. Requires `transformers`, `peft`, `bitsandbytes`, and `torch`
    installed and a CUDA GPU. Loads the base in 4-bit nf4 (same quant as training)
    so the 8B model fits in ~5 GB VRAM and there is no CPU offload — inference is
    5-10x faster than the bf16 fallback."""

    name = "qwen_lora"

    def __init__(self, base_model: str = BASE_MODEL, adapter_path: str | None = ADAPTER_PATH):
        # Import lazily so harness importable without ML deps.
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        from peft import PeftModel

        self.tokenizer = AutoTokenizer.from_pretrained(base_model)

        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4",
        )
        base = AutoModelForCausalLM.from_pretrained(
            base_model,
            quantization_config=bnb_config,
            device_map="auto",
        )
        if adapter_path:
            self.model = PeftModel.from_pretrained(base, adapter_path)
        else:
            self.model = base
        self.model.eval()

    def predict(self, user_prompt: str) -> str:
        import torch
        messages = [{"role": "user", "content": user_prompt}]
        # Qwen3 chat template supports enable_thinking
        try:
            prompt = self.tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
                enable_thinking=ENABLE_THINKING,
            )
        except TypeError:
            # older tokenizers
            prompt = self.tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)
        torch.manual_seed(GEN_SEED)
        with torch.no_grad():
            out = self.model.generate(
                **inputs,
                max_new_tokens=GEN_MAX_NEW_TOKENS,
                temperature=GEN_TEMPERATURE,
                do_sample=False,
                pad_token_id=self.tokenizer.eos_token_id,
            )
        text = self.tokenizer.decode(
            out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True
        )
        # Repair verbose-case field degradation (run-on trace, echoed fix,
        # unverifiable CVE citations). No-op on already-clean / non-shape1 output.
        try:
            from cot.postprocess import clean_scan_output
            text = clean_scan_output(text)
        except Exception:
            pass
        return text
