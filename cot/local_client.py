# ============================================================
# cot/local_client.py
#
# Local-model trace generator. Drop-in replacement for the
# Anthropic API client at cot/client.py with the same
# call_generator(prompt, system=None) signature.
#
# Defaults to openai/gpt-oss-20b — the teacher model actually used
# to generate the CoT pilot data. Override via env var WAVE_LOCAL_MODEL
# to point at any HF repo / local snapshot, e.g.:
#   $env:WAVE_LOCAL_MODEL = "Qwen/Qwen3-8B"
#   $env:WAVE_LOCAL_MODEL = "C:\models\qwen3.5-9b"
#
# Designed for a 16 GB VRAM card (RTX 5060 Ti): loads in 4-bit
# with bitsandbytes by default. Set WAVE_LOCAL_DTYPE=fp16 to
# force half-precision (fits ~7B at fp16, tight at 8B).
# ============================================================
import os
import re
import time
from typing import Optional


# ---- config ----
LOCAL_MODEL_NAME = os.environ.get("WAVE_LOCAL_MODEL", "openai/gpt-oss-20b")
LOCAL_DTYPE      = os.environ.get("WAVE_LOCAL_DTYPE", "4bit")  # "4bit" | "8bit" | "fp16"
LOCAL_MAX_TOKENS = int(os.environ.get("WAVE_LOCAL_MAX_TOKENS", "2048"))
LOCAL_TEMPERATURE = float(os.environ.get("WAVE_LOCAL_TEMPERATURE", "0.2"))
LOCAL_TOP_P       = float(os.environ.get("WAVE_LOCAL_TOP_P", "0.9"))
LOCAL_SEED        = int(os.environ.get("WAVE_LOCAL_SEED", "42"))
LOCAL_ENABLE_THINKING = os.environ.get("WAVE_LOCAL_THINK", "false").lower() in {"1", "true", "yes"}


# ---- lazy globals ----
_tokenizer = None
_model = None


def _load_model():
    """Lazy-load the model + tokenizer on first call_generator(). Cached after."""
    global _tokenizer, _model
    if _model is not None:
        return _tokenizer, _model

    print(f"[local_client] Loading {LOCAL_MODEL_NAME} ({LOCAL_DTYPE})...", flush=True)
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from pathlib import Path

    # Offload spill location for big models that don't fully fit in VRAM.
    # gpt-oss-20b's mxfp4 quantization keeps attention layers in bf16, so loading
    # peaks above the steady-state footprint; this lets transformers handle it.
    offload_dir = Path(os.environ.get("WAVE_LOCAL_OFFLOAD", "data/.offload"))
    offload_dir.mkdir(parents=True, exist_ok=True)

    kwargs: dict = {
        "device_map": "auto",
        "offload_folder": str(offload_dir),
        "offload_state_dict": True,
    }

    if LOCAL_DTYPE == "native":
        # Use whatever quantization/dtype the model ships with. Required for
        # gpt-oss (already mxfp4-quantized) and any other pre-quantized snapshot.
        pass
    elif LOCAL_DTYPE == "4bit":
        from transformers import BitsAndBytesConfig
        kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4",
        )
    elif LOCAL_DTYPE == "8bit":
        from transformers import BitsAndBytesConfig
        kwargs["quantization_config"] = BitsAndBytesConfig(load_in_8bit=True)
    elif LOCAL_DTYPE == "fp16":
        kwargs["torch_dtype"] = torch.float16
    elif LOCAL_DTYPE == "bf16":
        kwargs["torch_dtype"] = torch.bfloat16
    else:
        raise ValueError(f"Unknown WAVE_LOCAL_DTYPE: {LOCAL_DTYPE}")

    _tokenizer = AutoTokenizer.from_pretrained(LOCAL_MODEL_NAME, trust_remote_code=True)
    _model = AutoModelForCausalLM.from_pretrained(
        LOCAL_MODEL_NAME,
        trust_remote_code=True,
        **kwargs,
    )
    _model.eval()

    if _tokenizer.pad_token_id is None:
        _tokenizer.pad_token_id = _tokenizer.eos_token_id

    print(f"[local_client] Ready. Device map: {_model.hf_device_map if hasattr(_model, 'hf_device_map') else 'default'}", flush=True)
    return _tokenizer, _model


def _build_prompt(tokenizer, system: Optional[str], user: str) -> str:
    """Apply the model's chat template.

    For gpt-oss specifically, we prepend "Reasoning: low" to the system message
    so the model goes straight to the structured response instead of producing
    multi-thousand-token analysis-channel rumination. Override via
    WAVE_REASONING_EFFORT={low,medium,high}; default = low for short answers.
    """
    messages = []

    effort = os.environ.get("WAVE_REASONING_EFFORT", "low").lower()
    is_gpt_oss = "gpt-oss" in LOCAL_MODEL_NAME.lower()

    if system and is_gpt_oss:
        system = f"Reasoning: {effort}\n\n{system}"
    elif is_gpt_oss:
        system = f"Reasoning: {effort}"

    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": user})

    try:
        return tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
            enable_thinking=LOCAL_ENABLE_THINKING,
        )
    except TypeError:
        # Older tokenizers don't accept enable_thinking
        return tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
        )


def _strip_thinking_artifacts(text: str) -> str:
    """Normalize model output:
    - Qwen3 thinking-mode templates use <thinking> instead of <think>; rename.
    - gpt-oss Harmony channels (skip_special_tokens=True leaves bare channel
      names): "analysis...assistantfinal..." — strip preamble up to and
      including 'assistantfinal' so only the final channel's content survives.
    - Stray leading 'final' or 'analysis' tokens that survive other paths.
    """
    # gpt-oss Harmony: strip everything up to (and including) 'assistantfinal'
    m = re.search(r"\bassistantfinal\b", text)
    if m:
        text = text[m.end():].lstrip()
    # gpt-oss alt: text just starts with 'final' (no analysis channel emitted)
    text = re.sub(r"^\s*final\s+", "", text)
    # gpt-oss alt: text starts with 'analysis' but no terminator — unusual but possible
    text = re.sub(r"^\s*analysis\s+", "", text)
    # Qwen3 thinking mode -> our convention
    text = re.sub(r"<thinking>", "<think>", text, flags=re.IGNORECASE)
    text = re.sub(r"</thinking>", "</think>", text, flags=re.IGNORECASE)
    return text


def call_generator(
    prompt: str,
    system: Optional[str] = None,
    max_tokens: int = LOCAL_MAX_TOKENS,
    temperature: float = LOCAL_TEMPERATURE,
) -> dict:
    """Drop-in replacement for cot.client.call_generator. Returns the same shape:
    {"text", "input_tokens", "output_tokens"}.

    Raises on hard load failures; returns a malformed response on generation
    errors (lets the verifier reject downstream)."""
    import torch

    tokenizer, model = _load_model()

    chat_prompt = _build_prompt(tokenizer, system, prompt)
    inputs = tokenizer(chat_prompt, return_tensors="pt", truncation=True, max_length=8192)
    input_ids = inputs["input_ids"].to(model.device)
    attention_mask = inputs["attention_mask"].to(model.device)
    input_token_count = int(input_ids.shape[1])

    gen_kwargs = {
        "max_new_tokens": max_tokens,
        "pad_token_id":   tokenizer.pad_token_id,
        "eos_token_id":   tokenizer.eos_token_id,
    }
    if temperature > 0:
        gen_kwargs.update({
            "do_sample":   True,
            "temperature": temperature,
            "top_p":       LOCAL_TOP_P,
        })
    else:
        gen_kwargs["do_sample"] = False

    torch.manual_seed(LOCAL_SEED)
    with torch.no_grad():
        out = model.generate(input_ids=input_ids, attention_mask=attention_mask, **gen_kwargs)

    out_tokens = out[0][input_token_count:]
    text = tokenizer.decode(out_tokens, skip_special_tokens=True)
    text = _strip_thinking_artifacts(text)

    return {
        "text": text,
        "input_tokens":  input_token_count,
        "output_tokens": int(out_tokens.shape[0]),
    }
