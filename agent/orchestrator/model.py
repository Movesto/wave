"""14B translate-only interface + resource governor.

The model TRANSLATES (patch, auth script, payload refinement); deterministic tools PROVE. Loaded
lazily, 4-bit, and unloadable (governor: don't keep it co-resident with a heavy sandbox when VRAM
is tight). Reuses the load recipe verified in the Juliet spike. Env WAVE_MODEL overrides the id.
"""
import os
import re

_DEFAULT = "deepseek-ai/DeepSeek-R1-Distill-Qwen-14B"


def code_block(text):
    """Extract code from a model reply: a FENCED block, preferring one after </think>.
    Fenced-only on purpose: a reasoning model rambles, and a loose raw-code fallback grabs prose
    ("function step by step...") which then gets written into the source. No fence -> no patch."""
    after = (text or "").split("</think>")[-1]
    for chunk in (after, text or ""):
        blocks = re.findall(r"```(?:[\w+-]*)\s*(.*?)```", chunk, re.S)
        if blocks:
            return blocks[-1].strip()          # the last fenced block = the final answer
    return None


class Model:
    def __init__(self, model_id=None, max_new_tokens=1500):
        self.model_id = model_id or os.environ.get("WAVE_MODEL", _DEFAULT)
        self.max_new_tokens = max_new_tokens
        self._tok = None
        self._model = None

    def _load(self):
        if self._model is not None:
            return
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        print(f"[model] loading {self.model_id} (4-bit)...", flush=True)
        bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                 bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
        self._tok = AutoTokenizer.from_pretrained(self.model_id)
        self._model = AutoModelForCausalLM.from_pretrained(
            self.model_id, quantization_config=bnb, device_map="cuda", low_cpu_mem_usage=True)
        self._model.eval()
        print("[model] loaded", flush=True)

    def generate(self, system, user, max_new_tokens=None, temperature=0.4):
        self._load()
        import torch
        msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        inputs = self._tok.apply_chat_template(msgs, add_generation_prompt=True,
                                               return_tensors="pt", return_dict=True).to("cuda")
        plen = inputs["input_ids"].shape[1]
        with torch.no_grad():
            out = self._model.generate(**inputs, max_new_tokens=max_new_tokens or self.max_new_tokens,
                                       do_sample=True, temperature=temperature, top_p=0.95,
                                       pad_token_id=self._tok.eos_token_id)
        return self._tok.decode(out[0][plen:], skip_special_tokens=True)

    def unload(self):
        if self._model is None:
            return
        import torch, gc
        del self._model
        self._model = None
        gc.collect()
        torch.cuda.empty_cache()
        print("[model] unloaded", flush=True)
