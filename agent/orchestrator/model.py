"""14B translate-only interface + resource governor.

The model TRANSLATES (patch, auth script, payload refinement); deterministic tools PROVE. Loaded
lazily, 4-bit, and unloadable (governor: don't keep it co-resident with a heavy sandbox when VRAM
is tight). Reuses the load recipe verified in the Juliet spike. Env WAVE_MODEL overrides the id.
"""
import os
import re
from pathlib import Path

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
        # WAVE_NO_THINK=1 disables a Qwen3-family model's <think> phase (enable_thinking=False): the
        # reasoning never terminates into the reader's JSON within budget, so answer-only is the usable
        # mode -- the discrimination lives in the weights, not the visible chain. No-op for R1 etc.
        self.no_think = os.environ.get("WAVE_NO_THINK") == "1"
        self.adapter = os.environ.get("WAVE_ADAPTER")   # a trained LoRA adapter dir (base read from its config)
        # WAVE_API_BASE (e.g. http://localhost:11434/v1 for a local ollama server) -> talk to an
        # OpenAI-compatible endpoint instead of loading local weights. This is how we run a GGUF /
        # tool-calling model: the server owns native tool-calls; we just call the API. Local, no egress.
        self.api_base = os.environ.get("WAVE_API_BASE")
        self._tok = None
        self._model = None

    @property
    def supports_tools(self):
        """True when a native tool-calling backend is available (the API path)."""
        return bool(self.api_base)

    def _load(self):
        if self._model is not None:
            return
        import json as _json
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                 bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
        if self.adapter:
            # WAVE_ADAPTER: a trained LoRA adapter dir -> load its base (from adapter_config) 4-bit, then
            # stack the adapter. Tokenizer + chat template come from the adapter dir (the trained format).
            cfg = _json.loads((Path(self.adapter) / "adapter_config.json").read_text(encoding="utf-8"))
            base = cfg.get("base_model_name_or_path") or self.model_id
            print(f"[model] loading adapter {self.adapter} on {base} (4-bit)...", flush=True)
            from peft import PeftModel
            self._tok = AutoTokenizer.from_pretrained(self.adapter)
            b = AutoModelForCausalLM.from_pretrained(base, quantization_config=bnb, device_map="cuda",
                                                     low_cpu_mem_usage=True)
            self._model = PeftModel.from_pretrained(b, self.adapter)
        else:
            print(f"[model] loading {self.model_id} (4-bit)...", flush=True)
            self._tok = AutoTokenizer.from_pretrained(self.model_id)
            self._model = AutoModelForCausalLM.from_pretrained(
                self.model_id, quantization_config=bnb, device_map="cuda", low_cpu_mem_usage=True)
        self._model.eval()
        print("[model] loaded", flush=True)

    def _api_chat(self, messages, tools=None, temperature=0.2, max_tokens=None, timeout=300):
        """One call to the OpenAI-compatible endpoint -> the assistant message dict {content, tool_calls}."""
        import requests
        body = {"model": self.model_id, "messages": messages, "temperature": temperature, "stream": False}
        if tools:
            body["tools"] = tools
        if max_tokens:
            body["max_tokens"] = max_tokens
        r = requests.post(self.api_base.rstrip("/") + "/chat/completions",
                          headers={"Authorization": "Bearer local", "Content-Type": "application/json"},
                          json=body, timeout=timeout)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]

    def chat(self, messages, tools=None, temperature=0.2, max_tokens=None):
        """Native chat, optionally with tools -> the assistant message dict (content + tool_calls).
        Requires an API backend (WAVE_API_BASE); local transformers models use generate() instead."""
        if not self.api_base:
            raise RuntimeError("Model.chat(tools=...) needs an API backend -- set WAVE_API_BASE")
        return self._api_chat(messages, tools=tools, temperature=temperature, max_tokens=max_tokens)

    def generate(self, system, user, max_new_tokens=None, temperature=0.4):
        if self.api_base:                                   # API backend: no local weights, just call the endpoint
            msg = self._api_chat([{"role": "system", "content": system}, {"role": "user", "content": user}],
                                 temperature=temperature, max_tokens=max_new_tokens)
            return msg.get("content") or ""
        self._load()
        import torch
        msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        kw = {"enable_thinking": False} if self.no_think else {}
        try:
            inputs = self._tok.apply_chat_template(msgs, add_generation_prompt=True,
                                                   return_tensors="pt", return_dict=True, **kw).to("cuda")
        except TypeError:                                   # tokenizer doesn't accept enable_thinking
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
