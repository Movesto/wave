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
    def __init__(self, model_id=None, max_new_tokens=1500, api_base=None, api_key=None):
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
        # An explicit api_base/api_key (used for the cloud GLM "eyes" model) overrides the env; the local
        # ollama path passes neither and keeps the "Bearer local" placeholder. Detection stays local --
        # only comprehension is allowed to point at a remote endpoint.
        self.api_base = api_base or os.environ.get("WAVE_API_BASE")
        self.api_key = api_key or os.environ.get("WAVE_API_KEY")
        # ollama defaults to a 4096-token context (num_ctx); a code slice + a reasoning model's <think>
        # blows straight past it and the reply gets cut before the answer. Raise it for the LOCAL ollama
        # endpoint only -- OpenRouter/GLM rejects ollama's "options" field. WAVE_NUM_CTX overrides.
        self.num_ctx = int(os.environ.get("WAVE_NUM_CTX", "16384"))
        self._tok = None
        self._model = None

    @property
    def _is_local_api(self):
        return bool(self.api_base) and any(h in self.api_base for h in ("localhost", "127.0.0.1", ":11434"))

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

    def _api_chat(self, messages, tools=None, temperature=0.2, max_tokens=None, timeout=300, think=None,
                  json_mode=False):
        """One call to the OpenAI-compatible endpoint -> the assistant message dict {content, tool_calls}.
        Retries a couple times on a transient server error (ollama occasionally 500s under context load).
        think=False disables a reasoning model's <think> phase (ollama honors "think"). json_mode forces a
        valid-JSON reply (OpenAI response_format) -- the reliable way to get structured output out of a
        reasoning model: it emits the object directly instead of rambling past the token budget."""
        import time

        import requests
        body = {"model": self.model_id, "messages": messages, "temperature": temperature, "stream": False}
        if tools:
            body["tools"] = tools
        if max_tokens:
            body["max_tokens"] = max_tokens
        if think is not None:                               # ollama honors "think": the MTP model then
            body["think"] = think                           # reasons only briefly and emits the answer
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        if self.num_ctx and self._is_local_api:             # give the local model a real context window
            body["options"] = {"num_ctx": self.num_ctx}
        url = self.api_base.rstrip("/") + "/chat/completions"
        last = None
        for attempt in range(3):
            try:
                r = requests.post(url, headers={"Authorization": f"Bearer {self.api_key or 'local'}",
                                                "Content-Type": "application/json"}, json=body, timeout=timeout)
                r.raise_for_status()
                return r.json()["choices"][0]["message"]
            except Exception as e:                          # transient 500 / timeout / connection blip -> retry
                last = e
                time.sleep(2 * (attempt + 1))
        raise last

    def chat(self, messages, tools=None, temperature=0.2, max_tokens=None):
        """Native chat, optionally with tools -> the assistant message dict (content + tool_calls).
        Requires an API backend (WAVE_API_BASE); local transformers models use generate() instead."""
        if not self.api_base:
            raise RuntimeError("Model.chat(tools=...) needs an API backend -- set WAVE_API_BASE")
        return self._api_chat(messages, tools=tools, temperature=temperature, max_tokens=max_tokens)

    def _ollama_native(self, system, user, max_tokens=None, temperature=0.2, think=None, json_mode=False,
                       timeout=300):
        """Local ollama via the NATIVE /api/chat endpoint. The OpenAI-compat /v1 endpoint IGNORES
        options.num_ctx (silently capping context at 4096 -> a 400 on any prompt over ~4096 tokens); the
        native endpoint HONORS it. So all local text generate() goes here; tool-calling chat() stays on
        /v1. Maps max_tokens -> options.num_predict; json_mode -> format:"json"."""
        import time

        import requests
        root = self.api_base.rstrip("/")
        if root.endswith("/v1"):
            root = root[:-3]
        opts = {"num_ctx": self.num_ctx, "temperature": temperature}
        if max_tokens:
            opts["num_predict"] = max_tokens
        body = {"model": self.model_id, "stream": False, "options": opts,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        if think is not None:
            body["think"] = think
        if json_mode:
            body["format"] = "json"
        url = root.rstrip("/") + "/api/chat"
        last = None
        for attempt in range(3):
            try:
                r = requests.post(url, json=body, timeout=timeout)
                r.raise_for_status()
                m = r.json().get("message", {})
                return m.get("content") or m.get("thinking") or ""
            except Exception as e:
                last = e
                time.sleep(2 * (attempt + 1))
        raise last

    def generate(self, system, user, max_new_tokens=None, temperature=0.4, think=None, json_mode=False):
        if self._is_local_api:                              # local ollama -> native endpoint (num_ctx honored)
            return self._ollama_native(system, user, max_tokens=max_new_tokens, temperature=temperature,
                                       think=think, json_mode=json_mode)
        if self.api_base:                                   # cloud OpenAI-compat (GLM/OpenRouter)
            msg = self._api_chat([{"role": "system", "content": system}, {"role": "user", "content": user}],
                                 temperature=temperature, max_tokens=max_new_tokens, think=think,
                                 json_mode=json_mode)
            return msg.get("content") or msg.get("reasoning") or ""   # thinking-only reply -> salvage reasoning
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
