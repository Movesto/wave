"""FullModelPredictor: load a full standalone HF model (e.g. Qwen/Qwen3.5-9B) and expose the
same .predict(prompt) -> str interface as eval.inference.QwenLoraPredictor, so the pipeline can
use a strong general reasoner for triage/discovery instead of a LoRA adapter on Qwen3-8B.

Qwen3.5-9B is multimodal (Qwen3_5ForConditionalGeneration), so loading falls back to the
image-text-to-text class + processor when the plain causal-LM load fails.
"""
import torch
from transformers import (AutoModelForCausalLM, AutoTokenizer, AutoProcessor,
                          BitsAndBytesConfig)


def _load(model_id, bnb):
    try:
        tok = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
        model = AutoModelForCausalLM.from_pretrained(
            model_id, quantization_config=bnb, device_map="auto",
            torch_dtype=torch.bfloat16, trust_remote_code=True)
        return model, tok
    except Exception:
        from transformers import AutoModelForImageTextToText
        proc = AutoProcessor.from_pretrained(model_id, trust_remote_code=True)
        model = AutoModelForImageTextToText.from_pretrained(
            model_id, quantization_config=bnb, device_map="auto",
            torch_dtype=torch.bfloat16, trust_remote_code=True)
        return model, proc


class FullModelPredictor:
    def __init__(self, model_id, max_new=2048):
        bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                 bnb_4bit_compute_dtype=torch.bfloat16)
        self.model, self.tok = _load(model_id, bnb)
        self.model.eval()
        self.dec = getattr(self.tok, "tokenizer", self.tok)
        self.eos = getattr(self.dec, "eos_token_id", None)
        self.max_new = max_new

    def predict(self, prompt, system=None, max_new=None):
        msgs = ([{"role": "system", "content": system}] if system else []) \
            + [{"role": "user", "content": prompt}]
        try:      # Qwen3 thinking models otherwise reason forever and never emit the answer
            text = self.tok.apply_chat_template(msgs, tokenize=False,
                                                add_generation_prompt=True, enable_thinking=False)
        except TypeError:
            text = self.tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
        try:
            ids = self.tok(text, return_tensors="pt").to(self.model.device)
        except Exception:
            ids = self.tok(text=text, return_tensors="pt").to(self.model.device)
        with torch.no_grad():
            out = self.model.generate(**ids, max_new_tokens=(max_new or self.max_new),
                                      do_sample=True, temperature=0.3, top_p=0.95,
                                      pad_token_id=self.eos)
        return self.dec.decode(out[0][ids["input_ids"].shape[1]:], skip_special_tokens=True)
