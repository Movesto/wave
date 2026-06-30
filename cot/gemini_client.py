# ============================================================
# cot/gemini_client.py
#
# Gemini trace generator — drop-in for cot/client.py (anthropic) and
# cot/local_client.py (gpt-oss). Same call_generator(prompt, system)
# -> {text, input_tokens, output_tokens} contract, so it slots behind
# the existing oracle + gates as a stronger (frontier) teacher.
#
# Backend select:  WAVE_GENERATOR_BACKEND=gemini
# Model:           WAVE_GEMINI_MODEL  (default gemini-2.5-flash — ~10x
#                  cheaper than Pro, fast, strong enough with our gates)
# Key:             GEMINI_API_KEY or GOOGLE_API_KEY, or a local file
#                  .gemini_key in the repo root.
# ============================================================
import os
import time
from pathlib import Path
from typing import Optional

MODEL = os.environ.get("WAVE_GEMINI_MODEL", "gemini-2.5-flash")
TEMPERATURE = float(os.environ.get("WAVE_GEMINI_TEMP", "0.3"))
MAX_TOKENS = int(os.environ.get("WAVE_GEMINI_MAX_TOKENS", "2048"))

_client = None


def _api_key() -> Optional[str]:
    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if key:
        return key.strip()
    f = Path(__file__).resolve().parent.parent / ".gemini_key"
    if f.exists():
        return f.read_text(encoding="utf-8").strip()
    return None


def _get_client():
    global _client
    if _client is None:
        from google import genai
        key = _api_key()
        if not key:
            raise RuntimeError(
                "Gemini key not found. Set GEMINI_API_KEY, or put the key in a "
                "file named .gemini_key in the repo root."
            )
        _client = genai.Client(api_key=key)
    return _client


def call_generator(prompt: str, system: Optional[str] = None, **kwargs) -> dict:
    from google.genai import types
    client = _get_client()
    config = types.GenerateContentConfig(
        system_instruction=system,
        temperature=TEMPERATURE,
        max_output_tokens=MAX_TOKENS,
    )
    last_err = None
    for attempt in range(6):
        try:
            resp = client.models.generate_content(model=MODEL, contents=prompt, config=config)
            text = resp.text or ""
            um = getattr(resp, "usage_metadata", None)
            return {
                "text": text,
                "input_tokens": int(getattr(um, "prompt_token_count", 0) or 0),
                "output_tokens": int(getattr(um, "candidates_token_count", 0) or 0),
            }
        except Exception as e:
            last_err = e
            msg = str(e).lower()
            # backoff on rate limit / transient; fail fast on auth/bad-request
            if "api key" in msg or "permission" in msg or "invalid" in msg and "argument" in msg:
                raise
            time.sleep(min(2 ** attempt, 30))
    raise RuntimeError(f"Gemini call failed after retries: {last_err}")
