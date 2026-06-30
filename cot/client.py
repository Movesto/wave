# ============================================================
# cot/client.py
#
# Anthropic API wrapper with retry/backoff. Single entrypoint:
# call_generator(prompt, system=None) -> {"text", "usage"}.
# Handles 429 rate-limits and 5xx with exponential backoff.
# ============================================================
import time
import random
from typing import Optional

from anthropic import Anthropic, APIStatusError, APIConnectionError, RateLimitError

from .config import (
    GENERATOR_MODEL,
    GENERATOR_TEMPERATURE,
    GENERATOR_MAX_TOKENS,
    require_api_key,
)

_client: Optional[Anthropic] = None


def _client_once() -> Anthropic:
    global _client
    if _client is None:
        require_api_key()  # raises if missing
        _client = Anthropic()
    return _client


def call_generator(
    prompt: str,
    system: Optional[str] = None,
    max_tokens: int = GENERATOR_MAX_TOKENS,
    temperature: float = GENERATOR_TEMPERATURE,
    max_retries: int = 6,
) -> dict:
    """One Messages call with retry. Returns {"text", "input_tokens", "output_tokens"}."""
    client = _client_once()

    kwargs = {
        "model": GENERATOR_MODEL,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        kwargs["system"] = system

    delay = 2.0
    last_err = None
    for attempt in range(max_retries):
        try:
            resp = client.messages.create(**kwargs)
            text_blocks = [b.text for b in resp.content if getattr(b, "type", None) == "text"]
            text = "".join(text_blocks)
            return {
                "text": text,
                "input_tokens": resp.usage.input_tokens,
                "output_tokens": resp.usage.output_tokens,
            }
        except RateLimitError as e:
            last_err = e
            # Exponential backoff with jitter; respect Retry-After if present.
            sleep_for = delay + random.uniform(0, 1)
            retry_after = getattr(e.response, "headers", {}).get("retry-after") if hasattr(e, "response") else None
            if retry_after:
                try:
                    sleep_for = max(sleep_for, float(retry_after))
                except ValueError:
                    pass
            time.sleep(sleep_for)
            delay *= 2
        except APIConnectionError as e:
            last_err = e
            time.sleep(delay + random.uniform(0, 1))
            delay *= 2
        except APIStatusError as e:
            last_err = e
            # 5xx -> retry; 4xx (other than 429) -> raise
            if e.status_code >= 500:
                time.sleep(delay + random.uniform(0, 1))
                delay *= 2
            else:
                raise
    raise RuntimeError(f"call_generator exhausted {max_retries} retries; last error: {last_err}")
