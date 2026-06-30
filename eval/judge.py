# ============================================================
# eval/judge.py
#
# Layer-2 LLM-judge. Pinned model + prompt + temp 0 so the
# judge does not drift between runs. Returns 1-5 scores for:
#   - fix_quality (Shape 1/3): does the fix remediate?
#   - reasoning_faithfulness (Shape 1/3): does the <think>
#     logically arrive at the verdict, or restate the label?
#   - synthesis quality (Shape 4): dedup + ranking + insight,
#     no hallucinated findings.
#
# Skip-safe: if ANTHROPIC_API_KEY is not set, judge() returns
# None and Layer 1 metrics still produce a complete report.
# ============================================================
import json
import os
import time
import random
from typing import Optional

from .config import JUDGE_MODEL, JUDGE_TEMPERATURE, JUDGE_MAX_TOKENS, JUDGE_VERSION


# Lazy client
_client = None


def _client_once():
    global _client
    if _client is None:
        from anthropic import Anthropic
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("ANTHROPIC_API_KEY not set; judge unavailable")
        _client = Anthropic()
    return _client


SYSTEM_PROMPT = (
    "You are a strict, calibrated evaluator scoring the quality of a security scanner's "
    "output. Score each rubric on an integer 1-5 scale. Return ONLY a JSON object with the "
    "requested keys — no prose, no markdown fences. Lower is worse."
)


SHAPE1_3_TEMPLATE = """Evaluate this security scan trace.

INPUT CODE:
```
{code}
```

GROUND TRUTH: label={gt_label}, primary_cwe={gt_cwe}

MODEL OUTPUT (<think> + structured verdict):
```
{model_output}
```

Score on 1-5 each:
- fix_quality: does the proposed fix actually remediate the vulnerability (or is the "no fix needed" stance appropriate for safe code), in the right language?
- reasoning_faithfulness: does the <think> block logically arrive at the stated verdict by tracing the code, or is it reasoning-theater that just restates the label without genuine analysis?

Return JSON: {{"fix_quality": int, "reasoning_faithfulness": int, "note": "<one sentence>"}}
"""


SHAPE4_TEMPLATE = """Evaluate this whole-project security synthesis.

INPUT (project map + findings list):
```
{user_input}
```

MODEL OUTPUT:
```
{model_output}
```

Score on 1-5 each:
- dedup_clustering: did the model correctly cluster duplicate findings across paired files?
- severity_ranking: is the ranked order sensible given exploitation cost/blast radius?
- systemic_insight: does the systemic_observations section name a real pattern (not generic boilerplate)?
- hallucination_freedom: 5 = no invented findings; 1 = ranked entries that aren't in the input.

Return JSON: {{"dedup_clustering": int, "severity_ranking": int, "systemic_insight": int, "hallucination_freedom": int, "note": "<one sentence>"}}
"""


def _call_judge(user_prompt: str) -> Optional[dict]:
    try:
        client = _client_once()
    except RuntimeError:
        return None

    delay = 2.0
    for _ in range(5):
        try:
            resp = client.messages.create(
                model=JUDGE_MODEL,
                max_tokens=JUDGE_MAX_TOKENS,
                temperature=JUDGE_TEMPERATURE,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )
            text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
            # Pull the first JSON object out of the text
            start = text.find("{")
            end = text.rfind("}")
            if start < 0 or end <= start:
                return None
            return json.loads(text[start:end + 1])
        except Exception:
            time.sleep(delay + random.uniform(0, 1))
            delay *= 2
    return None


def judge_shape1_3(code: str, gt_label: str, gt_cwe: Optional[str], model_output: str) -> Optional[dict]:
    return _call_judge(SHAPE1_3_TEMPLATE.format(
        code=code[:2500],
        gt_label=gt_label or "unknown",
        gt_cwe=gt_cwe or "none",
        model_output=model_output[:3000],
    ))


def judge_shape4(user_input: str, model_output: str) -> Optional[dict]:
    return _call_judge(SHAPE4_TEMPLATE.format(
        user_input=user_input[:2500],
        model_output=model_output[:3000],
    ))


def judge_version() -> str:
    return JUDGE_VERSION
