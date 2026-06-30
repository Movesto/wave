# ============================================================
# cot/cost.py
#
# Up-front cost estimator. Used BEFORE a full run so we know
# what we're about to spend, per workflow instruction:
# "Estimate and print token/cost BEFORE any full run."
#
# Token counting is approximate (we don't ship a tokenizer for
# Claude). For a tighter estimate the SDK's count_tokens helper
# is available but slower; we keep this fast and intentionally
# slightly pessimistic.
# ============================================================
from dataclasses import dataclass
from .config import PRICING_USD_PER_MTOK, GENERATOR_MODEL


def approx_tokens(text: str) -> int:
    """Rough char->token estimate. Claude tokens average ~3.7 chars in English code.
    We use 4 for a slight overcount (better to overestimate cost than under)."""
    if not text:
        return 0
    return max(1, len(text) // 4)


@dataclass
class CostEstimate:
    model: str
    num_calls: int
    avg_input_tokens: int
    avg_output_tokens: int
    total_input_tokens: int
    total_output_tokens: int
    input_cost_usd: float
    output_cost_usd: float
    total_cost_usd: float

    def render(self) -> str:
        return (
            f"\n  COST ESTIMATE for {self.model}\n"
            f"  -------------------------------------\n"
            f"  calls:              {self.num_calls:,}\n"
            f"  avg input tokens:   {self.avg_input_tokens:,}\n"
            f"  avg output tokens:  {self.avg_output_tokens:,}\n"
            f"  total input:        {self.total_input_tokens:,} tokens\n"
            f"  total output:       {self.total_output_tokens:,} tokens\n"
            f"  input cost:         ${self.input_cost_usd:,.2f}\n"
            f"  output cost:        ${self.output_cost_usd:,.2f}\n"
            f"  ----------------------------------\n"
            f"  total estimated:    ${self.total_cost_usd:,.2f}\n"
        )


def estimate_cost(
    sample_prompts: list[str],
    num_calls: int,
    avg_output_tokens: int = 1500,
    model: str = GENERATOR_MODEL,
) -> CostEstimate:
    """Estimate cost given (a) representative prompt samples and (b) total call count.

    avg_output_tokens default 1500 = generous for <think>...</think> + structured
    verdict; tune per shape.
    """
    pricing = PRICING_USD_PER_MTOK.get(model)
    if pricing is None:
        raise ValueError(f"No pricing entry for model {model!r}. Update cot/config.py:PRICING_USD_PER_MTOK.")

    if not sample_prompts:
        avg_input = 1500  # default if no samples available yet
    else:
        avg_input = sum(approx_tokens(p) for p in sample_prompts) // len(sample_prompts)

    total_input = avg_input * num_calls
    total_output = avg_output_tokens * num_calls

    input_cost = total_input / 1_000_000 * pricing["input"]
    output_cost = total_output / 1_000_000 * pricing["output"]

    return CostEstimate(
        model=model,
        num_calls=num_calls,
        avg_input_tokens=avg_input,
        avg_output_tokens=avg_output_tokens,
        total_input_tokens=total_input,
        total_output_tokens=total_output,
        input_cost_usd=input_cost,
        output_cost_usd=output_cost,
        total_cost_usd=input_cost + output_cost,
    )
