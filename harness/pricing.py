"""List-price cost of an agent run, computed from the token classes the CLI reported.

The Claude CLI prices its own runs (``total_cost_usd``, cost basis "list"). The Codex CLI
reports tokens but no price, so a Codex run's cost is derived here from OpenAI's published
API list prices. Both figures are therefore list-price estimates, not what a subscription
was billed, and the paper should say so.

Codex ``usage`` semantics (``turn.completed``): ``input_tokens`` INCLUDES the cached share
(``cached_input_tokens``), ``output_tokens`` INCLUDES ``reasoning_output_tokens``. Cache
writes (``cache_write_input_tokens``) are billed at 1.25x the uncached input rate for
gpt-5.6 and later, and are otherwise part of ordinary input.

Prices are USD per 1M tokens from https://developers.openai.com/api/docs/pricing, read
2026-09-22 (gpt-5.6-sol is marked promotional there). Pin the date when quoting them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

PRICES_READ_ON = "2026-09-22"
PRICES_SOURCE = "https://developers.openai.com/api/docs/pricing"


@dataclass(frozen=True)
class Rates:
    input: float          # uncached input, $/1M
    cached_input: float   # cache read, $/1M
    output: float         # output incl. reasoning, $/1M
    cache_write_multiplier: float = 1.0   # x input rate for cache writes


OPENAI_RATES: dict[str, Rates] = {
    "gpt-5.5": Rates(5.00, 0.50, 30.00),
    "gpt-5.5-pro": Rates(30.00, 0.00, 180.00),
    "gpt-5.6-sol": Rates(4.00, 0.50, 20.00, 1.25),
    "gpt-5.6-terra": Rates(2.00, 0.20, 12.00, 1.25),
    "gpt-5.6-luna": Rates(0.20, 0.02, 1.20, 1.25),
}


def rates_for(model: str | None) -> Rates | None:
    """Rates for a model id, tolerating a date suffix (``gpt-5.5-2026-06-01``)."""
    if not model:
        return None
    name = model.lower()
    if name in OPENAI_RATES:
        return OPENAI_RATES[name]
    for known in sorted(OPENAI_RATES, key=len, reverse=True):
        if name.startswith(known + "-"):
            return OPENAI_RATES[known]
    return None


def _n(usage: Mapping[str, Any], key: str) -> int:
    value = usage.get(key)
    return int(value) if isinstance(value, (int, float)) else 0


def codex_cost_usd(model: str | None, usage: Mapping[str, Any] | None) -> float | None:
    """List-price cost of a Codex run from its final ``usage`` block; None when the model
    has no known rate or the block is empty."""
    rates = rates_for(model)
    if rates is None or not usage:
        return None
    total_input = _n(usage, "input_tokens")
    cached = min(_n(usage, "cached_input_tokens"), total_input)
    cache_write = min(_n(usage, "cache_write_input_tokens"), total_input - cached)
    uncached = total_input - cached - cache_write
    output = _n(usage, "output_tokens")
    if total_input == 0 and output == 0:
        return None
    dollars = (uncached * rates.input
               + cached * rates.cached_input
               + cache_write * rates.input * rates.cache_write_multiplier
               + output * rates.output) / 1_000_000
    return round(dollars, 6)


def agent_cost_usd(agent: Mapping[str, Any] | None) -> float | None:
    """The cost of a stored run's ``agent`` block: the CLI's own figure when it gave one,
    else a list-price estimate from the tokens (Codex). Reads runs recorded before the
    estimate was stored at run time."""
    if not agent:
        return None
    cost = agent.get("cost_usd")
    if isinstance(cost, (int, float)):
        return float(cost)
    if agent.get("provider") == "codex":
        return codex_cost_usd(agent.get("model") or agent.get("requested_model"), agent.get("usage"))
    return None
