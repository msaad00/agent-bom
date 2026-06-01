"""Open cost model for LLM API spend attribution.

agent-bom extracts ``input_tokens`` / ``output_tokens`` from OpenTelemetry
GenAI spans (see :mod:`agent_bom.otel_ingest`). This module turns those token
counts into a USD cost estimate using a published, operator-tunable price
table — the open cost model itself is a differentiator: operators can see and
override every number rather than trusting an opaque vendor meter.

Prices are USD per 1,000,000 tokens, captured 2026-06-01 from public provider
pricing pages. They are deliberately conservative list prices, not negotiated
rates — override via :func:`load_price_overrides` (``AGENT_BOM_COST_MODEL_JSON``)
for committed-use or enterprise discounts.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

PRICE_TABLE_CAPTURED = "2026-06-01"


@dataclass(frozen=True)
class ModelPrice:
    """USD per 1,000,000 tokens for one model."""

    input_per_mtok: float
    output_per_mtok: float


# provider -> model-prefix -> price. Longest matching prefix wins so that
# "gpt-4o-mini" resolves before "gpt-4o". Keep keys lowercase.
_PRICES: dict[str, dict[str, ModelPrice]] = {
    "openai": {
        "gpt-4o-mini": ModelPrice(0.15, 0.60),
        "gpt-4o": ModelPrice(2.50, 10.00),
        "gpt-4.1-mini": ModelPrice(0.40, 1.60),
        "gpt-4.1": ModelPrice(2.00, 8.00),
        "gpt-4-turbo": ModelPrice(10.00, 30.00),
        "gpt-4": ModelPrice(30.00, 60.00),
        "gpt-3.5-turbo": ModelPrice(0.50, 1.50),
        "o3-mini": ModelPrice(1.10, 4.40),
        "o3": ModelPrice(2.00, 8.00),
        "o1": ModelPrice(15.00, 60.00),
        "text-embedding-3-small": ModelPrice(0.02, 0.0),
        "text-embedding-3-large": ModelPrice(0.13, 0.0),
    },
    "anthropic": {
        "claude-3-haiku": ModelPrice(0.25, 1.25),
        "claude-3-5-haiku": ModelPrice(0.80, 4.00),
        "claude-3-opus": ModelPrice(15.00, 75.00),
        "claude-3-5-sonnet": ModelPrice(3.00, 15.00),
        "claude-3-7-sonnet": ModelPrice(3.00, 15.00),
        "claude-sonnet-4": ModelPrice(3.00, 15.00),
        "claude-opus-4": ModelPrice(15.00, 75.00),
        "claude-haiku-4": ModelPrice(1.00, 5.00),
    },
    "vertex_ai": {
        "gemini-1.5-flash": ModelPrice(0.075, 0.30),
        "gemini-1.5-pro": ModelPrice(1.25, 5.00),
        "gemini-2.0-flash": ModelPrice(0.10, 0.40),
        "gemini-2.5-pro": ModelPrice(1.25, 10.00),
    },
    "google": {
        "gemini-1.5-flash": ModelPrice(0.075, 0.30),
        "gemini-1.5-pro": ModelPrice(1.25, 5.00),
        "gemini-2.0-flash": ModelPrice(0.10, 0.40),
        "gemini-2.5-pro": ModelPrice(1.25, 10.00),
    },
    "cohere": {
        "command-r-plus": ModelPrice(2.50, 10.00),
        "command-r": ModelPrice(0.15, 0.60),
        "command": ModelPrice(1.00, 2.00),
    },
    "mistral": {
        "mistral-large": ModelPrice(2.00, 6.00),
        "mistral-small": ModelPrice(0.20, 0.60),
        "open-mixtral": ModelPrice(0.70, 0.70),
    },
}

# Provider aliases that map to a canonical pricing namespace.
_PROVIDER_ALIASES = {
    "azure": "openai",
    "azure_openai": "openai",
    "openai_azure": "openai",
    "bedrock": "anthropic",  # most common Bedrock GenAI usage in this tool
    "aws_bedrock": "anthropic",
    "googleai": "google",
    "google_vertex": "vertex_ai",
    "vertexai": "vertex_ai",
}

_OVERRIDES: dict[str, dict[str, ModelPrice]] | None = None


def _normalize_provider(provider: str) -> str:
    p = (provider or "").strip().lower()
    return _PROVIDER_ALIASES.get(p, p)


def load_price_overrides() -> dict[str, dict[str, ModelPrice]]:
    """Load operator price overrides from ``AGENT_BOM_COST_MODEL_JSON``.

    JSON shape: ``{"provider": {"model-prefix": {"input_per_mtok": x,
    "output_per_mtok": y}}}``. Cached after first read; call
    :func:`reset_price_overrides` in tests to reload.
    """
    global _OVERRIDES
    if _OVERRIDES is not None:
        return _OVERRIDES
    raw = os.environ.get("AGENT_BOM_COST_MODEL_JSON", "").strip()
    parsed: dict[str, dict[str, ModelPrice]] = {}
    if raw:
        try:
            data = json.loads(raw)
            for provider, models in data.items():
                bucket: dict[str, ModelPrice] = {}
                for prefix, price in models.items():
                    bucket[prefix.lower()] = ModelPrice(
                        float(price.get("input_per_mtok", 0.0)),
                        float(price.get("output_per_mtok", 0.0)),
                    )
                parsed[_normalize_provider(provider)] = bucket
        except (ValueError, AttributeError, TypeError):
            parsed = {}
    _OVERRIDES = parsed
    return _OVERRIDES


def reset_price_overrides() -> None:
    """Clear the cached overrides (test hook)."""
    global _OVERRIDES
    _OVERRIDES = None


def lookup_price(provider: str, model: str) -> ModelPrice | None:
    """Return the price for the longest model-prefix match, overrides first."""
    canonical = _normalize_provider(provider)
    model_l = (model or "").strip().lower()
    if not model_l:
        return None
    for table in (load_price_overrides(), _PRICES):
        bucket = table.get(canonical)
        if not bucket:
            continue
        match = None
        for prefix in bucket:
            if model_l.startswith(prefix) and (match is None or len(prefix) > len(match)):
                match = prefix
        if match is not None:
            return bucket[match]
    return None


def compute_cost_usd(provider: str, model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate USD cost for one model call. Unknown models cost 0.0.

    Returns 0.0 (not an error) for unpriced models so spend tracking degrades
    gracefully; callers can detect unpriced calls via :func:`is_priced`.
    """
    price = lookup_price(provider, model)
    if price is None:
        return 0.0
    inp = max(0, int(input_tokens))
    out = max(0, int(output_tokens))
    return round((inp / 1_000_000) * price.input_per_mtok + (out / 1_000_000) * price.output_per_mtok, 6)


def is_priced(provider: str, model: str) -> bool:
    """True when the model resolves to a known price."""
    return lookup_price(provider, model) is not None
