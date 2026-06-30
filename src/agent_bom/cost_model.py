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
from typing import Union

PRICE_TABLE_CAPTURED = "2026-06-01"

# Provenance of the rate used to price a call. A *reconciled* rate comes from an
# operator override — either an injected per-call rate map or the
# ``AGENT_BOM_COST_MODEL_JSON`` env table — and represents a negotiated/actual
# rate; a *list_price* rate comes from the static published table below and is
# only an estimate; *unpriced* means no rate resolved at all (cost 0.0).
RATE_RECONCILED = "reconciled"
RATE_LIST_PRICE = "list_price"
RATE_UNPRICED = "unpriced"

# Upper bound on tokens attributed to one call; clamps malformed spans so
# persistence stays inside int64 and cost figures stay sane.
MAX_TOKENS_PER_CALL = 1_000_000_000_000


@dataclass(frozen=True)
class ModelPrice:
    """USD per 1,000,000 tokens for one model."""

    input_per_mtok: float
    output_per_mtok: float


@dataclass(frozen=True)
class RatedCost:
    """A priced call together with the provenance of the rate that priced it.

    ``is_estimated`` is ``True`` for list-price (and unpriced) figures and
    ``False`` only for a reconciled/negotiated rate, so the API/UI can label a
    'list-price estimate' apart from a 'reconciled actual'.
    """

    cost_usd: float
    priced: bool
    rate_source: str
    is_estimated: bool


# An injected per-model rate map: provider -> model-prefix -> rate, where a rate
# is a ModelPrice or a ``{"input_per_mtok", "output_per_mtok"}`` mapping.
RateMap = dict[str, dict[str, Union[ModelPrice, dict[str, float]]]]


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


def _match_in_bucket(bucket: dict[str, ModelPrice], model_l: str) -> ModelPrice | None:
    """Longest model-prefix match within one provider's price bucket, or None."""
    match: str | None = None
    for prefix in bucket:
        if model_l.startswith(prefix) and (match is None or len(prefix) > len(match)):
            match = prefix
    return bucket[match] if match is not None else None


def _coerce_rate_map(rates: RateMap | None) -> dict[str, dict[str, ModelPrice]]:
    """Normalize an injected rate map into the internal price-table shape.

    Accepts ``ModelPrice`` values or ``{"input_per_mtok", "output_per_mtok"}``
    mappings; malformed entries are skipped rather than raised so a bad
    negotiated-rate row never breaks pricing.
    """
    out: dict[str, dict[str, ModelPrice]] = {}
    for provider, models in (rates or {}).items():
        if not isinstance(models, dict):
            continue
        bucket: dict[str, ModelPrice] = {}
        for prefix, price in models.items():
            try:
                if isinstance(price, ModelPrice):
                    bucket[str(prefix).lower()] = price
                else:
                    bucket[str(prefix).lower()] = ModelPrice(
                        float(price.get("input_per_mtok", 0.0)),
                        float(price.get("output_per_mtok", 0.0)),
                    )
            except (ValueError, AttributeError, TypeError):
                continue
        if bucket:
            out[_normalize_provider(provider)] = bucket
    return out


def lookup_rate(provider: str, model: str, *, rates: RateMap | None = None) -> tuple[ModelPrice | None, str]:
    """Resolve a model's price and the provenance of the rate used.

    Resolution order (longest-prefix within each table):
      1. ``rates`` — an injected per-call override map (negotiated/actual).
      2. ``AGENT_BOM_COST_MODEL_JSON`` operator overrides (negotiated/actual).
      3. the static published list-price table (an estimate).

    Returns ``(price, rate_source)`` where ``rate_source`` is one of
    :data:`RATE_RECONCILED`, :data:`RATE_LIST_PRICE`, or :data:`RATE_UNPRICED`.
    """
    canonical = _normalize_provider(provider)
    model_l = (model or "").strip().lower()
    if not model_l:
        return None, RATE_UNPRICED
    sources: tuple[tuple[dict[str, dict[str, ModelPrice]], str], ...] = (
        (_coerce_rate_map(rates), RATE_RECONCILED),
        (load_price_overrides(), RATE_RECONCILED),
        (_PRICES, RATE_LIST_PRICE),
    )
    for table, source in sources:
        bucket = table.get(canonical)
        if not bucket:
            continue
        price = _match_in_bucket(bucket, model_l)
        if price is not None:
            return price, source
    return None, RATE_UNPRICED


def lookup_price(provider: str, model: str) -> ModelPrice | None:
    """Return the price for the longest model-prefix match, overrides first."""
    price, _ = lookup_rate(provider, model)
    return price


def compute_cost_usd(provider: str, model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate USD cost for one model call. Unknown models cost 0.0.

    Returns 0.0 (not an error) for unpriced models so spend tracking degrades
    gracefully; callers can detect unpriced calls via :func:`is_priced`.
    """
    price = lookup_price(provider, model)
    if price is None:
        return 0.0
    # Clamp absurd token counts: no single call exceeds this, and it keeps the
    # persisted integer well inside SQLite/Postgres int64 so a malformed span
    # cannot raise on insert.
    inp = min(max(0, int(input_tokens)), MAX_TOKENS_PER_CALL)
    out = min(max(0, int(output_tokens)), MAX_TOKENS_PER_CALL)
    return round((inp / 1_000_000) * price.input_per_mtok + (out / 1_000_000) * price.output_per_mtok, 6)


def price_call(
    provider: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    *,
    rates: RateMap | None = None,
) -> RatedCost:
    """Price one call and label the provenance of the rate (estimate vs actual).

    Mirrors :func:`compute_cost_usd` but returns the cost alongside whether the
    figure is a list-price estimate or a reconciled/negotiated actual, so cost
    records and summaries can carry the ``rate_source`` / ``is_estimated`` flag.
    """
    price, source = lookup_rate(provider, model, rates=rates)
    if price is None:
        return RatedCost(0.0, False, RATE_UNPRICED, True)
    inp = min(max(0, int(input_tokens)), MAX_TOKENS_PER_CALL)
    out = min(max(0, int(output_tokens)), MAX_TOKENS_PER_CALL)
    cost = round((inp / 1_000_000) * price.input_per_mtok + (out / 1_000_000) * price.output_per_mtok, 6)
    return RatedCost(cost, True, source, source != RATE_RECONCILED)


def is_priced(provider: str, model: str) -> bool:
    """True when the model resolves to a known price."""
    return lookup_price(provider, model) is not None
