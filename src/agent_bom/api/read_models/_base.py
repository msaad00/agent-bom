"""Typed response contracts for the dashboard's highest-traffic read endpoints.

These models document the live JSON bodies in the OpenAPI contract that the UI
types are generated from. They are deliberately lenient at runtime:

* ``extra="allow"`` keeps any key a handler adds that the model does not yet
  name, so a response is never silently narrowed;
* routes register them with ``response_model_exclude_unset=True`` so optional
  keys are emitted only when the handler set them (no injected ``null``);
* non-integer numbers are ``int | float`` so an integral float such as ``100``
  is not re-rendered as ``100.0``;
* a response that no longer matches its model is logged and returned as the
  handler built it instead of failing the request with a 500.

``tests/test_api_read_contracts.py`` validates real seeded bodies against these
models with undeclared keys forbidden, so drift fails CI rather than production.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError, ValidationInfo, model_validator

_logger = logging.getLogger(__name__)

Num = int | float
# Validation context key that disables the fail-open fallback (contract tests).
STRICT_CONTRACT = "strict_contract"


class ReadModel(BaseModel):
    """Lenient base for nested response objects."""

    model_config = ConfigDict(extra="allow")


class ReadResponse(ReadModel):
    """Top-level response body: fail open on contract drift."""

    @model_validator(mode="wrap")
    @classmethod
    def _fail_open_on_drift(cls, data: Any, handler: Any, info: ValidationInfo) -> Any:
        try:
            return handler(data)
        except ValidationError as exc:
            if not isinstance(data, dict) or (info.context or {}).get(STRICT_CONTRACT):
                raise
            _logger.warning(
                "response contract drift for %s: %d field error(s); returning the handler body unchanged",
                cls.__name__,
                exc.error_count(),
            )
            return cls.model_construct(**data)


# ── shared shapes ────────────────────────────────────────────────────────────


class SeverityCounts(ReadModel):
    critical: int
    high: int
    medium: int
    low: int
    unrated: int | None = None


class CountWindow(ReadModel):
    applied: bool
    days: int | None = None
    label: str
    since: str | None = None


class Completeness(ReadModel):
    status: str
    reason: str


class CountMetadata(ReadModel):
    completeness: Completeness
    definition: str
    filters: dict[str, Any]
    returned: int
    scope: str
    source: str
    total: int
    total_kind: str
    window: CountWindow | None = None


class PostureBreakdownItem(ReadModel):
    contribution: Num
    count: int
    driver: str
    label: str
    weight: Num


class IssueCounts(ReadModel):
    approximate: bool
    basis: str
    critical: int
    high: int
    medium: int
    low: int
    unrated: int
    total: int
    window: CountWindow | None = None
