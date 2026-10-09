"""Typed OpenAPI contracts for the dashboard's read endpoints.

Routes document these models without validating nested response bodies at
runtime. Strict seeded contract tests detect drift; the UI generates its types
from the same OpenAPI schemas. Direct model validation remains lenient unless
strict contract context is supplied.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, ValidationError, ValidationInfo, WithJsonSchema, model_validator

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
            # Field paths and error types only: response values never reach the log.
            errors = exc.errors(include_input=False)
            fields = sorted({f"{'.'.join(str(part) for part in error['loc'])}:{error['type']}" for error in errors})
            _logger.warning(
                "response contract drift for %s: %d field error(s) [%s]; returning the handler body unchanged",
                cls.__name__,
                exc.error_count(),
                ", ".join(fields[:8]),
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
    total: int | None
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


def documented(model: type[BaseModel]) -> dict[str, Any]:
    """Route kwargs that document ``model`` as the 200 body without validating responses.

    The request path keeps FastAPI's plain ``dict`` serialization; the contract
    tests enforce the model against live bodies in CI instead.
    """
    ref = WithJsonSchema({"$ref": f"#/components/schemas/{model.__name__}"})
    return {"response_model": Annotated[dict[str, Any], ref], "responses": {200: {"model": model}}}
