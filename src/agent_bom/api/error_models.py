"""Shared error response models, independent of middleware and stores."""

from typing import Any, Literal

from pydantic import BaseModel, Field

_ERROR_CODE_BY_STATUS = {
    400: "BAD_REQUEST",
    401: "AUTH_FAILED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    409: "CONFLICT",
    413: "PAYLOAD_TOO_LARGE",
    415: "UNSUPPORTED_MEDIA_TYPE",
    422: "VALIDATION_ERROR",
    429: "RATE_LIMITED",
    500: "INTERNAL_ERROR",
    503: "SERVICE_UNAVAILABLE",
}


ErrorCode = Literal[
    "BAD_REQUEST",
    "AUTH_FAILED",
    "FORBIDDEN",
    "NOT_FOUND",
    "METHOD_NOT_ALLOWED",
    "CONFLICT",
    "PAYLOAD_TOO_LARGE",
    "UNSUPPORTED_MEDIA_TYPE",
    "VALIDATION_ERROR",
    "RATE_LIMITED",
    "INTERNAL_ERROR",
    "SERVICE_UNAVAILABLE",
]


class ErrorBody(BaseModel):
    """Stable machine-readable error: branch on ``code``, show ``message``."""

    code: ErrorCode
    message: str
    correlation_id: str = Field(description="Echoed as the X-Request-ID response header")
    details: Any = Field(description="The original error detail: a string, or field errors for VALIDATION_ERROR")


class ErrorEnvelope(BaseModel):
    """Body of every non-SCIM v1 error response."""

    error: ErrorBody
    detail: Any = Field(description="Legacy alias of error.details for older clients")


_ERROR_CODES_DOC = ", ".join(f"{status} {code}" for status, code in sorted(_ERROR_CODE_BY_STATUS.items()) if status < 500)

# Shared OpenAPI responses for the versioned API. The ranges replace FastAPI's
# default 422 ``HTTPValidationError``, which is not the shape clients receive.
ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    "4XX": {"model": ErrorEnvelope, "description": f"Client error envelope. Codes: {_ERROR_CODES_DOC}"},
    "5XX": {"model": ErrorEnvelope, "description": "Server error envelope (INTERNAL_ERROR, SERVICE_UNAVAILABLE)"},
}
