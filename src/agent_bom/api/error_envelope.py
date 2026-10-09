"""Shared v1 error responses for route handlers and pre-routing admission."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Coroutine, Sequence
from functools import wraps
from typing import Any, Literal, cast

from pydantic import BaseModel, Field
from starlette.middleware.base import RequestResponseEndpoint
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse, Response

from agent_bom.security import sanitize_error

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


def _error_code_for_status(status_code: int) -> str:
    return _ERROR_CODE_BY_STATUS.get(status_code, "INTERNAL_ERROR")


def _error_message_for(status_code: int, detail: object) -> str:
    """Best-effort short human message derived from the FastAPI detail."""
    if isinstance(detail, str) and detail.strip():
        return detail
    if isinstance(detail, list) and detail:
        # RequestValidationError serializes to a list of field-level errors;
        # collapse the first message so the envelope still has a human field.
        first = detail[0]
        if isinstance(first, dict):
            msg = first.get("msg")
            if isinstance(msg, str) and msg.strip():
                return msg
    if isinstance(detail, dict):
        msg = detail.get("message") or detail.get("msg")
        if isinstance(msg, str) and msg.strip():
            return msg
    return {
        400: "Bad request",
        401: "Authentication required",
        403: "Forbidden",
        404: "Not found",
        409: "Conflict",
        413: "Payload too large",
        422: "Validation error",
        429: "Rate limited",
        500: "Internal error",
        503: "Service unavailable",
    }.get(status_code, "Request failed")


def _json_safe_validation_errors(errors: Sequence[object]) -> list[dict[str, object]]:
    """Make Pydantic validation errors JSON-serializable and value-free.

    Two failure modes are handled here:

    * ``model_validator`` failures embed a live ``ValueError`` in
      ``ctx['error']``, and a non-JSON request body (``text/plain``, form
      encoding, or no ``Content-Type`` at all) makes Pydantic report the raw
      ``bytes`` in ``input``. Serializing either verbatim raises *inside* the
      validation handler, so the caller got a bare 500 with no ``error.code``
      and no ``correlation_id`` — on every POST/PUT/PATCH.
    * ``input`` reflected the submitted value back verbatim, so a
      credential-shaped field ended up in CI logs, proxies, and error trackers.

    Dropping ``input`` fixes both; ``jsonable_encoder`` is the backstop for any
    remaining non-JSON value elsewhere in the error record.
    """
    from fastapi.encoders import jsonable_encoder

    safe: list[dict[str, object]] = []
    for err in errors:
        if not isinstance(err, dict):
            safe.append({"error": str(err)})
            continue
        item = {key: value for key, value in err.items() if key != "input"}
        ctx = item.get("ctx")
        if isinstance(ctx, dict):
            item["ctx"] = {key: str(value) if isinstance(value, BaseException) else value for key, value in ctx.items()}
        try:
            safe.append(cast(dict[str, object], jsonable_encoder(item)))
        except Exception:  # noqa: BLE001 — the error envelope must never fail to serialize
            safe.append(
                {
                    "type": str(item.get("type", "value_error")),
                    "loc": [str(part) for part in cast(Sequence[object], item.get("loc") or ())],
                    "msg": str(item.get("msg", "Validation error")),
                }
            )
    return safe


def _build_error_envelope(
    *,
    status_code: int,
    detail: object,
    correlation_id: str,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    payload = {
        "error": {
            "code": _error_code_for_status(status_code),
            "message": _error_message_for(status_code, detail),
            "correlation_id": correlation_id,
            # Preserve the original FastAPI detail payload for backward
            # compatibility — existing UIs that displayed `detail` still work
            # while new clients can read `error.code` / `error.message`.
            "details": detail,
        },
        # Top-level alias kept so callers that grew up on
        # ``{"detail": "..."}`` still parse. New code should read ``error``.
        "detail": detail,
    }
    response_headers = dict(headers or {})
    response_headers.setdefault("X-Request-ID", correlation_id)
    return JSONResponse(status_code=status_code, content=payload, headers=response_headers)


def _with_middleware_error_envelope(request: StarletteRequest, response: Response) -> Response:
    """Add the v1 envelope to locally constructed middleware errors.

    Downstream streaming responses and the SCIM protocol keep their own shape.
    Existing body fields and headers (including rate limits) are retained.
    """
    if not isinstance(response, JSONResponse) or response.status_code < 400:
        return response
    if getattr(request, "scope", {}).get("path", "").startswith("/scim/"):
        return response
    payload = json.loads(bytes(response.body))
    if not isinstance(payload, dict) or "detail" not in payload or "error" in payload:
        return response
    correlation_id = getattr(getattr(request, "state", None), "request_id", "") or request.headers.get("x-request-id") or str(uuid.uuid4())
    envelope = _build_error_envelope(
        status_code=response.status_code,
        detail=payload["detail"],
        correlation_id=correlation_id,
    )
    payload.update(json.loads(bytes(envelope.body)))
    response.body = response.render(payload)
    response.headers["Content-Length"] = str(len(response.body))
    response.headers["X-Request-ID"] = correlation_id
    return response


def install_error_envelope(application: object) -> None:
    """Register FastAPI exception handlers that emit the v1 error envelope.

    The envelope is ``{error: {code, message, correlation_id, details}}`` and
    is also surfaced as a top-level ``detail`` field for backward compatibility
    with the historical FastAPI shape.
    """
    from fastapi import HTTPException
    from fastapi.exceptions import RequestValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    from agent_bom.api.idempotency_store import IdempotencyPayloadError

    def _correlation_id(request: StarletteRequest) -> str:
        return getattr(request.state, "request_id", "") or request.headers.get("x-request-id") or str(uuid.uuid4())

    async def http_exception_handler(request: StarletteRequest, exc: HTTPException) -> JSONResponse:
        if request.url.path.startswith("/scim/"):
            from agent_bom.api.scim import scim_error_body

            correlation_id = _correlation_id(request)
            detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
            payload = scim_error_body(status_code=exc.status_code, detail=detail)
            response_headers = dict(getattr(exc, "headers", None) or {})
            response_headers.setdefault("X-Request-ID", correlation_id)
            return JSONResponse(
                status_code=exc.status_code,
                content=payload,
                media_type="application/scim+json",
                headers=response_headers,
            )
        return _build_error_envelope(
            status_code=exc.status_code,
            detail=exc.detail,
            correlation_id=_correlation_id(request),
            headers=getattr(exc, "headers", None),
        )

    async def starlette_http_exception_handler(request: StarletteRequest, exc: StarletteHTTPException) -> JSONResponse:
        return _build_error_envelope(
            status_code=exc.status_code,
            detail=exc.detail,
            correlation_id=_correlation_id(request),
            headers=getattr(exc, "headers", None),
        )

    async def validation_exception_handler(request: StarletteRequest, exc: RequestValidationError) -> JSONResponse:
        return _build_error_envelope(
            status_code=422,
            detail=_json_safe_validation_errors(exc.errors()),
            correlation_id=_correlation_id(request),
        )

    async def idempotency_payload_exception_handler(request: StarletteRequest, exc: Exception) -> JSONResponse:
        # The payload that could not be fingerprinted is caller-controlled, so
        # this is a client error — not an unhandled 500 that poisons 5xx alerting.
        return _build_error_envelope(
            status_code=422,
            detail=sanitize_error(exc) or "Request payload could not be processed",
            correlation_id=_correlation_id(request),
        )

    application.add_exception_handler(HTTPException, http_exception_handler)  # type: ignore[attr-defined]
    application.add_exception_handler(StarletteHTTPException, starlette_http_exception_handler)  # type: ignore[attr-defined]
    application.add_exception_handler(RequestValidationError, validation_exception_handler)  # type: ignore[attr-defined]
    application.add_exception_handler(IdempotencyPayloadError, idempotency_payload_exception_handler)  # type: ignore[attr-defined]


def with_middleware_error_envelope(
    dispatch: Callable[[Any, StarletteRequest, RequestResponseEndpoint], Coroutine[Any, Any, Response]],
) -> Callable[[Any, StarletteRequest, RequestResponseEndpoint], Coroutine[Any, Any, Response]]:
    """Apply the route error contract to an admission middleware's own response."""

    @wraps(dispatch)
    async def wrapped(self: Any, request: StarletteRequest, call_next: RequestResponseEndpoint) -> Response:
        return _with_middleware_error_envelope(request, await dispatch(self, request, call_next))

    return wrapped
