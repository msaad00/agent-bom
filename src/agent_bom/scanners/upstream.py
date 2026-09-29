"""Adapter from HTTP outcomes to the typed upstream errors in ``core.errors``.

``request_with_retry`` returns ``None`` when retries are exhausted (timeouts,
connection errors, persistent 5xx) and raises ``SecurityError`` when DNS fails
or egress is refused. ``upstream_request`` turns both, and any unexpected
status, into one ``UpstreamError`` subclass so callers branch on type instead
of re-deciding "degraded vs failed vs empty" at every call site.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

import httpx

from agent_bom.core.errors import UpstreamError, UpstreamUnavailableError, upstream_error_for_status
from agent_bom.security import SecurityError


def upstream_error_from_response(
    source: str,
    response: httpx.Response | None,
    *,
    rate_limit_statuses: frozenset[int] = frozenset({429}),
) -> UpstreamError:
    """Classify a non-success ``request_with_retry`` outcome (``None`` = retries exhausted)."""
    if response is None:
        return upstream_error_for_status(source, None)
    retry_after: float | None = None
    header = response.headers.get("Retry-After")
    if header:
        try:
            retry_after = float(header)
        except ValueError:
            retry_after = None
    return upstream_error_for_status(source, response.status_code, retry_after=retry_after, rate_limit_statuses=rate_limit_statuses)


def upstream_error_from_egress_refusal(source: str) -> UpstreamUnavailableError:
    """``request_with_retry`` raises ``SecurityError`` when DNS fails or egress is refused."""
    return UpstreamUnavailableError(source, "host unresolvable or egress refused")


async def upstream_request(
    source: str,
    request_fn: Callable[..., Awaitable[httpx.Response | None]],
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    ok_statuses: frozenset[int] = frozenset({200}),
    rate_limit_statuses: frozenset[int] = frozenset({429}),
    **kwargs: Any,
) -> httpx.Response:
    """Return a response whose status is in ``ok_statuses`` or raise a typed ``UpstreamError``.

    ``request_fn`` is ``request_with_retry`` (passed in so callers' test seams
    keep working); its retry counts and backoff apply unchanged.
    """
    try:
        response = await request_fn(client, method, url, **kwargs)
    except SecurityError as exc:
        raise upstream_error_from_egress_refusal(source) from exc
    if response is None or response.status_code not in ok_statuses:
        raise upstream_error_from_response(source, response, rate_limit_statuses=rate_limit_statuses)
    return response
