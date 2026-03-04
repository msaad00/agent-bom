"""Resilient HTTP client with retries, backoff, and rate limiting."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

import httpx

from agent_bom.config import (
    HTTP_INITIAL_BACKOFF as INITIAL_BACKOFF,
)
from agent_bom.config import (
    HTTP_MAX_BACKOFF as MAX_BACKOFF,
)
from agent_bom.config import (
    HTTP_MAX_RETRIES as MAX_RETRIES,
)

logger = logging.getLogger(__name__)

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


def _sanitize_for_log(value: object) -> str:
    """Sanitize a value for safe inclusion in log messages.

    Replaces newlines and carriage returns to prevent log injection.
    """
    return str(value).replace("\n", "\\n").replace("\r", "\\r")


def _safe_url(url: str) -> str:  # noqa: PLW0108
    """Redact sensitive parts of a URL for safe logging.

    Strips query parameters (which may contain API keys/tokens)
    and userinfo (user:password@host) from the URL.
    """
    from urllib.parse import urlparse, urlunparse

    try:
        parsed = urlparse(url)
        # Remove query, fragment, and userinfo
        safe = urlunparse(
            (
                parsed.scheme,
                parsed.hostname or parsed.netloc.split("@")[-1],
                parsed.path,
                "",  # params
                "",  # query — may contain api_key, token, etc.
                "",  # fragment
            )
        )
        return _sanitize_for_log(safe)
    except (ValueError, AttributeError):
        return "<redacted-url>"


def create_client(timeout: float | None = None, max_redirects: int = 5) -> httpx.AsyncClient:
    """Create an httpx.AsyncClient with connection-level retries.

    Uses httpx's built-in transport retry for connection failures (DNS, TCP reset).
    Application-level retries (429, 5xx) are handled by ``request_with_retry``.

    Args:
        timeout: Per-request timeout in seconds.
        max_redirects: Maximum number of HTTP redirects to follow (default 5).
    """
    from agent_bom.config import HTTP_DEFAULT_TIMEOUT

    if timeout is None:
        timeout = HTTP_DEFAULT_TIMEOUT
    transport = httpx.AsyncHTTPTransport(retries=2)
    return httpx.AsyncClient(
        timeout=timeout,
        transport=transport,
        follow_redirects=True,
        max_redirects=max_redirects,
    )


async def request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    max_retries: int = MAX_RETRIES,
    **kwargs: Any,
) -> Optional[httpx.Response]:
    """Make an HTTP request with exponential backoff on retryable errors.

    Handles:
    - 429 Too Many Requests (respects Retry-After header)
    - 5xx server errors
    - Connection timeouts and network errors

    Returns:
        httpx.Response on success, None on exhausted retries.
    """
    log_url = _safe_url(url)
    backoff = INITIAL_BACKOFF

    for attempt in range(max_retries + 1):
        try:
            response = await client.request(method, url, **kwargs)

            if response.status_code not in RETRYABLE_STATUS_CODES:
                return response

            # Retryable status — check Retry-After header
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                try:
                    wait = min(float(retry_after), MAX_BACKOFF)
                except ValueError:
                    wait = backoff
            else:
                wait = backoff

            if attempt < max_retries:
                logger.info(
                    "HTTP %d from %s — retry %d/%d in %.1fs",
                    response.status_code,
                    log_url,
                    attempt + 1,
                    max_retries,
                    wait,
                )
                await asyncio.sleep(wait)
                backoff = min(backoff * 2, MAX_BACKOFF)
            else:
                logger.warning(
                    "HTTP %d from %s — exhausted %d retries",
                    response.status_code,
                    log_url,
                    max_retries,
                )
                return response

        except httpx.TimeoutException:
            if attempt < max_retries:
                logger.info(
                    "Timeout on %s — retry %d/%d in %.1fs",
                    log_url,
                    attempt + 1,
                    max_retries,
                    backoff,
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF)
            else:
                logger.warning("Timeout on %s — exhausted %d retries", log_url, max_retries)
                return None

        except httpx.HTTPError as e:
            safe_err = _sanitize_for_log(e)
            if attempt < max_retries:
                logger.info(
                    "HTTP error on %s: %s — retry %d/%d in %.1fs",
                    log_url,
                    safe_err,
                    attempt + 1,
                    max_retries,
                    backoff,
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF)
            else:
                logger.warning("HTTP error on %s: %s — exhausted %d retries", log_url, safe_err, max_retries)
                return None

    return None
