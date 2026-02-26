"""Resilient HTTP client with retries, backoff, and rate limiting."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

# Retry configuration
MAX_RETRIES = 3
INITIAL_BACKOFF = 1.0  # seconds
MAX_BACKOFF = 30.0
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


def _sanitize_for_log(value: object) -> str:
    """Sanitize a value for safe inclusion in log messages.

    Replaces newlines and carriage returns to prevent log injection.
    """
    return str(value).replace("\n", "\\n").replace("\r", "\\r")


def create_client(timeout: float = 30.0) -> httpx.AsyncClient:
    """Create an httpx.AsyncClient with connection-level retries.

    Uses httpx's built-in transport retry for connection failures (DNS, TCP reset).
    Application-level retries (429, 5xx) are handled by `request_with_retry`.
    """
    transport = httpx.AsyncHTTPTransport(retries=2)
    return httpx.AsyncClient(
        timeout=timeout,
        transport=transport,
        follow_redirects=True,
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
    safe_url = _sanitize_for_log(url)
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
                    response.status_code, safe_url, attempt + 1, max_retries, wait,
                )
                await asyncio.sleep(wait)
                backoff = min(backoff * 2, MAX_BACKOFF)
            else:
                logger.warning(
                    "HTTP %d from %s — exhausted %d retries",
                    response.status_code, safe_url, max_retries,
                )
                return response

        except httpx.TimeoutException:
            if attempt < max_retries:
                logger.info(
                    "Timeout on %s — retry %d/%d in %.1fs",
                    safe_url, attempt + 1, max_retries, backoff,
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF)
            else:
                logger.warning("Timeout on %s — exhausted %d retries", safe_url, max_retries)
                return None

        except httpx.HTTPError as e:
            safe_err = _sanitize_for_log(e)
            if attempt < max_retries:
                logger.info(
                    "HTTP error on %s: %s — retry %d/%d in %.1fs",
                    safe_url, safe_err, attempt + 1, max_retries, backoff,
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF)
            else:
                logger.warning("HTTP error on %s: %s — exhausted %d retries", safe_url, safe_err, max_retries)
                return None

    return None
