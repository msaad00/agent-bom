"""Resilient HTTP client with retries, backoff, and rate limiting."""

from __future__ import annotations

import asyncio
import logging
import random
import threading
import time
from typing import Any, Optional
from urllib.parse import urlparse

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
from agent_bom.config import (
    HTTP_RATE_LIMIT_BREAKER_THRESHOLD as RATE_LIMIT_BREAKER_THRESHOLD,
)

logger = logging.getLogger(__name__)

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


# ── Registry rate-limit circuit breaker ────────────────────────────────────
# Under sustained HTTP 429s from a registry (e.g. npm at peak), retrying every
# package through the full backoff ladder turns a throttle into a multi-minute
# stall and a per-package warning storm. Once a host returns
# RATE_LIMIT_BREAKER_THRESHOLD rate-limit responses within a run, the breaker
# opens for that host: further requests short-circuit immediately — no socket,
# no backoff, no per-call warning — so callers fall straight through to their
# cached/bundled fallback path. State is global (shared across sync + async)
# and reset per scan via reset_rate_limit_breaker().

_BREAKER_LOCK = threading.Lock()
_RATE_LIMIT_429_COUNTS: dict[str, int] = {}
_RATE_LIMIT_TRIPPED: set[str] = set()


def _host_of(url: str) -> str:
    """Return the lowercased hostname for a URL, or '' if unparseable."""
    try:
        return (urlparse(url).hostname or "").lower()
    except (ValueError, AttributeError):
        return ""


def registry_breaker_tripped(url_or_host: str) -> bool:
    """Return True if the rate-limit breaker is open for the URL's host.

    Accepts either a full URL or a bare hostname.
    """
    host = url_or_host if "/" not in url_or_host else _host_of(url_or_host)
    if not host:
        return False
    with _BREAKER_LOCK:
        return host in _RATE_LIMIT_TRIPPED


def _record_rate_limit(host: str) -> bool:
    """Count a 429 for *host*; return True once the breaker is/becomes open."""
    if not host:
        return False
    with _BREAKER_LOCK:
        if host in _RATE_LIMIT_TRIPPED:
            return True
        count = _RATE_LIMIT_429_COUNTS.get(host, 0) + 1
        _RATE_LIMIT_429_COUNTS[host] = count
        if count >= RATE_LIMIT_BREAKER_THRESHOLD:
            _RATE_LIMIT_TRIPPED.add(host)
            return True
        return False


def _record_non_rate_limited(host: str) -> None:
    """A non-429 response clears the consecutive 429 counter for a healthy host."""
    if not host:
        return
    with _BREAKER_LOCK:
        if host not in _RATE_LIMIT_TRIPPED:
            _RATE_LIMIT_429_COUNTS.pop(host, None)


def reset_rate_limit_breaker() -> None:
    """Reset all registry breaker state. Call at the start of each scan."""
    with _BREAKER_LOCK:
        _RATE_LIMIT_429_COUNTS.clear()
        _RATE_LIMIT_TRIPPED.clear()


# ── Offline mode ─────────────────────────────────────────────────────────────
# When True, ALL outbound HTTP requests are blocked at the transport layer.
# Set this flag before any network call via set_offline(True).

_OFFLINE: bool = False


class OfflineModeError(RuntimeError):
    """Raised when a network request is attempted in offline mode."""


def set_offline(value: bool) -> None:
    """Enable or disable global offline mode.

    When enabled, every call to create_client / create_sync_client /
    request_with_retry / sync_request_with_retry raises OfflineModeError
    before any socket is opened.
    """
    global _OFFLINE  # noqa: PLW0603
    _OFFLINE = value


def check_offline() -> None:
    """Raise OfflineModeError if offline mode is active."""
    if _OFFLINE:
        raise OfflineModeError("Network request blocked: --offline mode is active")


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


def _jittered_wait(wait: float) -> float:
    """Apply small positive jitter so concurrent clients do not back off in lockstep."""
    if wait <= 0:
        return 0.0
    return min(wait + random.uniform(0.0, wait * 0.1), MAX_BACKOFF)


def _should_retry_status(status_code: int, url: str) -> bool:
    """Return whether an HTTP status should enter the shared retry loop."""
    if status_code not in RETRYABLE_STATUS_CODES:
        return False
    parsed = urlparse(url)
    if status_code == 429 and (parsed.hostname or "").lower() == "api.github.com" and parsed.path.rstrip("/") == "/advisories":
        return False
    return True


def create_client(timeout: float | None = None, max_redirects: int = 0) -> httpx.AsyncClient:
    """Create an httpx.AsyncClient with connection-level retries.

    Uses httpx's built-in transport retry for connection failures (DNS, TCP reset).
    Application-level retries (429, 5xx) are handled by ``request_with_retry``.

    Args:
        timeout: Per-request timeout in seconds.
        max_redirects: Maximum redirects available if a caller explicitly
            enables redirects on a request. Redirect following is disabled by
            default so SSRF validation cannot be bypassed by a Location header.
    """
    check_offline()
    from agent_bom.config import HTTP_DEFAULT_TIMEOUT

    if timeout is None:
        timeout = HTTP_DEFAULT_TIMEOUT
    transport = httpx.AsyncHTTPTransport(retries=2)
    return httpx.AsyncClient(
        timeout=timeout,
        transport=transport,
        follow_redirects=False,
        max_redirects=max_redirects,
        verify=True,  # Explicit: always verify TLS certificates (defense-in-depth)
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
    check_offline()
    # Defense-in-depth: validate and re-derive the URL at the transport layer.
    # validate_url() raises SecurityError on SSRF attempts (private IPs,
    # localhost, metadata endpoints, non-HTTPS, DNS rebinding).
    # Re-constructing the URL from parsed components ensures CodeQL sees
    # the taint is broken.
    from urllib.parse import urlparse, urlunparse

    from agent_bom.security import validate_url as _validate_url  # noqa: E402

    _validate_url(url)  # raises SecurityError on SSRF attempts
    # Re-derive URL from parsed components to break CodeQL taint chain
    _parsed = urlparse(url)
    safe_url = urlunparse(_parsed)

    log_url = _safe_url(safe_url)
    host = _host_of(safe_url)
    backoff = INITIAL_BACKOFF

    # Breaker already open for this host: skip the network entirely so the
    # caller falls through to cached/bundled data without backoff or warnings.
    if host and registry_breaker_tripped(host):
        logger.debug("Rate-limit breaker open for %s — skipping live request to %s", host, log_url)
        return None

    for attempt in range(max_retries + 1):
        try:
            response = await client.request(method, safe_url, **kwargs)

            if not _should_retry_status(response.status_code, safe_url):
                _record_non_rate_limited(host)
                return response

            # Sustained 429s trip the per-host breaker: stop retrying this host
            # immediately and return the 429 so the caller can fall back fast.
            if response.status_code == 429 and _record_rate_limit(host):
                logger.debug("Rate-limit breaker tripped for %s on HTTP 429 — short-circuiting %s", host, log_url)
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
            wait = _jittered_wait(wait)

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
                wait = _jittered_wait(backoff)
                logger.info(
                    "Timeout on %s — retry %d/%d in %.1fs",
                    log_url,
                    attempt + 1,
                    max_retries,
                    wait,
                )
                await asyncio.sleep(wait)
                backoff = min(backoff * 2, MAX_BACKOFF)
            else:
                logger.warning("Timeout on %s — exhausted %d retries", log_url, max_retries)
                return None

        except httpx.HTTPError as e:
            safe_err = _sanitize_for_log(e)
            if attempt < max_retries:
                wait = _jittered_wait(backoff)
                logger.info(
                    "HTTP error on %s: %s — retry %d/%d in %.1fs",
                    log_url,
                    safe_err,
                    attempt + 1,
                    max_retries,
                    wait,
                )
                await asyncio.sleep(wait)
                backoff = min(backoff * 2, MAX_BACKOFF)
            else:
                logger.warning("HTTP error on %s: %s — exhausted %d retries", log_url, safe_err, max_retries)
                return None

    return None


# ── Synchronous API ──────────────────────────────────────────────────────
# Mirrors the async API above but uses httpx.Client for callers that
# cannot use asyncio (db/sync.py, parsers, cloud probes, CLI).


def create_sync_client(timeout: float | None = None, max_redirects: int = 0) -> httpx.Client:
    """Create an httpx.Client (sync) with connection-level retries."""
    check_offline()
    from agent_bom.config import HTTP_DEFAULT_TIMEOUT

    if timeout is None:
        timeout = HTTP_DEFAULT_TIMEOUT
    transport = httpx.HTTPTransport(retries=2)
    return httpx.Client(
        timeout=timeout,
        transport=transport,
        follow_redirects=False,
        max_redirects=max_redirects,
        verify=True,
    )


def sync_request_with_retry(
    client: httpx.Client,
    method: str,
    url: str,
    max_retries: int = MAX_RETRIES,
    **kwargs: Any,
) -> Optional[httpx.Response]:
    """Synchronous HTTP request with exponential backoff on retryable errors.

    Drop-in replacement for urllib.request.urlopen patterns.
    Handles 429, 5xx, timeouts, and connection errors.
    """
    check_offline()
    log_url = _safe_url(url)
    host = _host_of(url)
    backoff = INITIAL_BACKOFF

    if host and registry_breaker_tripped(host):
        logger.debug("Rate-limit breaker open for %s — skipping live request to %s", host, log_url)
        return None

    for attempt in range(max_retries + 1):
        try:
            response = client.request(method, url, **kwargs)

            if not _should_retry_status(response.status_code, url):
                _record_non_rate_limited(host)
                return response

            if response.status_code == 429 and _record_rate_limit(host):
                logger.debug("Rate-limit breaker tripped for %s on HTTP 429 — short-circuiting %s", host, log_url)
                return response

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
                time.sleep(wait)
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
                time.sleep(backoff)
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
                time.sleep(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF)
            else:
                logger.warning("HTTP error on %s: %s — exhausted %d retries", log_url, safe_err, max_retries)
                return None

    return None


def sync_get(url: str, timeout: float | None = None, headers: dict | None = None) -> httpx.Response | None:
    """Convenience: single GET request with retry. Manages its own client."""
    with create_sync_client(timeout=timeout) as client:
        return sync_request_with_retry(client, "GET", url, headers=headers or {})


def fetch_bytes(url: str, *, timeout: float = 30, headers: dict | None = None) -> bytes:
    """Download URL content as bytes, with retries. Raises on failure.

    Drop-in replacement for ``urllib.request.urlopen(url, timeout=X).read()``.
    """
    resp = sync_get(url, timeout=timeout, headers=headers)
    if resp is None:
        raise ConnectionError(f"Failed to fetch {_safe_url(url)} after retries")
    resp.raise_for_status()
    return resp.content


def fetch_json(url: str, *, timeout: float = 30, headers: dict | None = None) -> Any:
    """Download URL content as parsed JSON, with retries. Raises on failure."""
    resp = sync_get(url, timeout=timeout, headers=headers)
    if resp is None:
        raise ConnectionError(f"Failed to fetch {_safe_url(url)} after retries")
    resp.raise_for_status()
    return resp.json()
