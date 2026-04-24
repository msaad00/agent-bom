"""Hybrid push-to-dashboard — CLI local scan → push results to central dashboard.

Sanitizes results before push:
- Strips local config_path from agents
- Redacts environment variable values
- Adds stable source_id for tracking
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import logging
import os
import platform
import uuid

import httpx

logger = logging.getLogger(__name__)


def _csv_env(name: str) -> list[str]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def _endpoint_identity_from_env() -> dict[str, str | list[str]]:
    return {
        "source_id": generate_source_id(),
        "enrollment_name": os.environ.get("AGENT_BOM_PUSH_ENROLLMENT_NAME", "").strip(),
        "owner": os.environ.get("AGENT_BOM_PUSH_OWNER", "").strip(),
        "environment": os.environ.get("AGENT_BOM_PUSH_ENVIRONMENT", "").strip(),
        "mdm_provider": os.environ.get("AGENT_BOM_PUSH_MDM_PROVIDER", "").strip(),
        "tags": _csv_env("AGENT_BOM_PUSH_TAGS"),
    }


def generate_source_id() -> str:
    """Generate a stable machine identifier (hostname SHA256[:12])."""
    configured = os.environ.get("AGENT_BOM_PUSH_SOURCE_ID", "").strip()
    if configured:
        return configured
    hostname = platform.node() or "unknown"
    return hashlib.sha256(hostname.encode()).hexdigest()[:12]


def sanitize_results(results: dict) -> dict:
    """Deep-copy results and strip sensitive data before push.

    - Removes config_path from agents
    - Redacts env var patterns in metadata
    - Adds source_id
    """
    sanitized = copy.deepcopy(results)

    endpoint_identity = _endpoint_identity_from_env()

    # Strip config_path from agents
    for agent in sanitized.get("agents", []):
        agent.pop("config_path", None)
        # Redact env vars in metadata
        meta = agent.get("metadata", {})
        for key, val in list(meta.items()):
            if isinstance(val, str) and _looks_like_secret(key):
                meta[key] = "***REDACTED***"
        for key in ("source_id", "enrollment_name", "owner", "environment", "mdm_provider"):
            value = endpoint_identity.get(key, "")
            if value and not agent.get(key):
                agent[key] = value
        tags = endpoint_identity.get("tags", [])
        if tags and not agent.get("tags"):
            agent["tags"] = tags

    # Add source identifier
    sanitized["source_id"] = str(endpoint_identity["source_id"])
    sanitized["idempotency_key"] = str(uuid.uuid4())

    return sanitized


def _looks_like_secret(key: str) -> bool:
    """Check if a metadata key name looks like it holds a secret."""
    patterns = ("token", "key", "secret", "password", "credential", "auth")
    lower = key.lower()
    return any(p in lower for p in patterns)


_DEFAULT_PUSH_MAX_ATTEMPTS = 3
_DEFAULT_PUSH_BASE_DELAY = 1.0
_DEFAULT_PUSH_MAX_DELAY = 30.0


def _push_retry_delay(attempt: int, base: float, cap: float) -> float:
    """Exponential backoff with small jitter bounded by cap."""
    import random

    exp = base * (2 ** (attempt - 1))
    jitter = random.uniform(0, exp * 0.1)
    return min(cap, exp + jitter)


async def _push_async(
    push_url: str,
    results: dict,
    api_key: str | None = None,
    *,
    max_attempts: int = _DEFAULT_PUSH_MAX_ATTEMPTS,
    base_delay_seconds: float = _DEFAULT_PUSH_BASE_DELAY,
    max_delay_seconds: float = _DEFAULT_PUSH_MAX_DELAY,
) -> bool:
    """POST sanitized results to the central dashboard with bounded retries.

    Retries on network errors (``httpx.HTTPError``, ``OSError``) and on
    retryable server responses (408, 425, 429, 5xx). Non-retryable 4xx
    responses short-circuit immediately to avoid hammering misconfigured
    endpoints. Matches the backoff contract used by the proxy audit delivery
    controller so both egress paths degrade the same way.
    """
    from agent_bom.http_client import create_client
    from agent_bom.security import SecurityError, validate_url

    sanitized = sanitize_results(results)
    try:
        validate_url(push_url)
    except SecurityError as exc:
        logger.error("Push URL rejected by outbound URL policy: %s", exc)
        return False

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    retryable_status = {408, 425, 429, 500, 502, 503, 504}
    last_status: int | None = None
    last_error: str | None = None

    async with create_client(timeout=30.0) as client:
        for attempt in range(1, max_attempts + 1):
            try:
                resp = await client.post(push_url, json=sanitized, headers=headers)
            except (httpx.HTTPError, ValueError, OSError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                logger.warning(
                    "Push to %s attempt %d/%d failed with %s",
                    push_url,
                    attempt,
                    max_attempts,
                    last_error,
                )
            else:
                last_status = resp.status_code
                if resp.status_code < 300:
                    logger.info(
                        "Results pushed to %s (status=%d, attempt=%d)",
                        push_url,
                        resp.status_code,
                        attempt,
                    )
                    return True
                if resp.status_code not in retryable_status:
                    logger.warning(
                        "Push to %s rejected with non-retryable status %d — %s",
                        push_url,
                        resp.status_code,
                        resp.text[:200],
                    )
                    return False
                last_error = resp.text[:200]
                logger.warning(
                    "Push to %s attempt %d/%d returned retryable status %d",
                    push_url,
                    attempt,
                    max_attempts,
                    resp.status_code,
                )

            if attempt < max_attempts:
                await asyncio.sleep(_push_retry_delay(attempt, base_delay_seconds, max_delay_seconds))

    logger.error(
        "Push to %s failed after %d attempts (last_status=%s, last_error=%s)",
        push_url,
        max_attempts,
        last_status,
        last_error,
    )
    return False


def push_results(push_url: str, results: dict, api_key: str | None = None) -> bool:
    """Synchronous wrapper for pushing results to a dashboard."""
    return asyncio.run(_push_async(push_url, results, api_key))
