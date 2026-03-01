"""Hybrid push-to-dashboard — CLI local scan → push results to central dashboard.

Sanitizes results before push:
- Strips local config_path from agents
- Redacts environment variable values
- Adds stable source_id for tracking
"""

from __future__ import annotations

import copy
import hashlib
import logging
import platform

logger = logging.getLogger(__name__)


def generate_source_id() -> str:
    """Generate a stable machine identifier (hostname SHA256[:12])."""
    hostname = platform.node() or "unknown"
    return hashlib.sha256(hostname.encode()).hexdigest()[:12]


def sanitize_results(results: dict) -> dict:
    """Deep-copy results and strip sensitive data before push.

    - Removes config_path from agents
    - Redacts env var patterns in metadata
    - Adds source_id
    """
    sanitized = copy.deepcopy(results)

    # Strip config_path from agents
    for agent in sanitized.get("agents", []):
        agent.pop("config_path", None)
        # Redact env vars in metadata
        meta = agent.get("metadata", {})
        for key, val in list(meta.items()):
            if isinstance(val, str) and _looks_like_secret(key):
                meta[key] = "***REDACTED***"

    # Add source identifier
    sanitized["source_id"] = generate_source_id()

    return sanitized


def _looks_like_secret(key: str) -> bool:
    """Check if a metadata key name looks like it holds a secret."""
    patterns = ("token", "key", "secret", "password", "credential", "auth")
    lower = key.lower()
    return any(p in lower for p in patterns)


async def _push_async(push_url: str, results: dict, api_key: str | None = None) -> bool:
    """POST sanitized results to central dashboard."""
    from agent_bom.http_client import create_client

    sanitized = sanitize_results(results)
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    async with create_client(timeout=30.0) as client:
        try:
            resp = await client.post(push_url, json=sanitized, headers=headers)
            if resp.status_code < 300:
                logger.info("Results pushed to %s (status=%d)", push_url, resp.status_code)
                return True
            logger.warning("Push failed: HTTP %d — %s", resp.status_code, resp.text[:200])
            return False
        except Exception:
            logger.exception("Push to %s failed", push_url)
            return False


def push_results(push_url: str, results: dict, api_key: str | None = None) -> bool:
    """Synchronous wrapper for pushing results to a dashboard."""
    import asyncio

    return asyncio.run(_push_async(push_url, results, api_key))
