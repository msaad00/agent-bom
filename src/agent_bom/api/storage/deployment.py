"""Deployment requirements shared by storage and HTTP policy."""

import logging

from agent_bom.core.settings import env_raw

_logger = logging.getLogger(__name__)


def _configured_api_replicas() -> int:
    raw = (env_raw("AGENT_BOM_CONTROL_PLANE_REPLICAS") or "").strip()
    if not raw:
        return 1
    try:
        return max(1, int(raw))
    except ValueError:
        _logger.warning("Invalid AGENT_BOM_CONTROL_PLANE_REPLICAS; defaulting to 1")
        return 1


def clustered_control_plane_required() -> bool:
    """Return true when process-local control-plane state is unsafe."""
    return (env_raw("AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    } or _configured_api_replicas() > 1
