"""Centralised tenant-id resolution for the MCP server surface.

Closes the MCP half of #1964. The MCP server runs as an out-of-process
host invoked by Claude Desktop / Cursor / Codex / etc. — none of those
clients pass an authenticated tenant identity. The operator who launches
``agent-bom mcp server`` decides which tenant context the tools execute
under by setting ``AGENT_BOM_MCP_TENANT_ID`` (preferred) or falling back
to ``AGENT_BOM_TENANT_ID``.

This module is the only sanctioned reader of those env vars from MCP
code paths. ``tests/test_cli_mcp_tenant_resolution.py`` scans the
codebase and fails CI if a new ad-hoc env read appears in a MCP module.
"""

from __future__ import annotations

import logging
import os
from typing import Final

from agent_bom.cli._tenant import (
    DEFAULT_TENANT_ID,
    TENANT_ENV_VAR,
    _multi_tenant_signals_present,
)

logger = logging.getLogger(__name__)

MCP_TENANT_ENV_VAR: Final = "AGENT_BOM_MCP_TENANT_ID"


def resolve_mcp_tenant_id() -> str:
    """Return the effective tenant id for an MCP tool invocation.

    Resolution order: ``AGENT_BOM_MCP_TENANT_ID`` env (MCP-specific
    override) → ``AGENT_BOM_TENANT_ID`` env (shared with the CLI) →
    ``"default"``. Logs a warning at the fall-through to ``"default"``
    when multi-tenant signals are present so the operator sees the
    assumption in the MCP server log.
    """
    mcp_specific = (os.environ.get(MCP_TENANT_ENV_VAR) or "").strip()
    if mcp_specific:
        return mcp_specific
    shared = (os.environ.get(TENANT_ENV_VAR) or "").strip()
    if shared:
        return shared
    if _multi_tenant_signals_present():
        logger.warning(
            "agent-bom MCP server is using tenant_id=%r as a fallback but the deployment looks multi-tenant. "
            "Set %s on the MCP server process.",
            DEFAULT_TENANT_ID,
            MCP_TENANT_ENV_VAR,
        )
    return DEFAULT_TENANT_ID
