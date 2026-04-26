"""Centralised tenant-id resolution for the CLI and MCP server surfaces.

Closes the "define tenant resolution for CLI and MCP surfaces" half of #1964.

The HTTP control plane derives ``request.state.tenant_id`` from authenticated
identity (API key, OIDC token, SAML assertion, trusted proxy header — see
``agent_bom.api.middleware``). The CLI and the MCP server have no such
authenticated request to pull from, so before this module each call site
read ``AGENT_BOM_TENANT_ID`` (or worse, hard-coded ``"default"``)
independently. That made it easy for a future contributor to forget the env
fallback in one site and silently start writing rows under the wrong tenant.

The contract this module pins:

- The CLI accepts an explicit ``--tenant`` flag (or ``--tenant-id`` where
  already wired). The flag wins.
- Otherwise, ``AGENT_BOM_TENANT_ID`` from the process environment.
- Otherwise, the literal string ``"default"`` — but with an operator-visible
  log line under any signal that the deployment is multi-tenant
  (``AGENT_BOM_REQUIRE_TENANT_BOUNDARY=1`` or
  ``AGENT_BOM_CONTROL_PLANE_REPLICAS > 1``).
- Strict mode (``resolve_cli_tenant_id_strict``) refuses to fall through to
  ``"default"`` when those signals are present — a CLI user must opt into
  the default tenant explicitly. This is the guardrail that stops a CLI
  invocation in a multi-tenant environment from quietly cross-writing.

The MCP server uses the same resolution path (its tools run inside a
process whose tenant context is set by the operator at startup, not by the
caller). See ``src/agent_bom/mcp_tenant.py``.

A ``tests/test_cli_mcp_tenant_resolution.py`` guard scans the codebase and
fails CI if a new ad-hoc ``AGENT_BOM_TENANT_ID`` env read appears outside
this module — the central path is the only sanctioned one.
"""

from __future__ import annotations

import logging
import os
from typing import Final

logger = logging.getLogger(__name__)

DEFAULT_TENANT_ID: Final = "default"
TENANT_ENV_VAR: Final = "AGENT_BOM_TENANT_ID"
_REQUIRE_BOUNDARY_ENV: Final = "AGENT_BOM_REQUIRE_TENANT_BOUNDARY"
_REPLICAS_ENV: Final = "AGENT_BOM_CONTROL_PLANE_REPLICAS"


def _multi_tenant_signals_present() -> bool:
    """Return True when the current process configuration indicates the CLI
    is talking to a multi-tenant control plane. Used by strict mode to
    refuse a silent fall-through to the default tenant.
    """
    if (os.environ.get(_REQUIRE_BOUNDARY_ENV) or "").strip().lower() in {"1", "true", "yes", "on"}:
        return True
    raw = (os.environ.get(_REPLICAS_ENV) or "").strip()
    if raw.isdigit() and int(raw) > 1:
        return True
    return False


def resolve_cli_tenant_id(explicit: str | None = None) -> str:
    """Return the effective tenant id for a CLI invocation.

    Resolution order: explicit ``--tenant`` argument → ``AGENT_BOM_TENANT_ID``
    env → ``"default"``. Logs a one-line warning at the fall-through to
    ``"default"`` when multi-tenant signals are present so the operator sees
    the silent assumption in the build log.
    """
    if explicit and explicit.strip():
        return explicit.strip()
    env_value = (os.environ.get(TENANT_ENV_VAR) or "").strip()
    if env_value:
        return env_value
    if _multi_tenant_signals_present():
        logger.warning(
            "agent-bom CLI is using tenant_id=%r as a fallback but the deployment looks multi-tenant. Set %s explicitly or pass --tenant.",
            DEFAULT_TENANT_ID,
            TENANT_ENV_VAR,
        )
    return DEFAULT_TENANT_ID


def resolve_cli_tenant_id_strict(explicit: str | None = None) -> str:
    """Same as :func:`resolve_cli_tenant_id` but raises ``RuntimeError`` if
    the resolution would fall through to ``"default"`` while multi-tenant
    signals are present. Use this on write paths where a silent default
    would mean cross-tenant data contamination.
    """
    if explicit and explicit.strip():
        return explicit.strip()
    env_value = (os.environ.get(TENANT_ENV_VAR) or "").strip()
    if env_value:
        return env_value
    if _multi_tenant_signals_present():
        raise RuntimeError(
            "agent-bom CLI refuses to default to tenant_id='default' against a multi-tenant "
            f"control plane. Set {TENANT_ENV_VAR} or pass --tenant explicitly."
        )
    return DEFAULT_TENANT_ID
