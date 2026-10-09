"""Shared Snowflake discovery helpers: identifiers, coercion, failure evidence, façade resolution."""

from __future__ import annotations

import importlib
import json
import logging
import re
from types import ModuleType
from typing import Any

from .aws_inventory import record_discovery_failure
from .normalization import (
    coerce_int_or_none,
    coerce_truthy,
    resolve_env_or_value,
    sanitize_discovery_warning,
)

# Log under the façade's logger so existing log routing and filters keep applying.
logger = logging.getLogger("agent_bom.cloud.snowflake")


def _sf() -> ModuleType:
    """Resolve the ``agent_bom.cloud.snowflake`` façade at call time.

    Names callers and tests patch on the façade (``_get_connection`` and friends)
    must keep steering code that now lives in sibling modules."""
    return importlib.import_module("agent_bom.cloud.snowflake")


# Security-relevant Snowflake inventory surfaces that must never fail silently.
_SNOWFLAKE_INVENTORY_FAILURES: dict[str, str] = {
    "cortex_agents": "SHOW AGENTS IN ACCOUNT",
    "mcp_servers": "SHOW MCP SERVERS IN ACCOUNT",
    "grants_to_roles": "SELECT on SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES",
    "grants_to_users": "SELECT on SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS",
    "live_role_grants": "SHOW GRANTS TO/OF ROLE",
}


def _record_snowflake_inventory_failure(
    *,
    exc: BaseException,
    resource_type: str,
    inventory_key: str,
    warnings: list[str],
    missing: list[dict[str, str]] | None = None,
) -> None:
    """Translate a failed Snowflake inventory read into warnings + coverage evidence."""
    permission = _SNOWFLAKE_INVENTORY_FAILURES.get(inventory_key, inventory_key)
    record_discovery_failure(
        exc=exc,
        resource_type=resource_type,
        permission=permission,
        cloud="snowflake",
        warnings=warnings,
        missing=missing,
    )
    try:
        from agent_bom.coverage import CoverageWarning
        from agent_bom.scanners.state import record_coverage_warning

        record_coverage_warning(
            CoverageWarning(
                ecosystem="snowflake",
                release=f"snowflake:{inventory_key}",
                reason="inventory_evaluation_failed",
                detail=sanitize_discovery_warning(exc),
                package_count=0,
                advisory_rows=0,
            ).to_dict()
        )
    except Exception:  # noqa: BLE001 — coverage evidence is supplementary; never fail discovery
        logger.debug("Could not record Snowflake inventory coverage warning", exc_info=False)


# Backwards-compatible aliases for the shared cloud helpers. Call sites and
# tests may reference either the shared public names or these private aliases.
_env_or_value = resolve_env_or_value
_sf_truthy = coerce_truthy
_coerce_int_or_none = coerce_int_or_none


# Snowflake identifier safety: only allow alphanumeric, underscore, dot, dollar
_SAFE_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.$]*$")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1F\x7F]")


def _validate_sf_identifier(name: str) -> str:
    """Validate a Snowflake identifier against injection."""
    if not _SAFE_IDENT_RE.match(name):
        raise ValueError(f"Unsafe Snowflake identifier: {name!r}")
    return name


def _quote_sf_identifier(name: str) -> str:
    """Safely quote a Snowflake identifier for SQL interpolation.

    Unlike ``_validate_sf_identifier`` this supports legitimate quoted
    identifiers such as notebook names containing spaces while still
    preventing statement-breaking injection.
    """
    if not isinstance(name, str) or not name:
        raise ValueError("Snowflake identifier must be a non-empty string")
    if _CONTROL_CHAR_RE.search(name):
        raise ValueError(f"Unsafe Snowflake identifier: {name!r}")
    return '"' + name.replace('"', '""') + '"'


def _coerce_snowflake_days(days: Any, *, max_days: int | None = None) -> int:
    """Validate and normalize day-window inputs used in SQL interpolation."""
    try:
        value = int(days)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"days must be an integer, got {days!r}") from exc
    if value < 1:
        raise ValueError(f"days must be >= 1, got {value!r}")
    if max_days is not None:
        value = min(value, max_days)
    return value


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_json_field(value: Any) -> list[dict]:
    """Parse a JSON-encoded field that may be a string, list, or None."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, TypeError):
            return []
    return []


def _parse_json_object(value: Any) -> dict:
    """Parse a JSON-encoded object field that may be a string, dict, or None."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}
