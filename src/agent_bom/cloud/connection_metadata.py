"""Provider-owned public connection metadata; credentials belong in the broker.

Unknown fields fail closed on writes and are omitted from legacy public reads.
This is not a credential classifier: callers must never place secrets in public
identifier fields. Recognizable credential payloads are rejected defensively.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_bom.security import sanitize_text

_COMMON_FIELDS = frozenset({"inventory_scope"})
_PROVIDER_FIELDS: dict[str, frozenset[str]] = {
    "aws": frozenset({"member_role_name"}),
    "azure": frozenset({"tenant_id", "subscription_id", "auth_mode", "credential_binding"}),
    "gcp": frozenset({"project_id", "auth_mode", "credential_binding"}),
    "snowflake": frozenset({"account", "user", "role", "warehouse", "auth_mode", "credential_binding"}),
    "database": frozenset({"engine", "database", "schemas", "include_tables", "publicly_accessible"}),
}


def public_connection_param(provider: str, key: str, value: Any) -> bool:
    """Whether one field may be persisted or exposed as public configuration."""
    if key not in _PROVIDER_FIELDS.get(provider, frozenset()) | _COMMON_FIELDS or not isinstance(value, str):
        return False
    if any(char in value for char in ("\n", "\r", "\x00", "{", "}")):
        return False
    if "-----BEGIN" in value.upper() or value.lower().startswith("bearer "):
        return False
    return sanitize_text(value) == value


def public_connection_params(provider: str, params: Mapping[str, Any]) -> dict[str, str]:
    """Project legacy records without rewriting or exposing retained secrets."""
    return {key: value for key, value in params.items() if public_connection_param(provider, key, value)}
