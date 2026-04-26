"""Stable MCP error envelope for tool returns.

Closes #1960 (the "stable error codes" piece). Every MCP tool that returns a
JSON-serialised error to the client now flows through ``mcp_error_payload``
or ``mcp_error_json`` so clients can branch on a stable ``code``/``category``
pair instead of substring-matching on a free-form ``error`` string.

The envelope shape is:

    {
        "error": {
            "code": "AGENTBOM_MCP_VALIDATION_INVALID_ECOSYSTEM",
            "category": "validation",
            "message": "Invalid ecosystem: 'foo'. Valid: ...",
            "details": {...optional, omitted when empty...}
        }
    }

- ``code`` is a stable, machine-readable identifier. The ``AGENTBOM_MCP_``
  prefix keeps it distinct from JSON-RPC framework codes and from MCP
  protocol-level errors. Codes are versioned by the MCP_ERROR_VERSION
  constant; clients can pin against ``error.code`` directly.
- ``category`` lets clients build catch-all branches (auth, validation,
  timeout, upstream, rate_limited, not_found, unsupported, internal)
  without enumerating every code.
- ``message`` carries the operator-readable text; it has already been run
  through ``agent_bom.security.sanitize_error`` so it's safe to log.
- ``details`` is an optional dict for structured context (offending value,
  retry-after seconds, upstream provider name, etc.).

The companion human-readable reference + API-to-MCP parity matrix lives in
``docs/MCP_ERROR_CODES.md``.
"""

from __future__ import annotations

import json
from typing import Any, Final

from agent_bom.security import sanitize_error

MCP_ERROR_VERSION: Final = 1

# ── Categories (stable) ─────────────────────────────────────────────────────
CATEGORY_VALIDATION: Final = "validation"
CATEGORY_AUTH: Final = "auth"
CATEGORY_TIMEOUT: Final = "timeout"
CATEGORY_UPSTREAM: Final = "upstream"
CATEGORY_RATE_LIMITED: Final = "rate_limited"
CATEGORY_NOT_FOUND: Final = "not_found"
CATEGORY_UNSUPPORTED: Final = "unsupported"
CATEGORY_INTERNAL: Final = "internal"

_VALID_CATEGORIES: frozenset[str] = frozenset(
    {
        CATEGORY_VALIDATION,
        CATEGORY_AUTH,
        CATEGORY_TIMEOUT,
        CATEGORY_UPSTREAM,
        CATEGORY_RATE_LIMITED,
        CATEGORY_NOT_FOUND,
        CATEGORY_UNSUPPORTED,
        CATEGORY_INTERNAL,
    }
)

# ── Codes (stable, ``AGENTBOM_MCP_*``) ──────────────────────────────────────
# Validation (bad input, malformed argument).
CODE_VALIDATION_INVALID_ARGUMENT: Final = "AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT"
CODE_VALIDATION_INVALID_PATH: Final = "AGENTBOM_MCP_VALIDATION_INVALID_PATH"
CODE_VALIDATION_INVALID_ECOSYSTEM: Final = "AGENTBOM_MCP_VALIDATION_INVALID_ECOSYSTEM"
CODE_VALIDATION_INVALID_VULN_ID: Final = "AGENTBOM_MCP_VALIDATION_INVALID_VULN_ID"
CODE_VALIDATION_INVALID_IMAGE_REF: Final = "AGENTBOM_MCP_VALIDATION_INVALID_IMAGE_REF"
CODE_VALIDATION_MISSING_REQUIRED: Final = "AGENTBOM_MCP_VALIDATION_MISSING_REQUIRED"
# Auth.
CODE_AUTH_REQUIRED: Final = "AGENTBOM_MCP_AUTH_REQUIRED"
CODE_AUTH_FORBIDDEN: Final = "AGENTBOM_MCP_AUTH_FORBIDDEN"
# Rate limit / concurrency caps.
CODE_RATE_LIMITED_CALLER: Final = "AGENTBOM_MCP_RATE_LIMITED_CALLER"
CODE_RATE_LIMITED_CONCURRENCY: Final = "AGENTBOM_MCP_RATE_LIMITED_CONCURRENCY"
# Timeout.
CODE_TIMEOUT_TOOL: Final = "AGENTBOM_MCP_TIMEOUT_TOOL"
CODE_TIMEOUT_UPSTREAM: Final = "AGENTBOM_MCP_TIMEOUT_UPSTREAM"
# Upstream (OSV, registry, cloud provider, MCP introspection target).
CODE_UPSTREAM_UNAVAILABLE: Final = "AGENTBOM_MCP_UPSTREAM_UNAVAILABLE"
CODE_UPSTREAM_BAD_RESPONSE: Final = "AGENTBOM_MCP_UPSTREAM_BAD_RESPONSE"
# Not found.
CODE_NOT_FOUND_RESOURCE: Final = "AGENTBOM_MCP_NOT_FOUND_RESOURCE"
CODE_NOT_FOUND_AGENTS: Final = "AGENTBOM_MCP_NOT_FOUND_AGENTS"
# Unsupported request shape (analytics backend not configured, etc.).
CODE_UNSUPPORTED_BACKEND: Final = "AGENTBOM_MCP_UNSUPPORTED_BACKEND"
CODE_UNSUPPORTED_QUERY_TYPE: Final = "AGENTBOM_MCP_UNSUPPORTED_QUERY_TYPE"
# Internal — server bug, unhandled error path.
CODE_INTERNAL_UNEXPECTED: Final = "AGENTBOM_MCP_INTERNAL_UNEXPECTED"

# Code → category mapping. New codes MUST be added here so clients building a
# category-only catch can rely on this surface.
_CODE_CATEGORY: Final[dict[str, str]] = {
    CODE_VALIDATION_INVALID_ARGUMENT: CATEGORY_VALIDATION,
    CODE_VALIDATION_INVALID_PATH: CATEGORY_VALIDATION,
    CODE_VALIDATION_INVALID_ECOSYSTEM: CATEGORY_VALIDATION,
    CODE_VALIDATION_INVALID_VULN_ID: CATEGORY_VALIDATION,
    CODE_VALIDATION_INVALID_IMAGE_REF: CATEGORY_VALIDATION,
    CODE_VALIDATION_MISSING_REQUIRED: CATEGORY_VALIDATION,
    CODE_AUTH_REQUIRED: CATEGORY_AUTH,
    CODE_AUTH_FORBIDDEN: CATEGORY_AUTH,
    CODE_RATE_LIMITED_CALLER: CATEGORY_RATE_LIMITED,
    CODE_RATE_LIMITED_CONCURRENCY: CATEGORY_RATE_LIMITED,
    CODE_TIMEOUT_TOOL: CATEGORY_TIMEOUT,
    CODE_TIMEOUT_UPSTREAM: CATEGORY_TIMEOUT,
    CODE_UPSTREAM_UNAVAILABLE: CATEGORY_UPSTREAM,
    CODE_UPSTREAM_BAD_RESPONSE: CATEGORY_UPSTREAM,
    CODE_NOT_FOUND_RESOURCE: CATEGORY_NOT_FOUND,
    CODE_NOT_FOUND_AGENTS: CATEGORY_NOT_FOUND,
    CODE_UNSUPPORTED_BACKEND: CATEGORY_UNSUPPORTED,
    CODE_UNSUPPORTED_QUERY_TYPE: CATEGORY_UNSUPPORTED,
    CODE_INTERNAL_UNEXPECTED: CATEGORY_INTERNAL,
}


def category_for(code: str) -> str:
    """Return the category for a stable error code, defaulting to ``internal``.

    Unknown codes route to ``internal`` so a typo by a tool author surfaces as
    a server-side bug to clients rather than crashing the response builder.
    """
    return _CODE_CATEGORY.get(code, CATEGORY_INTERNAL)


def known_codes() -> tuple[str, ...]:
    """Return the sorted tuple of all registered stable codes."""
    return tuple(sorted(_CODE_CATEGORY))


def known_categories() -> tuple[str, ...]:
    """Return the sorted tuple of all registered categories."""
    return tuple(sorted(_VALID_CATEGORIES))


def mcp_error_payload(
    code: str,
    message: str | Exception,
    *,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the canonical ``{"error": {...}}`` envelope as a Python dict.

    ``message`` may be a string or an exception. Exceptions are funnelled
    through :func:`agent_bom.security.sanitize_error` so file paths, URLs,
    and other sensitive substrings are stripped before they reach the wire.
    """

    sanitized = sanitize_error(message) if isinstance(message, Exception) else str(message)
    error: dict[str, Any] = {
        "code": code,
        "category": category_for(code),
        "message": sanitized,
    }
    if details:
        error["details"] = details
    return {"error": error, "schema_version": MCP_ERROR_VERSION}


def mcp_error_json(
    code: str,
    message: str | Exception,
    *,
    details: dict[str, Any] | None = None,
) -> str:
    """Return :func:`mcp_error_payload` already JSON-serialised."""
    return json.dumps(mcp_error_payload(code, message, details=details))
