"""Shared platform record invariants.

These helpers keep tenant- and time-bearing records consistent across fleet,
gateway/discovery provenance, and later graph/event consumers.
"""

from __future__ import annotations

from datetime import datetime, timezone


def now_utc_iso() -> str:
    """Return the current UTC timestamp as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


# Tenant identifier contract — agent-bom owns a small reserved namespace;
# everything else is the customer's. See docs/IDENTITY_AND_NAMING_CONTRACT.md.
#
# `default` is the system fallback for unset/blank tenant identifiers (single-
# tenant deployments + tests rely on it). Other reserved names are kept
# in sync with role/permission vocabulary so a customer can't shadow our
# enums by accident.
RESERVED_TENANT_IDS: frozenset[str] = frozenset(
    {
        "default",
        "system",
        "admin",
        "analyst",
        "viewer",
        "__system__",
    }
)


class ReservedTenantIdError(ValueError):
    """Raised when a customer-supplied tenant id collides with a reserved name."""


def normalize_tenant_id(value: str | None) -> str:
    """Return a canonical tenant id, falling back to ``default``.

    Used everywhere the system needs to bucket tenant-scoped state. The
    ``default`` fallback is the documented system-tenant for unset / blank
    inputs (single-node demos, tests, single-tenant pilots). For any
    customer-supplied tenant identifier (HTTP header, JWT claim, SCIM
    payload), prefer ``validate_customer_tenant_id`` first so the value
    can't shadow this fallback.
    """
    tenant_id = (value or "").strip()
    return tenant_id or "default"


def is_reserved_tenant_id(tenant_id: str | None) -> bool:
    """Return True if ``tenant_id`` is in the reserved namespace.

    The namespace is intentionally small (``RESERVED_TENANT_IDS``); it
    covers our role + permission vocabulary plus the `default` fallback
    so customer-supplied identifiers can't collide with system buckets.
    """
    return (tenant_id or "").strip().lower() in RESERVED_TENANT_IDS


def validate_customer_tenant_id(value: str | None) -> str:
    """Normalise a customer-supplied tenant id and reject reserved names.

    Use at the API ingress (HTTP header, JWT claim, SCIM payload) where a
    customer is asserting *their* identifier. A blank value raises so the
    caller can't accidentally land in the system fallback bucket — pass
    that through ``normalize_tenant_id`` if the system default is what
    you want.

    Raises:
        ReservedTenantIdError: when the supplied value is empty or
            collides with ``RESERVED_TENANT_IDS``.
    """
    tenant_id = (value or "").strip()
    if not tenant_id:
        raise ReservedTenantIdError(
            "tenant id is required for customer-supplied identity; use normalize_tenant_id() to fall back to the system default"
        )
    if is_reserved_tenant_id(tenant_id):
        raise ReservedTenantIdError(
            f"tenant id {tenant_id!r} is reserved by agent-bom and cannot "
            f"be used as a customer identifier. Reserved names: "
            f"{sorted(RESERVED_TENANT_IDS)}."
        )
    return tenant_id


def normalize_timestamp(value: str | None) -> str | None:
    """Return a canonical UTC ISO-8601 timestamp.

    Blank values stay ``None``. Naive timestamps are treated as UTC.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    normalized = parsed.isoformat()
    if normalized.endswith("+00:00"):
        return f"{normalized[:-6]}Z"
    return normalized
