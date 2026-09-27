"""Explicit tenant identity for authenticated requests and tenant-bound work."""

from __future__ import annotations


def require_explicit_tenant_id(value: object) -> str:
    """Validate an established tenant without inventing a single-tenant fallback.

    Authentication/bootstrap may deliberately select ``default``. Once that
    boundary has established an identity, missing or malformed context is an
    error, never authority to access the default tenant.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("An explicit non-empty tenant id is required")
    return value.strip()
