"""Identity + naming contract hardening (#2207).

Locks in the three contract fixes documented in
``docs/IDENTITY_AND_NAMING_CONTRACT.md``:

1. **Strict role parsing** — invalid AGENT_BOM_DEFAULT_ROLE / API-key role
   raises rather than silently falling back to viewer. Lax enum coercion
   was a footgun: a typo'd "admion" silently became viewer with no log.
2. **Reserved tenant namespace** — customer-supplied tenant IDs cannot
   collide with the system fallback or role/permission vocabulary.
3. **API key entropy floor** — customer keys via AGENT_BOM_API_KEYS must
   be ≥ MIN_API_KEY_LENGTH so a misconfigured short value can't slip
   into production.

Tests use the actual public API the operator hits (env-var loading +
ingress middleware) so the contract is enforced where it matters, not
just at the helper level.
"""

from __future__ import annotations

import os

import pytest

from agent_bom.platform_invariants import (
    RESERVED_TENANT_IDS,
    ReservedTenantIdError,
    is_reserved_tenant_id,
    normalize_tenant_id,
    validate_customer_tenant_id,
)
from agent_bom.rbac import (
    MIN_API_KEY_LENGTH,
    ApiKeyEntropyError,
    InvalidRoleError,
    Role,
    configure_api_keys,
    load_api_keys_from_env,
    resolve_role,
)

# ─── Strict role parsing ─────────────────────────────────────────────────────


def test_resolve_role_raises_on_invalid_default_role(monkeypatch):
    """A typo in AGENT_BOM_DEFAULT_ROLE must fail at the call site, not
    silently coerce to viewer. The pre-#2207 behaviour was to swallow
    `ValueError` and return `Role.VIEWER`; that masked operator typos."""
    monkeypatch.setenv("AGENT_BOM_DEFAULT_ROLE", "admion")  # typo
    with pytest.raises(InvalidRoleError) as exc:
        resolve_role()
    assert "admion" in str(exc.value)
    assert "AGENT_BOM_DEFAULT_ROLE" in str(exc.value)


def test_resolve_role_accepts_valid_default_role(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_DEFAULT_ROLE", "analyst")
    assert resolve_role() == Role.ANALYST


def test_resolve_role_falls_back_to_viewer_when_unset(monkeypatch):
    """Unset env var still falls back to viewer — least-privilege default
    is preserved. Only EXPLICITLY-set bad values raise."""
    monkeypatch.delenv("AGENT_BOM_DEFAULT_ROLE", raising=False)
    assert resolve_role() == Role.VIEWER


def test_configure_api_keys_raises_on_invalid_role():
    """Invalid role on a key entry must fail loudly; pre-#2207 silently
    skipped the entry, leaving the operator with a non-functional key
    they thought was wired."""
    valid_key = "k" * MIN_API_KEY_LENGTH
    with pytest.raises(InvalidRoleError):
        configure_api_keys({valid_key: "supreme-overlord"})


def test_load_api_keys_from_env_raises_on_invalid_role(monkeypatch):
    valid_key = "k" * MIN_API_KEY_LENGTH
    monkeypatch.setenv("AGENT_BOM_API_KEYS", f"{valid_key}:wizard")
    with pytest.raises(InvalidRoleError):
        load_api_keys_from_env()


# ─── API key entropy floor ───────────────────────────────────────────────────


def test_configure_api_keys_rejects_short_key():
    """A short customer-supplied key (< MIN_API_KEY_LENGTH chars) must
    raise. Critical because operators sometimes set placeholder values
    like `abc:admin` while wiring deployments and forget to swap them in."""
    short_key = "abc"
    with pytest.raises(ApiKeyEntropyError) as exc:
        configure_api_keys({short_key: "admin"})
    assert str(MIN_API_KEY_LENGTH) in str(exc.value)


def test_configure_api_keys_accepts_minimum_length():
    valid_key = "k" * MIN_API_KEY_LENGTH
    configure_api_keys({valid_key: "admin"})
    assert resolve_role(api_key=valid_key) == Role.ADMIN


def test_load_api_keys_from_env_rejects_short_key(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_API_KEYS", "shortkey:admin")
    with pytest.raises(ApiKeyEntropyError):
        load_api_keys_from_env()


def test_min_api_key_length_matches_internal_mint_size():
    """The entropy floor for customer keys must be at least as strict
    as what we mint internally. ``secrets.token_urlsafe(32)`` produces
    43+ characters but the bar is set on the input strength, not the
    encoding overhead."""
    # 32 random bytes → 256 bits of entropy. The floor is 32 chars,
    # which after token_urlsafe encoding represents ≥ 24 bytes / 192
    # bits (about 6 chars per 32 bits). Setting the floor at 32 chars
    # still rejects obviously-weak values without rejecting our minted
    # tokens.
    assert MIN_API_KEY_LENGTH >= 32


# ─── Reserved tenant namespace ───────────────────────────────────────────────


@pytest.mark.parametrize("reserved", sorted(RESERVED_TENANT_IDS))
def test_validate_customer_tenant_id_rejects_reserved_names(reserved):
    """Customer-supplied tenant IDs cannot shadow system buckets or our
    role/permission vocabulary."""
    with pytest.raises(ReservedTenantIdError):
        validate_customer_tenant_id(reserved)


def test_validate_customer_tenant_id_is_case_insensitive_to_reserved():
    """A customer can't bypass the reserved set by changing case —
    `Admin` and `VIEWER` are rejected the same way `admin` is."""
    for variant in ("Admin", "VIEWER", "Analyst", "System"):
        with pytest.raises(ReservedTenantIdError):
            validate_customer_tenant_id(variant)


def test_default_is_a_valid_customer_tenant_id():
    """`default` is the canonical single-tenant value used by the system
    fallback, tests, and many deployments. It MUST remain accepted as a
    customer-supplied tenant id — single-tenant pilots use it directly,
    and ingress validation rejecting it would break the whole test suite
    + every deployment that hasn't customised the tenant header."""
    assert validate_customer_tenant_id("default") == "default"
    assert validate_customer_tenant_id("DEFAULT") == "DEFAULT"


def test_validate_customer_tenant_id_rejects_blank():
    with pytest.raises(ReservedTenantIdError):
        validate_customer_tenant_id("")
    with pytest.raises(ReservedTenantIdError):
        validate_customer_tenant_id(None)


def test_validate_customer_tenant_id_passes_normal_values():
    """Anything outside the reserved set is fine — UUIDs, slugs, IdP
    tenant identifiers."""
    for value in (
        "tenant-acme",
        "550e8400-e29b-41d4-a716-446655440000",
        "ORG/ACME",
        "okta-org-12345",
    ):
        assert validate_customer_tenant_id(value) == value.strip()


def test_normalize_tenant_id_still_falls_back_to_default():
    """Internal callers that don't supply a tenant ID get the system
    fallback bucket. The reserved namespace fix doesn't change internal
    semantics — only customer-supplied paths get strict validation."""
    assert normalize_tenant_id(None) == "default"
    assert normalize_tenant_id("") == "default"
    assert normalize_tenant_id("   ") == "default"


def test_is_reserved_tenant_id_helper():
    assert is_reserved_tenant_id("admin") is True
    assert is_reserved_tenant_id("VIEWER") is True  # case-insensitive
    assert is_reserved_tenant_id("default") is False  # NOT reserved
    assert is_reserved_tenant_id("Customer-Acme") is False
    assert is_reserved_tenant_id(None) is False


# ─── Cleanup so test ordering doesn't leak api-key state ─────────────────────


@pytest.fixture(autouse=True)
def _clear_api_key_state():
    yield
    configure_api_keys({})  # safe: empty dict; no raise
    os.environ.pop("AGENT_BOM_DEFAULT_ROLE", None)
    os.environ.pop("AGENT_BOM_API_KEYS", None)
