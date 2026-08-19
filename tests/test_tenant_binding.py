from __future__ import annotations

import hashlib
import hmac

import pytest


def test_tenant_binding_claim_is_deterministic_and_tamper_evident(monkeypatch):
    from agent_bom.api.tenant_binding import issue_tenant_binding_claim, verify_tenant_binding_claim

    key = "k" * 32
    monkeypatch.setenv("AGENT_BOM_TENANT_BINDING_KEY", key)
    claim = issue_tenant_binding_claim("tenant-a", issued_at=1_800_000_000, nonce="ab" * 16)

    canonical = f"v1:{'tenant-a'.encode().hex()}:1800000000:{'ab' * 16}"
    expected = hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    assert claim.canonical == canonical
    assert claim.signature == expected
    assert verify_tenant_binding_claim(claim, now=1_800_000_010)
    assert not verify_tenant_binding_claim(claim.with_tenant_id("tenant-b"), now=1_800_000_010)


def test_tenant_binding_has_no_ephemeral_or_short_key_fallback(monkeypatch):
    from agent_bom.api.tenant_binding import TenantBindingConfigurationError, tenant_binding_keys

    monkeypatch.delenv("AGENT_BOM_TENANT_BINDING_KEY", raising=False)
    monkeypatch.delenv("AGENT_BOM_TENANT_BINDING_KEY_FILE", raising=False)
    with pytest.raises(TenantBindingConfigurationError, match="required"):
        tenant_binding_keys()

    monkeypatch.setenv("AGENT_BOM_TENANT_BINDING_KEY", "too-short")
    with pytest.raises(TenantBindingConfigurationError, match="at least 32 bytes"):
        tenant_binding_keys()


def test_tenant_binding_accepts_primary_and_rotation_verification_keys(monkeypatch):
    from agent_bom.api.tenant_binding import issue_tenant_binding_claim, tenant_binding_keys, verify_tenant_binding_claim

    old_key = "o" * 32
    new_key = "n" * 32
    monkeypatch.setenv("AGENT_BOM_TENANT_BINDING_KEY", f"{new_key},{old_key}")
    assert tenant_binding_keys() == (new_key.encode(), old_key.encode())

    claim = issue_tenant_binding_claim("default", issued_at=1_800_000_000, nonce="cd" * 16, key=old_key.encode())
    assert verify_tenant_binding_claim(claim, now=1_800_000_001)


@pytest.mark.parametrize("now", [1_799_999_969, 1_800_000_031])
def test_tenant_binding_rejects_claims_outside_bounded_time_window(monkeypatch, now):
    from agent_bom.api.tenant_binding import issue_tenant_binding_claim, verify_tenant_binding_claim

    monkeypatch.setenv("AGENT_BOM_TENANT_BINDING_KEY", "k" * 32)
    claim = issue_tenant_binding_claim("tenant-a", issued_at=1_800_000_000, nonce="ef" * 16)
    assert not verify_tenant_binding_claim(claim, now=now, max_age_seconds=30, max_future_skew_seconds=30)


def test_tenant_binding_rejects_reserved_tenant_identity(monkeypatch):
    from agent_bom.api.tenant_binding import issue_tenant_binding_claim
    from agent_bom.platform_invariants import ReservedTenantIdError

    monkeypatch.setenv("AGENT_BOM_TENANT_BINDING_KEY", "k" * 32)
    with pytest.raises(ReservedTenantIdError):
        issue_tenant_binding_claim("admin", issued_at=1_800_000_000, nonce="12" * 16)
