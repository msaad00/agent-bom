"""Tamper-evident claims for binding a Postgres transaction to one tenant.

The application role is shared across tenants, so an arbitrary custom Postgres
GUC cannot be the database identity boundary: unprivileged sessions may set
two-part custom parameters directly.  These claims are the application-side
primitive for the database-enforced binding authority.  The database contract
is added separately so each stage can be reviewed and rolled out safely.

There is intentionally no ephemeral-key fallback.  A process that cannot
produce a claim verifiable by every Postgres replica must fail closed instead
of silently reverting to self-asserted tenant identity.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, replace

from agent_bom.api.secret_source import resolve_secret
from agent_bom.platform_invariants import validate_customer_tenant_id

_TENANT_BINDING_KEY_ENV = "AGENT_BOM_TENANT_BINDING_KEY"
_MINIMUM_KEY_BYTES = 32
_CLAIM_VERSION = 1


class TenantBindingConfigurationError(ValueError):
    """Raised when the durable tenant-binding key is absent or unsafe."""


@dataclass(frozen=True, slots=True)
class TenantBindingClaim:
    """A short-lived signed request to bind one DB transaction to a tenant."""

    tenant_id: str
    issued_at: int
    nonce: str
    signature: str
    version: int = _CLAIM_VERSION

    @property
    def canonical(self) -> str:
        """Return the language-neutral message authenticated by the claim."""
        tenant_hex = self.tenant_id.encode("utf-8").hex()
        return f"v{self.version}:{tenant_hex}:{self.issued_at}:{self.nonce}"

    def with_tenant_id(self, tenant_id: str) -> TenantBindingClaim:
        """Return a copy used by verifiers/tests to model tenant tampering."""
        return replace(self, tenant_id=tenant_id)


def _validate_key(key: bytes) -> bytes:
    if len(key) < _MINIMUM_KEY_BYTES:
        raise TenantBindingConfigurationError(
            f"{_TENANT_BINDING_KEY_ENV} entries must be at least {_MINIMUM_KEY_BYTES} bytes"
        )
    return key


def tenant_binding_keys() -> tuple[bytes, ...]:
    """Return durable tenant-binding keys, primary first for safe rotation."""
    try:
        configured = resolve_secret(_TENANT_BINDING_KEY_ENV, required=True)
    except ValueError as exc:
        raise TenantBindingConfigurationError(
            f"{_TENANT_BINDING_KEY_ENV} or {_TENANT_BINDING_KEY_ENV}_FILE is required"
        ) from exc

    keys = tuple(_validate_key(chunk.strip().encode("utf-8")) for chunk in configured.split(",") if chunk.strip())
    if not keys:
        raise TenantBindingConfigurationError(
            f"{_TENANT_BINDING_KEY_ENV} or {_TENANT_BINDING_KEY_ENV}_FILE is required"
        )
    return keys


def _validate_nonce(nonce: str) -> str:
    normalized = nonce.strip().lower()
    if len(normalized) != 32:
        raise ValueError("tenant-binding nonce must be 16 bytes encoded as 32 hexadecimal characters")
    try:
        bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError("tenant-binding nonce must contain only hexadecimal characters") from exc
    return normalized


def issue_tenant_binding_claim(
    tenant_id: str,
    *,
    issued_at: int | None = None,
    nonce: str | None = None,
    key: bytes | None = None,
) -> TenantBindingClaim:
    """Sign a bounded tenant-binding claim using the primary durable key."""
    normalized_tenant = validate_customer_tenant_id(tenant_id)
    signing_key = _validate_key(key) if key is not None else tenant_binding_keys()[0]
    claim = TenantBindingClaim(
        tenant_id=normalized_tenant,
        issued_at=int(time.time()) if issued_at is None else int(issued_at),
        nonce=_validate_nonce(nonce or secrets.token_hex(16)),
        signature="",
    )
    signature = hmac.new(signing_key, claim.canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return replace(claim, signature=signature)


def verify_tenant_binding_claim(
    claim: TenantBindingClaim,
    *,
    now: int | None = None,
    max_age_seconds: int = 30,
    max_future_skew_seconds: int = 30,
    keys: tuple[bytes, ...] | None = None,
) -> bool:
    """Verify signature, shape, tenant namespace, and the bounded time window."""
    current_time = int(time.time()) if now is None else int(now)
    if max_age_seconds < 0 or max_future_skew_seconds < 0:
        raise ValueError("tenant-binding time windows must be non-negative")
    if claim.version != _CLAIM_VERSION:
        return False
    if current_time - claim.issued_at > max_age_seconds:
        return False
    if claim.issued_at - current_time > max_future_skew_seconds:
        return False
    try:
        validate_customer_tenant_id(claim.tenant_id)
        _validate_nonce(claim.nonce)
        if len(claim.signature) != 64:
            return False
        bytes.fromhex(claim.signature)
    except ValueError:
        return False

    verification_keys = keys if keys is not None else tenant_binding_keys()
    for candidate in verification_keys:
        expected = hmac.new(_validate_key(candidate), claim.canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        if hmac.compare_digest(claim.signature, expected):
            return True
    return False
