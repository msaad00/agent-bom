"""Role-based access control (RBAC) and API key management.

Provides API key creation, verification, and role-based endpoint protection
for enterprise deployments.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Protocol


class Role(str, Enum):
    """User roles for RBAC."""

    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# Role hierarchy: admin > analyst > viewer
_ROLE_HIERARCHY: dict[Role, int] = {
    Role.ADMIN: 3,
    Role.ANALYST: 2,
    Role.VIEWER: 1,
}


@dataclass
class ApiKey:
    """Stored API key metadata (the raw key is never stored)."""

    key_id: str
    key_hash: str  # scrypt KDF of the raw key
    key_salt: str  # hex-encoded salt for scrypt
    key_prefix: str  # First 8 chars for identification
    name: str
    role: Role
    created_at: str = ""
    expires_at: str | None = None
    scopes: list[str] = field(default_factory=list)
    tenant_id: str = "default"

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc).isoformat() > self.expires_at

    def has_role(self, required: Role) -> bool:
        """Check if this key's role meets or exceeds the required role."""
        return _ROLE_HIERARCHY.get(self.role, 0) >= _ROLE_HIERARCHY.get(required, 0)

    def to_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "key_prefix": self.key_prefix,
            "name": self.name,
            "role": self.role.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "scopes": self.scopes,
            "tenant_id": self.tenant_id,
        }


@dataclass(frozen=True)
class ApiKeyPolicy:
    """Operator-controlled API key lifetime policy."""

    default_ttl_seconds: int = 30 * 24 * 60 * 60
    max_ttl_seconds: int = 90 * 24 * 60 * 60


def get_api_key_policy() -> ApiKeyPolicy:
    """Load API key lifetime policy from env with safe defaults."""
    default_ttl = int(os.environ.get("AGENT_BOM_API_KEY_DEFAULT_TTL_SECONDS", str(30 * 24 * 60 * 60)))
    max_ttl = int(os.environ.get("AGENT_BOM_API_KEY_MAX_TTL_SECONDS", str(90 * 24 * 60 * 60)))
    if default_ttl <= 0:
        raise ValueError("AGENT_BOM_API_KEY_DEFAULT_TTL_SECONDS must be > 0")
    if max_ttl <= 0:
        raise ValueError("AGENT_BOM_API_KEY_MAX_TTL_SECONDS must be > 0")
    if default_ttl > max_ttl:
        raise ValueError("AGENT_BOM_API_KEY_DEFAULT_TTL_SECONDS cannot exceed AGENT_BOM_API_KEY_MAX_TTL_SECONDS")
    return ApiKeyPolicy(default_ttl_seconds=default_ttl, max_ttl_seconds=max_ttl)


def normalize_api_key_expiry(
    expires_at: str | None,
    *,
    now: datetime | None = None,
    policy: ApiKeyPolicy | None = None,
) -> str:
    """Normalize and enforce API key expiry under the configured policy."""
    active_policy = policy or get_api_key_policy()
    current = now or datetime.now(timezone.utc)
    if expires_at:
        try:
            parsed = datetime.fromisoformat(expires_at)
        except ValueError as exc:
            raise ValueError("expires_at must be a valid ISO-8601 datetime with timezone") from exc
        if parsed.tzinfo is None:
            raise ValueError("expires_at must include timezone information")
        if parsed <= current:
            raise ValueError("expires_at must be in the future")
        max_expiry = current + timedelta(seconds=active_policy.max_ttl_seconds)
        if parsed > max_expiry:
            raise ValueError(f"expires_at exceeds the maximum allowed API key lifetime ({active_policy.max_ttl_seconds} seconds)")
        return parsed.isoformat()
    return (current + timedelta(seconds=active_policy.default_ttl_seconds)).isoformat()


def _derive_key(raw_key: str, salt: bytes) -> str:
    """Derive key hash using scrypt KDF (CodeQL-safe, brute-force resistant)."""
    derived = hashlib.scrypt(
        raw_key.encode(),
        salt=salt,
        n=16384,  # CPU/memory cost (2^14)
        r=8,  # block size
        p=1,  # parallelization
        dklen=32,
    )
    return derived.hex()


def create_api_key(
    name: str,
    role: Role,
    expires_at: str | None = None,
    scopes: list[str] | None = None,
    tenant_id: str = "default",
) -> tuple[str, ApiKey]:
    """Generate a new API key.

    Returns (raw_key, api_key_record). The raw key is only returned once
    and should be given to the user. Only the scrypt-derived hash is stored.
    """
    raw_key = f"abom_{secrets.token_urlsafe(32)}"
    salt = os.urandom(16)
    key_hash = _derive_key(raw_key, salt)
    key_id = secrets.token_hex(8)

    normalized_expiry = normalize_api_key_expiry(expires_at)
    api_key = ApiKey(
        key_id=key_id,
        key_hash=key_hash,
        key_salt=salt.hex(),
        key_prefix=raw_key[:12],
        name=name,
        role=role,
        expires_at=normalized_expiry,
        scopes=scopes or [],
        tenant_id=tenant_id,
    )
    return raw_key, api_key


def verify_api_key(raw_key: str, stored_keys: list[ApiKey]) -> ApiKey | None:
    """Verify a raw API key against stored keys.

    Uses scrypt KDF with per-key salt and constant-time comparison.
    Returns the matching ApiKey if found and not expired, else None.
    """
    key_prefix = raw_key[:12]
    candidates = [stored for stored in stored_keys if stored.key_prefix == key_prefix]
    for stored in candidates:
        salt = bytes.fromhex(stored.key_salt)
        candidate = _derive_key(raw_key, salt)
        if hmac.compare_digest(stored.key_hash, candidate):
            if stored.is_expired():
                return None
            return stored
    return None


# ---------------------------------------------------------------------------
# Key store (in-memory singleton)
# ---------------------------------------------------------------------------


class KeyStore:
    """Thread-safe in-memory API key store."""

    def __init__(self) -> None:
        self._keys: list[ApiKey] = []
        self._lock = threading.Lock()

    def add(self, key: ApiKey) -> None:
        with self._lock:
            self._keys.append(key)

    def remove(self, key_id: str) -> bool:
        with self._lock:
            before = len(self._keys)
            self._keys = [k for k in self._keys if k.key_id != key_id]
            return len(self._keys) < before

    def get(self, key_id: str) -> ApiKey | None:
        with self._lock:
            return next((k for k in self._keys if k.key_id == key_id), None)

    def list_keys(self, tenant_id: str | None = None) -> list[ApiKey]:
        with self._lock:
            keys = list(self._keys)
        if tenant_id is None:
            return keys
        return [k for k in keys if k.tenant_id == tenant_id]

    def verify(self, raw_key: str) -> ApiKey | None:
        with self._lock:
            return verify_api_key(raw_key, self._keys)

    def has_keys(self) -> bool:
        with self._lock:
            return len(self._keys) > 0


class KeyStoreProtocol(Protocol):
    """Interface shared by in-memory and persistent API key stores."""

    def add(self, key: ApiKey) -> None: ...
    def remove(self, key_id: str) -> bool: ...
    def get(self, key_id: str) -> ApiKey | None: ...
    def list_keys(self, tenant_id: str | None = None) -> list[ApiKey]: ...
    def verify(self, raw_key: str) -> ApiKey | None: ...
    def has_keys(self) -> bool: ...


_key_store: KeyStoreProtocol | None = None
_store_lock = threading.Lock()


def get_key_store() -> KeyStoreProtocol:
    global _key_store
    if _key_store is None:
        with _store_lock:
            if _key_store is None:
                _key_store = KeyStore()
    return _key_store


def set_key_store(store: KeyStoreProtocol) -> None:
    global _key_store
    with _store_lock:
        _key_store = store
