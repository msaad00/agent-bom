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
    revoked_at: str | None = None
    rotation_overlap_until: str | None = None
    replacement_key_id: str | None = None

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _parse_timestamp(value: str | None) -> datetime | None:
        if not value:
            return None
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed

    def is_expired(self, *, now: datetime | None = None) -> bool:
        if not self.expires_at:
            return False
        current = now or datetime.now(timezone.utc)
        expires_at = self._parse_timestamp(self.expires_at)
        return bool(expires_at and current > expires_at)

    def is_revoked(self) -> bool:
        return bool(self.revoked_at)

    def is_within_rotation_overlap(self, *, now: datetime | None = None) -> bool:
        if not self.replacement_key_id or not self.rotation_overlap_until:
            return False
        current = now or datetime.now(timezone.utc)
        overlap_until = self._parse_timestamp(self.rotation_overlap_until)
        return bool(overlap_until and current <= overlap_until)

    def is_usable(self, *, now: datetime | None = None) -> bool:
        if self.is_revoked():
            return False
        if self.is_expired(now=now):
            return False
        if self.replacement_key_id:
            return self.is_within_rotation_overlap(now=now)
        return True

    def lifecycle_state(self, *, now: datetime | None = None) -> str:
        if self.is_revoked():
            return "revoked"
        if self.is_expired(now=now):
            return "expired"
        if self.replacement_key_id:
            return "rotation_overlap" if self.is_within_rotation_overlap(now=now) else "rotated"
        return "active"

    def has_role(self, required: Role) -> bool:
        """Check if this key's role meets or exceeds the required role."""
        return _ROLE_HIERARCHY.get(self.role, 0) >= _ROLE_HIERARCHY.get(required, 0)

    def has_scope(self, required_scope: str | None) -> bool:
        """Check whether this key's scopes allow the requested action."""
        if not required_scope:
            return True
        if not self.scopes:
            return True
        if any(scope in {"saml-session", "browser-session", "oidc-session"} for scope in self.scopes):
            return True
        for scope in self.scopes:
            if scope == "*" or scope == required_scope:
                return True
            if scope.endswith(":*") and required_scope.startswith(scope[:-1]):
                return True
            if scope.endswith(".*") and required_scope.startswith(scope[:-1]):
                return True
        return False

    def to_dict(self) -> dict:
        current = datetime.now(timezone.utc)
        overlap_remaining_seconds = None
        if self.rotation_overlap_until:
            overlap_until = self._parse_timestamp(self.rotation_overlap_until)
            if overlap_until is not None:
                overlap_remaining_seconds = max(0, int((overlap_until - current).total_seconds()))
        return {
            "key_id": self.key_id,
            "key_prefix": self.key_prefix,
            "name": self.name,
            "role": self.role.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "scopes": self.scopes,
            "tenant_id": self.tenant_id,
            "revoked_at": self.revoked_at,
            "rotation_overlap_until": self.rotation_overlap_until,
            "replacement_key_id": self.replacement_key_id,
            "state": self.lifecycle_state(now=current),
            "overlap_seconds_remaining": overlap_remaining_seconds,
        }


@dataclass(frozen=True)
class ApiKeyPolicy:
    """Operator-controlled API key lifetime policy."""

    default_ttl_seconds: int = 30 * 24 * 60 * 60
    max_ttl_seconds: int = 90 * 24 * 60 * 60
    default_overlap_seconds: int = 0
    max_overlap_seconds: int = 24 * 60 * 60


@dataclass(frozen=True)
class SCIMRoleResolution:
    """Runtime auth role resolved from tenant-bound SCIM lifecycle state."""

    matched: bool
    active: bool
    role: Role | None = None
    user_id: str | None = None
    user_name: str | None = None


def _dedupe_subjects(subjects: tuple[object, ...]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for subject in subjects:
        candidate = str(subject or "").strip()
        if not candidate:
            continue
        key = candidate.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def _highest_role(values: list[str]) -> Role | None:
    best: Role | None = None
    for value in values:
        try:
            candidate = Role(str(value).strip().lower())
        except ValueError:
            continue
        if best is None or _ROLE_HIERARCHY[candidate] > _ROLE_HIERARCHY[best]:
            best = candidate
    return best


def resolve_scim_user_role(tenant_id: str, *subjects: object) -> SCIMRoleResolution:
    """Resolve an active SCIM user's highest role within one tenant.

    The resolver is intentionally tenant-scoped and only matches indexed SCIM
    identity fields so runtime auth does not scan all provisioned users.
    """

    from agent_bom.api.scim import scim_enabled_from_env

    if not scim_enabled_from_env():
        return SCIMRoleResolution(matched=False, active=False)

    candidates = _dedupe_subjects(subjects)
    if not tenant_id or not candidates:
        return SCIMRoleResolution(matched=False, active=False)

    from agent_bom.api.stores import _get_scim_store
    from agent_bom.platform_invariants import normalize_tenant_id

    tenant = normalize_tenant_id(tenant_id)
    users = []
    seen_users: set[str] = set()
    store = _get_scim_store()
    for subject in candidates:
        for attr in ("userName", "externalId", "id"):
            for user in store.list_users(tenant, filter_attr=attr, filter_value=subject):
                key = f"{user.tenant_id}:{user.user_id}"
                if key not in seen_users:
                    seen_users.add(key)
                    users.append(user)

    if not users:
        return SCIMRoleResolution(matched=False, active=False)

    active_users = [user for user in users if user.active]
    if not active_users:
        user = users[0]
        return SCIMRoleResolution(matched=True, active=False, user_id=user.user_id, user_name=user.user_name)

    best_user = active_users[0]
    best_role: Role | None = None
    for user in active_users:
        role = _highest_role(user.roles)
        if role is None:
            role = Role.VIEWER
        if best_role is None or _ROLE_HIERARCHY[role] > _ROLE_HIERARCHY[best_role]:
            best_role = role
            best_user = user

    return SCIMRoleResolution(matched=True, active=True, role=best_role, user_id=best_user.user_id, user_name=best_user.user_name)


def get_api_key_policy() -> ApiKeyPolicy:
    """Load API key lifetime policy from env with safe defaults."""
    default_ttl = int(os.environ.get("AGENT_BOM_API_KEY_DEFAULT_TTL_SECONDS", str(30 * 24 * 60 * 60)))
    max_ttl = int(os.environ.get("AGENT_BOM_API_KEY_MAX_TTL_SECONDS", str(90 * 24 * 60 * 60)))
    default_overlap = int(os.environ.get("AGENT_BOM_API_KEY_DEFAULT_OVERLAP_SECONDS", "0"))
    max_overlap = int(os.environ.get("AGENT_BOM_API_KEY_MAX_OVERLAP_SECONDS", str(24 * 60 * 60)))
    if default_ttl <= 0:
        raise ValueError("AGENT_BOM_API_KEY_DEFAULT_TTL_SECONDS must be > 0")
    if max_ttl <= 0:
        raise ValueError("AGENT_BOM_API_KEY_MAX_TTL_SECONDS must be > 0")
    if default_ttl > max_ttl:
        raise ValueError("AGENT_BOM_API_KEY_DEFAULT_TTL_SECONDS cannot exceed AGENT_BOM_API_KEY_MAX_TTL_SECONDS")
    if default_overlap < 0:
        raise ValueError("AGENT_BOM_API_KEY_DEFAULT_OVERLAP_SECONDS must be >= 0")
    if max_overlap < 0:
        raise ValueError("AGENT_BOM_API_KEY_MAX_OVERLAP_SECONDS must be >= 0")
    if default_overlap > max_overlap:
        raise ValueError("AGENT_BOM_API_KEY_DEFAULT_OVERLAP_SECONDS cannot exceed AGENT_BOM_API_KEY_MAX_OVERLAP_SECONDS")
    return ApiKeyPolicy(
        default_ttl_seconds=default_ttl,
        max_ttl_seconds=max_ttl,
        default_overlap_seconds=default_overlap,
        max_overlap_seconds=max_overlap,
    )


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


def normalize_rotation_overlap_seconds(
    overlap_seconds: int | None,
    *,
    policy: ApiKeyPolicy | None = None,
) -> int:
    """Normalize a requested key-rotation overlap window under operator policy."""
    active_policy = policy or get_api_key_policy()
    candidate = active_policy.default_overlap_seconds if overlap_seconds is None else overlap_seconds
    if candidate < 0:
        raise ValueError("overlap_seconds must be >= 0")
    if candidate > active_policy.max_overlap_seconds:
        raise ValueError(f"overlap_seconds exceeds the maximum allowed overlap window ({active_policy.max_overlap_seconds} seconds)")
    return candidate


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
            if not stored.is_usable():
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
            for key in self._keys:
                if key.key_id == key_id and not key.is_revoked():
                    key.revoked_at = datetime.now(timezone.utc).isoformat()
                    key.rotation_overlap_until = None
                    return True
            return False

    def mark_rotating(self, key_id: str, *, replacement_key_id: str, overlap_until: str) -> bool:
        with self._lock:
            for key in self._keys:
                if key.key_id == key_id and not key.is_revoked():
                    key.replacement_key_id = replacement_key_id
                    key.rotation_overlap_until = overlap_until
                    return True
            return False

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
    def mark_rotating(self, key_id: str, *, replacement_key_id: str, overlap_until: str) -> bool: ...
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
                if os.environ.get("AGENT_BOM_POSTGRES_URL"):
                    from agent_bom.api.postgres_access import PostgresKeyStore

                    _key_store = PostgresKeyStore()
                else:
                    _key_store = KeyStore()
    return _key_store


def set_key_store(store: KeyStoreProtocol) -> None:
    global _key_store
    with _store_lock:
        _key_store = store
