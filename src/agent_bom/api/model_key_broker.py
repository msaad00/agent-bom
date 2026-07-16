"""Virtual, scoped, revocable model-provider key broker (#3907).

Today the control plane brokers only cloud/MCP-server connection secrets. This
module is the model-key analogue: an operator registers a *real* model-provider
credential (OpenAI, Anthropic, Azure OpenAI, Bedrock, …) **once**, and agent-bom
mints **virtual keys** that

- map to the real key without ever exposing it,
- are SCOPED (per holder identity/blueprint, provider, optional model allowlist),
- are time-boxed (expiry) and REVOCABLE independently, and
- attribute usage back to the holder.

Security model — reuses the existing secret broker, does not reinvent it:

- The real provider key is sealed at rest with the **same** Fernet sealing the
  cloud-connection broker uses (:mod:`agent_bom.api.connection_crypto`), i.e. the
  ``~/.agent-bom/connections.key`` / ``AGENT_BOM_CONNECTIONS_KEY`` material and its
  pluggable managed-key providers. The plaintext key is write-only: it is never
  logged, never returned in any API response, and only decrypted server-side at
  resolve time immediately before the model call.
- A virtual key is a bearer token ``abvk_<public>_<secret>`` — only its SHA-256
  hash is persisted (mirroring the agent-identity store); the raw token is
  returned exactly once at mint time.
- Every operation is tenant-scoped (``WHERE tenant_id = …`` in every backend) and
  resolution fails closed: an unknown / revoked / expired virtual key, an
  out-of-scope provider / model / holder, or a missing / disabled underlying
  provider key all raise :class:`ModelKeyBrokerError` with a stable ``reason`` and
  never surface secret material.

Backend parity mirrors the agent-identity store: in-memory for tests, SQLite as
the durable single-node default, and Postgres (tenant RLS) for multi-replica
deployments — selected by the shared durable-store backend resolver. Both records
are persisted as a JSON ``data`` blob keyed by id + tenant so a new backend is a
registration, not a fork.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version

# Model providers a real key can target. The broker is provider-agnostic at the
# storage layer; this tuple is the allowlist the API/CLI validate against so a
# typo does not silently register an unusable key.
SUPPORTED_MODEL_PROVIDERS: tuple[str, ...] = (
    "openai",
    "anthropic",
    "azure-openai",
    "bedrock",
    "google-vertex",
    "mistral",
    "cohere",
)

VK_TOKEN_PREFIX = "abvk"

# Default virtual-key lifetime: short-lived by design (re-mint rather than issue a
# long-lived key). Callers may override; the floor keeps a typo from minting an
# effectively-expired key.
DEFAULT_VK_TTL_SECONDS = 3600
MIN_VK_TTL_SECONDS = 60
# Cap the lifetime so a virtual key stays genuinely short-lived (30 days max).
MAX_VK_TTL_SECONDS = 30 * 86400

STATUS_ACTIVE = "active"
STATUS_DISABLED = "disabled"
STATUS_REVOKED = "revoked"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_virtual_key_token() -> tuple[str, str, str]:
    """Return ``(raw_token, public_prefix, token_hash)``; the raw token is shown once."""
    public = secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)
    raw = f"{VK_TOKEN_PREFIX}_{public}_{secret}"
    return raw, public, hash_token(raw)


class ModelKeyBrokerError(RuntimeError):
    """Raised for a registration or resolution failure.

    ``reason`` is a stable, secret-free code the API maps to a status code. The
    message never embeds the real provider key or the raw virtual token.
    """

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass
class ModelProviderKey:
    """A registered real model-provider credential, sealed at rest.

    ``secret_encrypted`` holds the Fernet ciphertext of the real API key — never
    the plaintext. :meth:`to_public_dict` is the only shape that leaves the process
    and it omits that column entirely.
    """

    provider_key_id: str
    tenant_id: str
    provider: str
    display_name: str
    secret_encrypted: str
    status: str = STATUS_ACTIVE
    created_at: str = ""
    updated_at: str = ""
    owner: str = ""
    owner_type: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("secret_encrypted", None)
        data["has_secret"] = bool(self.secret_encrypted)
        return data


@dataclass
class VirtualModelKey:
    """A minted, scoped, revocable virtual key mapping to a real provider key.

    Only ``token_hash`` is persisted; the raw ``abvk_`` token is returned once at
    mint time. Scope is ``{provider, allowed_models, holder_id/holder_type}`` plus
    an expiry; :meth:`to_public_dict` omits the hash.
    """

    virtual_key_id: str
    tenant_id: str
    provider_key_id: str
    provider: str
    token_hash: str
    token_prefix: str
    holder_id: str
    status: str = STATUS_ACTIVE
    holder_type: str = ""
    issued_at: str = ""
    expires_at: str = ""
    allowed_models: list[str] = field(default_factory=list)
    revoked_at: str = ""
    revoked_reason: str = ""
    last_used_at: str = ""
    use_count: int = 0
    owner: str = ""
    owner_type: str = ""

    def model_allowed(self, model: str) -> bool:
        """True when this key may be used for ``model`` (empty allowlist = any)."""
        if not self.allowed_models:
            return True
        target = (model or "").strip()
        return "*" in self.allowed_models or target in self.allowed_models

    def is_live(self, *, at: datetime | None = None) -> bool:
        """True when the key may still resolve (active and not past expiry)."""
        if self.status != STATUS_ACTIVE:
            return False
        now = at or _now()
        if not self.expires_at:
            return False
        try:
            return now <= datetime.fromisoformat(self.expires_at)
        except ValueError:
            return False

    def to_public_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("token_hash", None)
        return data


@dataclass
class ResolvedModelKey:
    """The server-side result of resolving a virtual key to its real credential.

    ``api_key`` is the plaintext real provider key. This object is only ever
    constructed inside the process for the model-call path; it is never
    serialized into an API response or a log line.
    """

    virtual_key_id: str
    tenant_id: str
    provider: str
    model: str
    provider_key_id: str
    holder_id: str
    api_key: str


# ── Store contract + backends ─────────────────────────────────────────────────


class ModelKeyBrokerStore(Protocol):
    """Tenant-scoped persistence for provider keys and virtual keys."""

    def init_schema(self) -> None: ...
    def put_provider_key(self, record: ModelProviderKey) -> None: ...
    def get_provider_key(self, provider_key_id: str, *, tenant_id: str) -> ModelProviderKey | None: ...
    def list_provider_keys(self, tenant_id: str) -> list[ModelProviderKey]: ...
    def delete_provider_key(self, provider_key_id: str, *, tenant_id: str) -> bool: ...
    def put_virtual_key(self, record: VirtualModelKey) -> None: ...
    def get_virtual_key(self, virtual_key_id: str, *, tenant_id: str) -> VirtualModelKey | None: ...
    def get_virtual_key_by_hash(self, token_hash: str, *, tenant_id: str) -> VirtualModelKey | None: ...
    def list_virtual_keys(
        self,
        tenant_id: str,
        *,
        provider_key_id: str | None = None,
        include_inactive: bool = False,
    ) -> list[VirtualModelKey]: ...


def _copy_provider_key(record: ModelProviderKey) -> ModelProviderKey:
    return replace(record)


def _copy_virtual_key(record: VirtualModelKey) -> VirtualModelKey:
    return replace(record, allowed_models=list(record.allowed_models))


class InMemoryModelKeyBrokerStore:
    """Dict-backed broker store for tests and ephemeral runs."""

    def __init__(self) -> None:
        self._provider_keys: dict[str, ModelProviderKey] = {}
        self._virtual_keys: dict[str, VirtualModelKey] = {}
        self._vk_by_hash: dict[str, str] = {}
        self._lock = threading.Lock()

    def init_schema(self) -> None:
        """No-op: the in-memory backend has no persistent schema."""

    def put_provider_key(self, record: ModelProviderKey) -> None:
        with self._lock:
            self._provider_keys[record.provider_key_id] = _copy_provider_key(record)

    def get_provider_key(self, provider_key_id: str, *, tenant_id: str) -> ModelProviderKey | None:
        with self._lock:
            record = self._provider_keys.get(provider_key_id)
            if record is None or record.tenant_id != tenant_id:
                return None
            return _copy_provider_key(record)

    def list_provider_keys(self, tenant_id: str) -> list[ModelProviderKey]:
        with self._lock:
            rows = [_copy_provider_key(r) for r in self._provider_keys.values() if r.tenant_id == tenant_id]
        return sorted(rows, key=lambda r: (r.created_at, r.provider_key_id))

    def delete_provider_key(self, provider_key_id: str, *, tenant_id: str) -> bool:
        with self._lock:
            record = self._provider_keys.get(provider_key_id)
            if record is None or record.tenant_id != tenant_id:
                return False
            del self._provider_keys[provider_key_id]
            return True

    def put_virtual_key(self, record: VirtualModelKey) -> None:
        with self._lock:
            self._virtual_keys[record.virtual_key_id] = _copy_virtual_key(record)
            self._vk_by_hash[record.token_hash] = record.virtual_key_id

    def get_virtual_key(self, virtual_key_id: str, *, tenant_id: str) -> VirtualModelKey | None:
        with self._lock:
            record = self._virtual_keys.get(virtual_key_id)
            if record is None or record.tenant_id != tenant_id:
                return None
            return _copy_virtual_key(record)

    def get_virtual_key_by_hash(self, token_hash: str, *, tenant_id: str) -> VirtualModelKey | None:
        with self._lock:
            vk_id = self._vk_by_hash.get(token_hash)
            record = self._virtual_keys.get(vk_id) if vk_id else None
            if record is None or record.tenant_id != tenant_id:
                return None
            return _copy_virtual_key(record)

    def list_virtual_keys(
        self,
        tenant_id: str,
        *,
        provider_key_id: str | None = None,
        include_inactive: bool = False,
    ) -> list[VirtualModelKey]:
        with self._lock:
            rows = [_copy_virtual_key(r) for r in self._virtual_keys.values() if r.tenant_id == tenant_id]
        if provider_key_id is not None:
            rows = [r for r in rows if r.provider_key_id == provider_key_id]
        if not include_inactive:
            rows = [r for r in rows if r.status == STATUS_ACTIVE]
        return sorted(rows, key=lambda r: (r.issued_at, r.virtual_key_id), reverse=True)


class SQLiteModelKeyBrokerStore:
    """SQLite-backed broker store (durable single-node default).

    Both records are persisted as a JSON ``data`` blob keyed by id + tenant,
    matching the agent-identity store shape so tenant-scoped reads ride an index.
    """

    def __init__(self, db_path: str = "agent_bom.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        conn: sqlite3.Connection = self._local.conn
        return conn

    def init_schema(self) -> None:
        self._init_db()

    def _init_db(self) -> None:
        ensure_sqlite_schema_version(self._conn, "model_provider_keys")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS model_provider_keys (
                provider_key_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                data TEXT NOT NULL
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_model_provider_keys_tenant ON model_provider_keys(tenant_id, created_at)")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS model_virtual_keys (
                virtual_key_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                provider_key_id TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                data TEXT NOT NULL
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_model_virtual_keys_tenant ON model_virtual_keys(tenant_id, issued_at)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_model_virtual_keys_hash ON model_virtual_keys(token_hash)")
        self._conn.commit()

    def put_provider_key(self, record: ModelProviderKey) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO model_provider_keys "
            "(provider_key_id, tenant_id, provider, status, created_at, data) VALUES (?, ?, ?, ?, ?, ?)",
            (
                record.provider_key_id,
                record.tenant_id,
                record.provider,
                record.status,
                record.created_at,
                json.dumps(asdict(record), sort_keys=True),
            ),
        )
        self._conn.commit()

    def get_provider_key(self, provider_key_id: str, *, tenant_id: str) -> ModelProviderKey | None:
        row = self._conn.execute(
            "SELECT data FROM model_provider_keys WHERE provider_key_id = ? AND tenant_id = ?",
            (provider_key_id, tenant_id),
        ).fetchone()
        return ModelProviderKey(**json.loads(row[0])) if row else None

    def list_provider_keys(self, tenant_id: str) -> list[ModelProviderKey]:
        rows = self._conn.execute(
            "SELECT data FROM model_provider_keys WHERE tenant_id = ? ORDER BY created_at, provider_key_id",
            (tenant_id,),
        ).fetchall()
        return [ModelProviderKey(**json.loads(r[0])) for r in rows]

    def delete_provider_key(self, provider_key_id: str, *, tenant_id: str) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM model_provider_keys WHERE provider_key_id = ? AND tenant_id = ?",
            (provider_key_id, tenant_id),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def put_virtual_key(self, record: VirtualModelKey) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO model_virtual_keys "
            "(virtual_key_id, tenant_id, provider_key_id, token_hash, status, issued_at, data) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                record.virtual_key_id,
                record.tenant_id,
                record.provider_key_id,
                record.token_hash,
                record.status,
                record.issued_at,
                json.dumps(asdict(record), sort_keys=True),
            ),
        )
        self._conn.commit()

    def get_virtual_key(self, virtual_key_id: str, *, tenant_id: str) -> VirtualModelKey | None:
        row = self._conn.execute(
            "SELECT data FROM model_virtual_keys WHERE virtual_key_id = ? AND tenant_id = ?",
            (virtual_key_id, tenant_id),
        ).fetchone()
        return VirtualModelKey(**json.loads(row[0])) if row else None

    def get_virtual_key_by_hash(self, token_hash: str, *, tenant_id: str) -> VirtualModelKey | None:
        row = self._conn.execute(
            "SELECT data FROM model_virtual_keys WHERE token_hash = ? AND tenant_id = ?",
            (token_hash, tenant_id),
        ).fetchone()
        return VirtualModelKey(**json.loads(row[0])) if row else None

    def list_virtual_keys(
        self,
        tenant_id: str,
        *,
        provider_key_id: str | None = None,
        include_inactive: bool = False,
    ) -> list[VirtualModelKey]:
        rows = self._conn.execute(
            "SELECT data FROM model_virtual_keys WHERE tenant_id = ? ORDER BY issued_at DESC, virtual_key_id DESC",
            (tenant_id,),
        ).fetchall()
        records = [VirtualModelKey(**json.loads(r[0])) for r in rows]
        if provider_key_id is not None:
            records = [r for r in records if r.provider_key_id == provider_key_id]
        if not include_inactive:
            records = [r for r in records if r.status == STATUS_ACTIVE]
        return records


# ── Lifecycle operations ──────────────────────────────────────────────────────


def register_provider_key(
    store: ModelKeyBrokerStore,
    *,
    tenant_id: str,
    provider: str,
    display_name: str,
    api_key: str,
    owner: str = "",
    owner_type: str = "",
) -> ModelProviderKey:
    """Register (seal) a real provider key for ``tenant_id``.

    The plaintext ``api_key`` is encrypted with the shared connection-secret
    sealing and is never returned. Fails closed (``ModelKeyBrokerError``) when the
    provider is unknown, the key is empty, or no sealing key is configured.
    """
    from agent_bom.api.connection_crypto import (
        ConnectionSecretError,
        connections_key_configured,
        encrypt_secret,
    )

    normalized = (provider or "").strip().lower()
    if normalized not in SUPPORTED_MODEL_PROVIDERS:
        raise ModelKeyBrokerError(
            f"Unsupported model provider '{provider}'. Use one of: {', '.join(SUPPORTED_MODEL_PROVIDERS)}.",
            reason="unsupported_provider",
        )
    if not (api_key or "").strip():
        raise ModelKeyBrokerError("Refusing to register an empty provider key.", reason="empty_key")
    if not connections_key_configured():
        raise ModelKeyBrokerError(
            "Model-key sealing is not configured (AGENT_BOM_CONNECTIONS_KEY unset); refusing to store a provider key.",
            reason="sealing_unconfigured",
        )
    try:
        secret_encrypted = encrypt_secret(api_key.strip())
    except ConnectionSecretError as exc:
        # Never echo the key or sealing detail — only the failure mode.
        raise ModelKeyBrokerError("Unable to seal the provider key at rest.", reason="sealing_failed") from exc

    now = _iso(_now())
    record = ModelProviderKey(
        provider_key_id=f"mpk_{secrets.token_hex(8)}",
        tenant_id=tenant_id,
        provider=normalized,
        display_name=(display_name or "").strip()[:200],
        secret_encrypted=secret_encrypted,
        status=STATUS_ACTIVE,
        created_at=now,
        updated_at=now,
        owner=(owner or "").strip()[:200],
        owner_type=(owner_type or "").strip()[:60],
    )
    store.put_provider_key(record)
    return record


def _clamp_ttl(ttl_seconds: int) -> int:
    return max(MIN_VK_TTL_SECONDS, min(int(ttl_seconds), MAX_VK_TTL_SECONDS))


def mint_virtual_key(
    store: ModelKeyBrokerStore,
    *,
    tenant_id: str,
    provider_key_id: str,
    holder_id: str,
    holder_type: str = "",
    allowed_models: list[str] | None = None,
    ttl_seconds: int = DEFAULT_VK_TTL_SECONDS,
    owner: str = "",
    owner_type: str = "",
) -> tuple[VirtualModelKey, str]:
    """Mint a scoped virtual key bound to a registered provider key.

    Returns ``(virtual_key, raw_token)``; the raw token is available only here.
    The virtual key inherits the provider from the underlying provider key and is
    scoped to ``holder_id`` plus an optional ``allowed_models`` allowlist, expiring
    after ``ttl_seconds`` (clamped short-lived). Fails closed when the provider key
    does not exist for the tenant or is disabled.
    """
    provider_key = store.get_provider_key(provider_key_id, tenant_id=tenant_id)
    if provider_key is None:
        raise ModelKeyBrokerError(f"Provider key {provider_key_id} not found for this tenant.", reason="provider_key_missing")
    if provider_key.status != STATUS_ACTIVE:
        raise ModelKeyBrokerError("Provider key is disabled; cannot mint a virtual key.", reason="provider_key_disabled")
    if not (holder_id or "").strip():
        raise ModelKeyBrokerError("A virtual key must be bound to a holder identity.", reason="missing_holder")

    raw, prefix, token_hash = generate_virtual_key_token()
    now = _now()
    models = [m.strip() for m in (allowed_models or []) if m and m.strip()]
    record = VirtualModelKey(
        virtual_key_id=f"vmk_{secrets.token_hex(8)}",
        tenant_id=tenant_id,
        provider_key_id=provider_key_id,
        provider=provider_key.provider,
        token_hash=token_hash,
        token_prefix=prefix,
        holder_id=holder_id.strip()[:200],
        holder_type=(holder_type or "").strip()[:60],
        status=STATUS_ACTIVE,
        issued_at=_iso(now),
        expires_at=_iso(now + timedelta(seconds=_clamp_ttl(ttl_seconds))),
        allowed_models=models,
        owner=(owner or "").strip()[:200],
        owner_type=(owner_type or "").strip()[:60],
    )
    store.put_virtual_key(record)
    return record, raw


def record_virtual_key_usage(store: ModelKeyBrokerStore, record: VirtualModelKey, *, at: datetime | None = None) -> None:
    """Attribute one use to the virtual key (increment counter + stamp last-used)."""
    record.use_count = int(record.use_count) + 1
    record.last_used_at = _iso(at or _now())
    store.put_virtual_key(record)


def resolve_virtual_key(
    store: ModelKeyBrokerStore,
    *,
    tenant_id: str,
    raw_token: str,
    provider: str,
    model: str,
    holder_id: str | None = None,
    at: datetime | None = None,
    record_usage: bool = True,
) -> ResolvedModelKey:
    """Resolve a raw virtual key to its real provider credential, server-side.

    Enforces scope and fails closed. ``reason`` on the raised error is one of:
    ``not_found`` (unknown token / wrong tenant), ``revoked``, ``expired``,
    ``provider_mismatch``, ``model_not_allowed``, ``holder_mismatch``,
    ``provider_key_missing``, ``provider_key_disabled``, ``sealing_failed``.

    The returned :class:`ResolvedModelKey` carries the plaintext key for the
    in-process model-call path only; callers must never serialize it.
    """
    from agent_bom.api.connection_crypto import ConnectionSecretError, decrypt_secret

    now = at or _now()
    vk = store.get_virtual_key_by_hash(hash_token(raw_token), tenant_id=tenant_id)
    if vk is None:
        raise ModelKeyBrokerError("Unknown virtual key.", reason="not_found")
    if vk.status == STATUS_REVOKED:
        raise ModelKeyBrokerError("Virtual key has been revoked.", reason="revoked")
    if not vk.is_live(at=now):
        raise ModelKeyBrokerError("Virtual key has expired.", reason="expired")

    requested_provider = (provider or "").strip().lower()
    if requested_provider != vk.provider:
        raise ModelKeyBrokerError("Virtual key is not scoped for this provider.", reason="provider_mismatch")
    if not vk.model_allowed(model):
        raise ModelKeyBrokerError("Virtual key is not scoped for this model.", reason="model_not_allowed")
    if holder_id is not None and holder_id.strip() and holder_id.strip() != vk.holder_id:
        raise ModelKeyBrokerError("Virtual key is not scoped for this holder.", reason="holder_mismatch")

    provider_key = store.get_provider_key(vk.provider_key_id, tenant_id=tenant_id)
    if provider_key is None:
        raise ModelKeyBrokerError("Underlying provider key no longer exists.", reason="provider_key_missing")
    if provider_key.status != STATUS_ACTIVE:
        raise ModelKeyBrokerError("Underlying provider key is disabled.", reason="provider_key_disabled")

    try:
        api_key = decrypt_secret(provider_key.secret_encrypted)
    except ConnectionSecretError as exc:
        # Never echo the ciphertext or sealing detail — only the failure mode.
        raise ModelKeyBrokerError("Unable to unseal the provider key.", reason="sealing_failed") from exc

    if record_usage:
        record_virtual_key_usage(store, vk, at=now)

    return ResolvedModelKey(
        virtual_key_id=vk.virtual_key_id,
        tenant_id=tenant_id,
        provider=vk.provider,
        model=(model or "").strip(),
        provider_key_id=vk.provider_key_id,
        holder_id=vk.holder_id,
        api_key=api_key,
    )


def revoke_virtual_key(
    store: ModelKeyBrokerStore,
    virtual_key_id: str,
    *,
    tenant_id: str,
    reason: str = "",
) -> VirtualModelKey | None:
    """Immediately revoke a virtual key; further resolution fails closed."""
    vk = store.get_virtual_key(virtual_key_id, tenant_id=tenant_id)
    if vk is None:
        return None
    vk.status = STATUS_REVOKED
    vk.revoked_at = _iso(_now())
    vk.revoked_reason = (reason or "").strip()[:500]
    store.put_virtual_key(vk)
    return vk


def set_provider_key_status(
    store: ModelKeyBrokerStore,
    provider_key_id: str,
    *,
    tenant_id: str,
    status: str,
) -> ModelProviderKey | None:
    """Enable (``active``) or disable (``disabled``) a registered provider key."""
    if status not in (STATUS_ACTIVE, STATUS_DISABLED):
        raise ModelKeyBrokerError("status must be 'active' or 'disabled'.", reason="invalid_status")
    record = store.get_provider_key(provider_key_id, tenant_id=tenant_id)
    if record is None:
        return None
    record.status = status
    record.updated_at = _iso(_now())
    store.put_provider_key(record)
    return record


# ── Backend selection ─────────────────────────────────────────────────────────

_MODEL_KEY_BROKER_STORE: ModelKeyBrokerStore | None = None


def get_model_key_broker_store() -> ModelKeyBrokerStore:
    """Return the process broker store, durable by default (mirrors the identity store).

    Postgres when configured (multi-replica, tenant RLS), in-memory only on an
    explicit ``AGENT_BOM_EPHEMERAL_STORE`` opt-out, otherwise durable SQLite.
    """
    global _MODEL_KEY_BROKER_STORE
    if _MODEL_KEY_BROKER_STORE is not None:
        return _MODEL_KEY_BROKER_STORE
    from agent_bom.api.durable_store import select_backend, sqlite_path

    backend = select_backend()
    if backend == "postgres":
        from agent_bom.api.postgres_model_key_broker import PostgresModelKeyBrokerStore

        _MODEL_KEY_BROKER_STORE = PostgresModelKeyBrokerStore()
    elif backend == "memory":
        _MODEL_KEY_BROKER_STORE = InMemoryModelKeyBrokerStore()
    else:
        _MODEL_KEY_BROKER_STORE = SQLiteModelKeyBrokerStore(sqlite_path())
    return _MODEL_KEY_BROKER_STORE


def set_model_key_broker_store(store: ModelKeyBrokerStore | None) -> None:
    """Swap the process broker store (tests / explicit backend wiring)."""
    global _MODEL_KEY_BROKER_STORE
    _MODEL_KEY_BROKER_STORE = store
