"""Tests for the virtual, scoped, revocable model-provider key broker (#3907).

Covers the store (CRUD + tenant isolation, both in-memory and SQLite), the
at-rest sealing of the real provider key (reusing the connection-secret crypto),
and the register -> mint -> resolve -> revoke lifecycle including scope
enforcement (provider / model / holder), fail-closed on revoked / expired /
disabled, tenant isolation on resolve, and the guarantee that a real provider
key never appears in any store public dict, virtual key, or resolution error.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet

from agent_bom.api import connection_crypto
from agent_bom.api.model_key_broker import (
    SUPPORTED_MODEL_PROVIDERS,
    InMemoryModelKeyBrokerStore,
    ModelKeyBrokerError,
    SQLiteModelKeyBrokerStore,
    generate_virtual_key_token,
    mint_virtual_key,
    register_provider_key,
    resolve_virtual_key,
    revoke_virtual_key,
)

_REAL_KEY = "sk-super-secret-real-openai-key-DO-NOT-LEAK"
_TEST_FERNET = Fernet.generate_key().decode("ascii")


@pytest.fixture(autouse=True)
def _sealing_key() -> Iterator[None]:
    """Configure the at-rest sealing key the broker reuses from the connection crypto."""
    prior = os.environ.get(connection_crypto.CONNECTIONS_KEY_ENV)
    prior_file = os.environ.get(f"{connection_crypto.CONNECTIONS_KEY_ENV}_FILE")
    prior_provider = os.environ.get(connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV)
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = _TEST_FERNET
    os.environ.pop(f"{connection_crypto.CONNECTIONS_KEY_ENV}_FILE", None)
    os.environ.pop(connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV, None)
    connection_crypto.reset_key_cache()
    try:
        yield
    finally:
        for name, value in (
            (connection_crypto.CONNECTIONS_KEY_ENV, prior),
            (f"{connection_crypto.CONNECTIONS_KEY_ENV}_FILE", prior_file),
            (connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV, prior_provider),
        ):
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        connection_crypto.reset_key_cache()


def _stores() -> Iterator[InMemoryModelKeyBrokerStore | SQLiteModelKeyBrokerStore]:
    yield InMemoryModelKeyBrokerStore()
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        yield SQLiteModelKeyBrokerStore(path)
    finally:
        os.unlink(path)


@pytest.fixture(params=["memory", "sqlite"])
def store(request: pytest.FixtureRequest) -> Iterator[object]:
    if request.param == "memory":
        yield InMemoryModelKeyBrokerStore()
    else:
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            yield SQLiteModelKeyBrokerStore(path)
        finally:
            os.unlink(path)


# ── sealing / registration ──────────────────────────────────────────────────


def test_register_seals_real_key_and_never_returns_it(store: object) -> None:
    pk = register_provider_key(
        store,
        tenant_id="t-alpha",
        provider="openai",
        display_name="prod-openai",
        api_key=_REAL_KEY,
    )
    # The stored ciphertext is not the plaintext.
    assert _REAL_KEY not in pk.secret_encrypted
    assert pk.secret_encrypted
    # The public dict never carries the secret, only a boolean.
    public = pk.to_public_dict()
    assert "secret_encrypted" not in public
    assert _REAL_KEY not in str(public)
    assert public["has_secret"] is True
    assert public["provider"] == "openai"


def test_register_fails_closed_without_sealing_key(store: object) -> None:
    os.environ.pop(connection_crypto.CONNECTIONS_KEY_ENV, None)
    connection_crypto.reset_key_cache()
    with pytest.raises(ModelKeyBrokerError):
        register_provider_key(
            store,
            tenant_id="t-alpha",
            provider="openai",
            display_name="x",
            api_key=_REAL_KEY,
        )


def test_register_rejects_unknown_provider(store: object) -> None:
    with pytest.raises(ModelKeyBrokerError):
        register_provider_key(store, tenant_id="t-alpha", provider="not-a-provider", display_name="x", api_key=_REAL_KEY)
    # Sanity: the tuple is what the route validates against.
    assert "openai" in SUPPORTED_MODEL_PROVIDERS
    assert "anthropic" in SUPPORTED_MODEL_PROVIDERS


# ── mint / resolve lifecycle ─────────────────────────────────────────────────


def test_mint_returns_raw_token_once_and_hashes_at_rest(store: object) -> None:
    pk = register_provider_key(store, tenant_id="t", provider="anthropic", display_name="x", api_key=_REAL_KEY)
    vk, raw = mint_virtual_key(
        store,
        tenant_id="t",
        provider_key_id=pk.provider_key_id,
        holder_id="agent-1",
        holder_type="agent_identity",
        allowed_models=["claude-opus-4"],
    )
    assert raw.startswith("abvk_")
    # Only a hash is stored; the raw token is not persisted.
    assert vk.token_hash and vk.token_hash != raw
    assert raw not in str(vk.to_public_dict())
    assert "token_hash" not in vk.to_public_dict()
    assert vk.provider == "anthropic"
    assert vk.status == "active"


def test_resolve_maps_virtual_to_real_key_within_scope(store: object) -> None:
    pk = register_provider_key(store, tenant_id="t", provider="openai", display_name="x", api_key=_REAL_KEY)
    _vk, raw = mint_virtual_key(store, tenant_id="t", provider_key_id=pk.provider_key_id, holder_id="agent-1", allowed_models=["gpt-4o"])
    resolved = resolve_virtual_key(store, tenant_id="t", raw_token=raw, provider="openai", model="gpt-4o")
    assert resolved.api_key == _REAL_KEY
    assert resolved.provider == "openai"
    assert resolved.provider_key_id == pk.provider_key_id


def test_resolve_rejects_out_of_scope_provider(store: object) -> None:
    pk = register_provider_key(store, tenant_id="t", provider="openai", display_name="x", api_key=_REAL_KEY)
    _vk, raw = mint_virtual_key(store, tenant_id="t", provider_key_id=pk.provider_key_id, holder_id="a")
    with pytest.raises(ModelKeyBrokerError) as exc:
        resolve_virtual_key(store, tenant_id="t", raw_token=raw, provider="anthropic", model="claude-opus-4")
    assert exc.value.reason == "provider_mismatch"


def test_resolve_rejects_out_of_scope_model(store: object) -> None:
    pk = register_provider_key(store, tenant_id="t", provider="openai", display_name="x", api_key=_REAL_KEY)
    _vk, raw = mint_virtual_key(store, tenant_id="t", provider_key_id=pk.provider_key_id, holder_id="a", allowed_models=["gpt-4o"])
    with pytest.raises(ModelKeyBrokerError) as exc:
        resolve_virtual_key(store, tenant_id="t", raw_token=raw, provider="openai", model="gpt-3.5-turbo")
    assert exc.value.reason == "model_not_allowed"


def test_empty_model_allowlist_permits_any_model(store: object) -> None:
    pk = register_provider_key(store, tenant_id="t", provider="openai", display_name="x", api_key=_REAL_KEY)
    _vk, raw = mint_virtual_key(store, tenant_id="t", provider_key_id=pk.provider_key_id, holder_id="a", allowed_models=[])
    resolved = resolve_virtual_key(store, tenant_id="t", raw_token=raw, provider="openai", model="anything-goes")
    assert resolved.api_key == _REAL_KEY


def test_resolve_rejects_out_of_scope_holder(store: object) -> None:
    pk = register_provider_key(store, tenant_id="t", provider="openai", display_name="x", api_key=_REAL_KEY)
    _vk, raw = mint_virtual_key(store, tenant_id="t", provider_key_id=pk.provider_key_id, holder_id="agent-1")
    with pytest.raises(ModelKeyBrokerError) as exc:
        resolve_virtual_key(store, tenant_id="t", raw_token=raw, provider="openai", model="gpt-4o", holder_id="agent-2")
    assert exc.value.reason == "holder_mismatch"


# ── revocation + expiry fail closed ──────────────────────────────────────────


def test_revoked_virtual_key_fails_closed(store: object) -> None:
    pk = register_provider_key(store, tenant_id="t", provider="openai", display_name="x", api_key=_REAL_KEY)
    vk, raw = mint_virtual_key(store, tenant_id="t", provider_key_id=pk.provider_key_id, holder_id="a")
    revoke_virtual_key(store, vk.virtual_key_id, tenant_id="t", reason="compromised")
    with pytest.raises(ModelKeyBrokerError) as exc:
        resolve_virtual_key(store, tenant_id="t", raw_token=raw, provider="openai", model="gpt-4o")
    assert exc.value.reason == "revoked"


def test_expired_virtual_key_fails_closed(store: object) -> None:
    pk = register_provider_key(store, tenant_id="t", provider="openai", display_name="x", api_key=_REAL_KEY)
    _vk, raw = mint_virtual_key(store, tenant_id="t", provider_key_id=pk.provider_key_id, holder_id="a", ttl_seconds=60)
    future = datetime.now(timezone.utc) + timedelta(seconds=120)
    with pytest.raises(ModelKeyBrokerError) as exc:
        resolve_virtual_key(store, tenant_id="t", raw_token=raw, provider="openai", model="gpt-4o", at=future)
    assert exc.value.reason == "expired"


def test_deleting_provider_key_fails_resolution_closed(store: object) -> None:
    pk = register_provider_key(store, tenant_id="t", provider="openai", display_name="x", api_key=_REAL_KEY)
    _vk, raw = mint_virtual_key(store, tenant_id="t", provider_key_id=pk.provider_key_id, holder_id="a")
    assert store.delete_provider_key(pk.provider_key_id, tenant_id="t") is True
    with pytest.raises(ModelKeyBrokerError) as exc:
        resolve_virtual_key(store, tenant_id="t", raw_token=raw, provider="openai", model="gpt-4o")
    assert exc.value.reason == "provider_key_missing"


# ── tenant isolation ─────────────────────────────────────────────────────────


def test_tenant_b_cannot_resolve_tenant_a_virtual_key(store: object) -> None:
    pk = register_provider_key(store, tenant_id="t-alpha", provider="openai", display_name="x", api_key=_REAL_KEY)
    _vk, raw = mint_virtual_key(store, tenant_id="t-alpha", provider_key_id=pk.provider_key_id, holder_id="a")
    with pytest.raises(ModelKeyBrokerError) as exc:
        resolve_virtual_key(store, tenant_id="t-beta", raw_token=raw, provider="openai", model="gpt-4o")
    assert exc.value.reason == "not_found"


def test_provider_and_virtual_key_lists_are_tenant_scoped(store: object) -> None:
    pk_a = register_provider_key(store, tenant_id="t-alpha", provider="openai", display_name="a", api_key=_REAL_KEY)
    register_provider_key(store, tenant_id="t-beta", provider="anthropic", display_name="b", api_key=_REAL_KEY)
    mint_virtual_key(store, tenant_id="t-alpha", provider_key_id=pk_a.provider_key_id, holder_id="a")

    assert {p.tenant_id for p in store.list_provider_keys("t-alpha")} == {"t-alpha"}
    assert {v.tenant_id for v in store.list_virtual_keys("t-alpha")} == {"t-alpha"}
    assert store.list_virtual_keys("t-beta") == []
    # Tenant B cannot fetch tenant A's provider key by id.
    assert store.get_provider_key(pk_a.provider_key_id, tenant_id="t-beta") is None


def test_mint_rejects_provider_key_from_another_tenant(store: object) -> None:
    pk = register_provider_key(store, tenant_id="t-alpha", provider="openai", display_name="x", api_key=_REAL_KEY)
    with pytest.raises(ModelKeyBrokerError):
        mint_virtual_key(store, tenant_id="t-beta", provider_key_id=pk.provider_key_id, holder_id="a")


# ── usage attribution + no-leak error ────────────────────────────────────────


def test_resolve_records_usage_attribution(store: object) -> None:
    pk = register_provider_key(store, tenant_id="t", provider="openai", display_name="x", api_key=_REAL_KEY)
    vk, raw = mint_virtual_key(store, tenant_id="t", provider_key_id=pk.provider_key_id, holder_id="agent-1")
    resolve_virtual_key(store, tenant_id="t", raw_token=raw, provider="openai", model="gpt-4o")
    resolve_virtual_key(store, tenant_id="t", raw_token=raw, provider="openai", model="gpt-4o")
    refreshed = store.get_virtual_key(vk.virtual_key_id, tenant_id="t")
    assert refreshed is not None
    assert refreshed.use_count == 2
    assert refreshed.last_used_at


def test_unknown_token_error_never_contains_secret(store: object) -> None:
    register_provider_key(store, tenant_id="t", provider="openai", display_name="x", api_key=_REAL_KEY)
    with pytest.raises(ModelKeyBrokerError) as exc:
        resolve_virtual_key(store, tenant_id="t", raw_token="abvk_deadbeef_nope", provider="openai", model="gpt-4o")
    assert exc.value.reason == "not_found"
    assert _REAL_KEY not in str(exc.value)


def test_generate_token_shape() -> None:
    raw, prefix, token_hash = generate_virtual_key_token()
    assert raw.startswith("abvk_")
    assert prefix in raw
    assert token_hash and token_hash not in raw


def test_sqlite_backend_persists_across_instances() -> None:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        s1 = SQLiteModelKeyBrokerStore(path)
        pk = register_provider_key(s1, tenant_id="t", provider="openai", display_name="x", api_key=_REAL_KEY)
        _vk, raw = mint_virtual_key(s1, tenant_id="t", provider_key_id=pk.provider_key_id, holder_id="a")
        # A fresh store instance on the same file resolves the same virtual key.
        s2 = SQLiteModelKeyBrokerStore(path)
        resolved = resolve_virtual_key(s2, tenant_id="t", raw_token=raw, provider="openai", model="gpt-4o")
        assert resolved.api_key == _REAL_KEY
        # The raw provider key must not be stored in plaintext anywhere in the DB file.
        with sqlite3.connect(path) as conn:
            for (data,) in conn.execute("SELECT data FROM model_provider_keys").fetchall():
                assert _REAL_KEY not in data
    finally:
        os.unlink(path)
