"""Tests for the per-tenant cloud connections plane (Phase A).

Covers the store (CRUD + tenant isolation, ``auth_params`` migration), at-rest
encryption (ciphertext in the DB column, decrypt round-trip, missing-key refuses
to persist), the CRUD API (RBAC, no-secret responses, tenant scoping), and the
credential broker for all four providers (AWS AssumeRole, Azure
ClientSecretCredential, GCP read-only service-account credentials, Snowflake
key-pair connection) plus the per-provider read-only scan-launch route.
"""

from __future__ import annotations

import base64
import os
import sqlite3
import sys
import types
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from agent_bom.api import connection_crypto
from agent_bom.api.connection_store import (
    STATUS_PENDING,
    CloudConnectionRecord,
    InMemoryConnectionStore,
    SQLiteConnectionStore,
    set_connection_store,
)

PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"
_TEST_KEY = Fernet.generate_key().decode("ascii")


def _proxy_headers(role: str = "admin", tenant: str = "tenant-alpha") -> dict[str, str]:
    return {
        "X-Agent-Bom-Role": role,
        "X-Agent-Bom-Tenant-ID": tenant,
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }


@pytest.fixture(autouse=True)
def _connection_env() -> Iterator[None]:
    """Configure trusted-proxy auth + an encryption key, isolated per test."""
    prior = {
        "AGENT_BOM_TRUST_PROXY_AUTH": os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH"),
        "AGENT_BOM_TRUST_PROXY_AUTH_SECRET": os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH_SECRET"),
        connection_crypto.CONNECTIONS_KEY_ENV: os.environ.get(connection_crypto.CONNECTIONS_KEY_ENV),
        connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV: os.environ.get(connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV),
        connection_crypto.CONNECTIONS_KEY_REF_ENV: os.environ.get(connection_crypto.CONNECTIONS_KEY_REF_ENV),
    }
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH"] = "1"
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] = PROXY_SECRET
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = _TEST_KEY
    os.environ.pop(connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV, None)
    os.environ.pop(connection_crypto.CONNECTIONS_KEY_REF_ENV, None)
    connection_crypto.reset_key_cache()
    set_connection_store(InMemoryConnectionStore())
    try:
        yield
    finally:
        for key, value in prior.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        connection_crypto.reset_key_cache()
        set_connection_store(None)


def _record(tenant_id: str, *, provider: str = "aws") -> CloudConnectionRecord:
    return CloudConnectionRecord(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        provider=provider,
        display_name="prod-readonly",
        role_ref="arn:aws:iam::123456789012:role/agent-bom-readonly",
        external_id_encrypted=connection_crypto.encrypt_secret("super-secret-external-id"),
        regions=["us-east-1"],
        status=STATUS_PENDING,
        created_at="2026-06-26T00:00:00+00:00",
        updated_at="2026-06-26T00:00:00+00:00",
    )


# --------------------------------------------------------------------------- #
# Store: CRUD + tenant isolation
# --------------------------------------------------------------------------- #


def test_store_crud_round_trip() -> None:
    store = InMemoryConnectionStore()
    record = _record("tenant-a")
    store.put(record)

    fetched = store.get("tenant-a", record.id)
    assert fetched is not None
    assert fetched.display_name == "prod-readonly"
    assert fetched.last_scan_id is None
    assert [r.id for r in store.list_for_tenant("tenant-a")] == [record.id]

    assert store.delete("tenant-a", record.id) is True
    assert store.get("tenant-a", record.id) is None
    assert store.list_for_tenant("tenant-a") == []


def test_store_tenant_isolation() -> None:
    store = InMemoryConnectionStore()
    a = _record("tenant-a")
    b = _record("tenant-b")
    store.put(a)
    store.put(b)

    # Tenant A cannot read tenant B's connection by id, nor see it in its list.
    assert store.get("tenant-a", b.id) is None
    assert [r.id for r in store.list_for_tenant("tenant-a")] == [a.id]
    # Cross-tenant delete is a no-op.
    assert store.delete("tenant-a", b.id) is False
    assert store.get("tenant-b", b.id) is not None


def test_sqlite_store_crud_and_isolation(tmp_path: Any) -> None:
    db_path = str(tmp_path / "connections.db")
    store = SQLiteConnectionStore(db_path)
    a = _record("tenant-a")
    b = _record("tenant-b")
    store.put(a)
    store.put(b)

    assert store.get("tenant-a", a.id) is not None
    assert store.get("tenant-a", b.id) is None
    assert [r.id for r in store.list_for_tenant("tenant-b")] == [b.id]
    assert store.delete("tenant-b", b.id) is True
    assert store.get("tenant-b", b.id) is None


def test_sqlite_last_scan_id_and_auth_params_columns_present_defaults_and_round_trips(tmp_path: Any) -> None:
    db_path = str(tmp_path / "connections.db")
    store = SQLiteConnectionStore(db_path)

    # The migrated columns exist.
    columns = {row[1] for row in sqlite3.connect(db_path).execute("PRAGMA table_info(cloud_connections)").fetchall()}
    assert "last_scan_id" in columns
    assert "auth_params" in columns

    # A record with no last_scan_id/auth_params defaults cleanly on read-back.
    plain = _record("tenant-a")
    store.put(plain)
    fetched_plain = store.get("tenant-a", plain.id)
    assert fetched_plain is not None
    assert fetched_plain.last_scan_id is None
    assert fetched_plain.auth_params == {}

    # A record with last_scan_id/auth_params round-trips unchanged.
    with_params = _record("tenant-a", provider="azure")
    with_params.last_scan_id = "scan-123"
    with_params.auth_params = {"tenant_id": "t-guid", "subscription_id": "s-guid"}
    store.put(with_params)
    fetched_params = store.get("tenant-a", with_params.id)
    assert fetched_params is not None
    assert fetched_params.last_scan_id == "scan-123"
    assert fetched_params.auth_params == {"tenant_id": "t-guid", "subscription_id": "s-guid"}


def test_sqlite_auth_params_migration_is_idempotent_on_legacy_table(tmp_path: Any) -> None:
    """A pre-migration table (no auth_params column) is migrated and backfilled."""
    db_path = str(tmp_path / "legacy.db")
    raw = sqlite3.connect(db_path)
    # Recreate the pre-auth_params schema with one legacy row.
    raw.execute(
        "CREATE TABLE cloud_connections (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, provider TEXT NOT NULL, "
        "display_name TEXT NOT NULL, role_ref TEXT NOT NULL, external_id_encrypted TEXT NOT NULL DEFAULT '', "
        "regions TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'pending', status_detail TEXT NOT NULL DEFAULT '', "
        "created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_scan_at TEXT, scan_interval_minutes INTEGER)"
    )
    raw.execute(
        "INSERT INTO cloud_connections (id, tenant_id, provider, display_name, role_ref, created_at, updated_at) "
        "VALUES ('legacy-1', 'tenant-a', 'aws', 'legacy', 'arn:role', '2026-06-01T00:00:00+00:00', '2026-06-01T00:00:00+00:00')"
    )
    raw.commit()
    raw.close()

    store = SQLiteConnectionStore(db_path)  # runs the idempotent migration
    legacy = store.get("tenant-a", "legacy-1")
    assert legacy is not None
    assert legacy.last_scan_id is None
    assert legacy.auth_params == {}
    # Re-init is a no-op (idempotent) and the backfilled column stays NOT NULL.
    store.init_schema()
    columns = {row[1] for row in sqlite3.connect(db_path).execute("PRAGMA table_info(cloud_connections)").fetchall()}
    assert "last_scan_id" in columns
    assert "auth_params" in columns


# --------------------------------------------------------------------------- #
# Encryption: ciphertext at rest, round-trip, missing-key refusal
# --------------------------------------------------------------------------- #


def test_db_column_holds_ciphertext_not_plaintext(tmp_path: Any) -> None:
    db_path = str(tmp_path / "connections.db")
    store = SQLiteConnectionStore(db_path)
    record = _record("tenant-a")
    store.put(record)

    raw = sqlite3.connect(db_path).execute("SELECT external_id_encrypted FROM cloud_connections WHERE id = ?", (record.id,)).fetchone()
    stored = raw[0]
    assert "super-secret-external-id" not in stored
    assert stored == record.external_id_encrypted
    # And it decrypts back to the plaintext.
    assert connection_crypto.decrypt_secret(stored) == "super-secret-external-id"


def test_encrypt_decrypt_round_trip() -> None:
    token = connection_crypto.encrypt_secret("value-123")
    assert token != "value-123"
    assert connection_crypto.decrypt_secret(token) == "value-123"


def test_missing_key_refuses_to_encrypt() -> None:
    os.environ.pop(connection_crypto.CONNECTIONS_KEY_ENV, None)
    assert connection_crypto.connections_key_configured() is False
    with pytest.raises(connection_crypto.ConnectionSecretError):
        connection_crypto.encrypt_secret("would-be-plaintext")


def test_invalid_key_raises_clear_error() -> None:
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = "not-a-valid-fernet-key"
    with pytest.raises(connection_crypto.ConnectionSecretError):
        connection_crypto.encrypt_secret("x")


# --------------------------------------------------------------------------- #
# Key providers: managed-key resolution (aws-secrets / aws-kms), fail-closed,
# in-process caching. boto3 is mocked at the _boto3_client seam.
# --------------------------------------------------------------------------- #


class _FakeSecretsClient:
    """Stand-in for a Secrets Manager client; counts GetSecretValue calls."""

    def __init__(self, *, secret_string: str | None = None, error: Exception | None = None) -> None:
        self.calls = 0
        self._secret_string = secret_string
        self._error = error

    def get_secret_value(self, *, SecretId: str) -> dict[str, Any]:  # noqa: N803 - boto3 kwarg
        self.calls += 1
        if self._error is not None:
            raise self._error
        return {"SecretString": self._secret_string}


class _FakeKmsClient:
    """Stand-in for a KMS client; counts Decrypt calls."""

    def __init__(self, *, plaintext: bytes | None = None, error: Exception | None = None) -> None:
        self.calls = 0
        self._plaintext = plaintext
        self._error = error

    def decrypt(self, *, CiphertextBlob: bytes) -> dict[str, Any]:  # noqa: N803 - boto3 kwarg
        self.calls += 1
        if self._error is not None:
            raise self._error
        return {"Plaintext": self._plaintext}


def _patch_client(monkeypatch: Any, client: Any) -> None:
    monkeypatch.setattr(connection_crypto, "_boto3_client", lambda service, provider: client)


def test_aws_secrets_provider_round_trip(monkeypatch: Any) -> None:
    os.environ[connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV] = connection_crypto.PROVIDER_AWS_SECRETS
    os.environ[connection_crypto.CONNECTIONS_KEY_REF_ENV] = "arn:aws:secretsmanager:us-east-1:123456789012:secret:agent-bom/conn-key"
    os.environ.pop(connection_crypto.CONNECTIONS_KEY_ENV, None)
    fake = _FakeSecretsClient(secret_string=_TEST_KEY)
    _patch_client(monkeypatch, fake)
    connection_crypto.reset_key_cache()

    assert connection_crypto.connections_key_configured() is True
    token = connection_crypto.encrypt_secret("ext-id")
    assert connection_crypto.decrypt_secret(token) == "ext-id"
    # Resolved once, then served from cache (decrypt did not re-fetch).
    assert fake.calls == 1


def test_aws_secrets_missing_ref_fails_closed(monkeypatch: Any) -> None:
    os.environ[connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV] = connection_crypto.PROVIDER_AWS_SECRETS
    os.environ.pop(connection_crypto.CONNECTIONS_KEY_REF_ENV, None)
    fake = _FakeSecretsClient(secret_string=_TEST_KEY)
    _patch_client(monkeypatch, fake)
    connection_crypto.reset_key_cache()

    assert connection_crypto.connections_key_configured() is False
    with pytest.raises(connection_crypto.ConnectionSecretError):
        connection_crypto.encrypt_secret("ext-id")
    # Never attempted a provider call without a ref.
    assert fake.calls == 0


def test_aws_secrets_denial_fails_closed_without_leaking(monkeypatch: Any) -> None:
    os.environ[connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV] = connection_crypto.PROVIDER_AWS_SECRETS
    os.environ[connection_crypto.CONNECTIONS_KEY_REF_ENV] = "arn:aws:secretsmanager:us-east-1:123456789012:secret:agent-bom/conn-key"
    denial = RuntimeError("AccessDeniedException: not authorized to GetSecretValue on agent-bom/conn-key")
    fake = _FakeSecretsClient(error=denial)
    _patch_client(monkeypatch, fake)
    connection_crypto.reset_key_cache()

    with pytest.raises(connection_crypto.ConnectionSecretError) as excinfo:
        connection_crypto.encrypt_secret("ext-id")
    message = str(excinfo.value)
    assert "conn-key" not in message
    assert "AccessDenied" not in message
    assert _TEST_KEY not in message


def test_aws_kms_provider_unwraps_data_key(monkeypatch: Any) -> None:
    data_key = os.urandom(32)  # what GenerateDataKey(NumberOfBytes=32) returns
    wrapped = base64.b64encode(b"kms-wrapped-ciphertext-blob").decode("ascii")
    os.environ[connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV] = connection_crypto.PROVIDER_AWS_KMS
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = wrapped
    fake = _FakeKmsClient(plaintext=data_key)
    _patch_client(monkeypatch, fake)
    connection_crypto.reset_key_cache()

    assert connection_crypto.connections_key_configured() is True
    token = connection_crypto.encrypt_secret("ext-id")
    assert connection_crypto.decrypt_secret(token) == "ext-id"
    assert fake.calls == 1


def test_aws_kms_denial_fails_closed_without_leaking(monkeypatch: Any) -> None:
    os.environ[connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV] = connection_crypto.PROVIDER_AWS_KMS
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = base64.b64encode(b"blob").decode("ascii")
    denial = RuntimeError("AccessDeniedException: not authorized to Decrypt with arn:aws:kms:us-east-1:123456789012:key/abc-123")
    fake = _FakeKmsClient(error=denial)
    _patch_client(monkeypatch, fake)
    connection_crypto.reset_key_cache()

    with pytest.raises(connection_crypto.ConnectionSecretError) as excinfo:
        connection_crypto.encrypt_secret("ext-id")
    message = str(excinfo.value)
    assert "arn:aws:kms" not in message
    assert "AccessDenied" not in message


def test_aws_kms_malformed_wrapped_key_fails_closed(monkeypatch: Any) -> None:
    os.environ[connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV] = connection_crypto.PROVIDER_AWS_KMS
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = "not!valid!base64!!"
    fake = _FakeKmsClient(plaintext=os.urandom(32))
    _patch_client(monkeypatch, fake)
    connection_crypto.reset_key_cache()

    with pytest.raises(connection_crypto.ConnectionSecretError):
        connection_crypto.encrypt_secret("ext-id")
    # Malformed base64 is rejected before any KMS call.
    assert fake.calls == 0


def test_resolved_key_cached_until_reset(monkeypatch: Any) -> None:
    os.environ[connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV] = connection_crypto.PROVIDER_AWS_SECRETS
    os.environ[connection_crypto.CONNECTIONS_KEY_REF_ENV] = "arn:aws:secretsmanager:us-east-1:123456789012:secret:agent-bom/conn-key"
    fake = _FakeSecretsClient(secret_string=_TEST_KEY)
    _patch_client(monkeypatch, fake)
    connection_crypto.reset_key_cache()

    connection_crypto.encrypt_secret("a")
    connection_crypto.encrypt_secret("b")
    connection_crypto.decrypt_secret(connection_crypto.encrypt_secret("c"))
    assert fake.calls == 1  # one fetch served every operation

    connection_crypto.reset_key_cache()
    connection_crypto.encrypt_secret("d")
    assert fake.calls == 2  # reset forces a fresh resolution


def test_unknown_provider_fails_closed() -> None:
    os.environ[connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV] = "azure-keyvault"
    connection_crypto.reset_key_cache()

    assert connection_crypto.connections_key_configured() is False
    with pytest.raises(connection_crypto.ConnectionSecretError):
        connection_crypto.encrypt_secret("ext-id")


# --------------------------------------------------------------------------- #
# Key provider: HashiCorp Vault (KV v2), fail-closed, no token/key leak.
# The shared HTTP client is mocked at the http_client.sync_get seam.
# --------------------------------------------------------------------------- #


class _FakeVaultResponse:
    """Stand-in for an httpx.Response from a Vault KV v2 read."""

    def __init__(self, *, status_code: int = 200, payload: Any = None, raise_json: bool = False) -> None:
        self.status_code = status_code
        self._payload = payload
        self._raise_json = raise_json

    def json(self) -> Any:
        if self._raise_json:
            raise ValueError("not json")
        return self._payload


def _vault_payload(key: str, field: str = "key") -> dict[str, Any]:
    """A well-formed KV v2 read payload carrying the Fernet key at *field*."""
    return {"data": {"data": {field: key}, "metadata": {"version": 1}}}


def _configure_vault(monkeypatch: Any, *, ref: str = "secret/agent-bom/conn-key") -> None:
    monkeypatch.setenv(connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV, connection_crypto.PROVIDER_VAULT)
    monkeypatch.setenv(connection_crypto.VAULT_ADDR_ENV, "https://vault.internal:8200")
    monkeypatch.setenv(connection_crypto.VAULT_TOKEN_ENV, "s.super-secret-vault-token")
    monkeypatch.setenv(connection_crypto.CONNECTIONS_KEY_REF_ENV, ref)
    os.environ.pop(connection_crypto.CONNECTIONS_KEY_ENV, None)
    connection_crypto.reset_key_cache()


def _patch_vault_get(monkeypatch: Any, response: Any) -> dict[str, Any]:
    """Patch http_client.sync_get; capture the url + headers it was called with."""
    from agent_bom import http_client

    captured: dict[str, Any] = {"calls": 0}

    def _fake_get(url: str, timeout: Any = None, headers: Any = None) -> Any:
        captured["calls"] += 1
        captured["url"] = url
        captured["headers"] = headers
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(http_client, "sync_get", _fake_get)
    return captured


def test_vault_provider_round_trip(monkeypatch: Any) -> None:
    _configure_vault(monkeypatch)
    captured = _patch_vault_get(monkeypatch, _FakeVaultResponse(payload=_vault_payload(_TEST_KEY)))

    assert connection_crypto.connections_key_configured() is True
    token = connection_crypto.encrypt_secret("ext-id")
    assert connection_crypto.decrypt_secret(token) == "ext-id"
    # KV v2 data path + token header; resolved once then served from cache.
    assert captured["url"] == "https://vault.internal:8200/v1/secret/data/agent-bom/conn-key"
    assert captured["headers"]["X-Vault-Token"] == "s.super-secret-vault-token"
    assert captured["calls"] == 1


def test_vault_custom_field(monkeypatch: Any) -> None:
    _configure_vault(monkeypatch, ref="secret/agent-bom/conn#fernet")
    _patch_vault_get(monkeypatch, _FakeVaultResponse(payload=_vault_payload(_TEST_KEY, field="fernet")))

    token = connection_crypto.encrypt_secret("ext-id")
    assert connection_crypto.decrypt_secret(token) == "ext-id"


def test_vault_missing_addr_fails_closed(monkeypatch: Any) -> None:
    _configure_vault(monkeypatch)
    monkeypatch.delenv(connection_crypto.VAULT_ADDR_ENV, raising=False)
    captured = _patch_vault_get(monkeypatch, _FakeVaultResponse(payload=_vault_payload(_TEST_KEY)))
    connection_crypto.reset_key_cache()

    assert connection_crypto.connections_key_configured() is False
    with pytest.raises(connection_crypto.ConnectionSecretError):
        connection_crypto.encrypt_secret("ext-id")
    assert captured["calls"] == 0  # never reached the network without an address


def test_vault_missing_token_fails_closed(monkeypatch: Any) -> None:
    _configure_vault(monkeypatch)
    monkeypatch.delenv(connection_crypto.VAULT_TOKEN_ENV, raising=False)
    captured = _patch_vault_get(monkeypatch, _FakeVaultResponse(payload=_vault_payload(_TEST_KEY)))
    connection_crypto.reset_key_cache()

    assert connection_crypto.connections_key_configured() is False
    with pytest.raises(connection_crypto.ConnectionSecretError):
        connection_crypto.encrypt_secret("ext-id")
    assert captured["calls"] == 0


def test_vault_missing_field_fails_closed(monkeypatch: Any) -> None:
    _configure_vault(monkeypatch)
    # Body is well-formed KV v2 but the configured field is absent.
    _patch_vault_get(monkeypatch, _FakeVaultResponse(payload=_vault_payload(_TEST_KEY, field="other")))

    with pytest.raises(connection_crypto.ConnectionSecretError):
        connection_crypto.encrypt_secret("ext-id")


def test_vault_non_200_fails_closed_without_leaking(monkeypatch: Any) -> None:
    _configure_vault(monkeypatch)
    _patch_vault_get(monkeypatch, _FakeVaultResponse(status_code=403, payload={"errors": ["permission denied"]}))

    with pytest.raises(connection_crypto.ConnectionSecretError) as excinfo:
        connection_crypto.encrypt_secret("ext-id")
    message = str(excinfo.value)
    assert "s.super-secret-vault-token" not in message
    assert _TEST_KEY not in message
    assert "permission denied" not in message


def test_vault_malformed_body_fails_closed(monkeypatch: Any) -> None:
    _configure_vault(monkeypatch)
    _patch_vault_get(monkeypatch, _FakeVaultResponse(payload="not-a-dict"))

    with pytest.raises(connection_crypto.ConnectionSecretError) as excinfo:
        connection_crypto.encrypt_secret("ext-id")
    assert "s.super-secret-vault-token" not in str(excinfo.value)


def test_vault_unreachable_fails_closed_without_leaking(monkeypatch: Any) -> None:
    _configure_vault(monkeypatch)
    # sync_get returns None when retries are exhausted.
    _patch_vault_get(monkeypatch, None)

    with pytest.raises(connection_crypto.ConnectionSecretError) as excinfo:
        connection_crypto.encrypt_secret("ext-id")
    assert "s.super-secret-vault-token" not in str(excinfo.value)


def test_vault_transport_error_does_not_leak_token(monkeypatch: Any) -> None:
    _configure_vault(monkeypatch)
    boom = RuntimeError("connect to https://vault.internal:8200 with token s.super-secret-vault-token failed")
    _patch_vault_get(monkeypatch, boom)

    with pytest.raises(connection_crypto.ConnectionSecretError) as excinfo:
        connection_crypto.encrypt_secret("ext-id")
    assert "s.super-secret-vault-token" not in str(excinfo.value)


# --------------------------------------------------------------------------- #
# MultiFernet key rotation: encrypt with the primary, decrypt with any key.
# --------------------------------------------------------------------------- #


def test_rotation_old_ciphertext_decrypts_after_new_primary() -> None:
    old_key = _TEST_KEY
    new_key = Fernet.generate_key().decode("ascii")

    # Encrypt under the original single key.
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = old_key
    connection_crypto.reset_key_cache()
    token = connection_crypto.encrypt_secret("ext-id")

    # Rotate: new key becomes primary, old key retained for decrypt.
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = f"{new_key},{old_key}"
    connection_crypto.reset_key_cache()
    assert connection_crypto.decrypt_secret(token) == "ext-id"


def test_rotation_encrypts_with_primary_key() -> None:
    new_key = Fernet.generate_key().decode("ascii")
    old_key = _TEST_KEY

    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = f"{new_key},{old_key}"
    connection_crypto.reset_key_cache()
    token = connection_crypto.encrypt_secret("ext-id")

    # The token must decrypt under the primary (new) key alone...
    assert Fernet(new_key.encode("ascii")).decrypt(token.encode("ascii")).decode() == "ext-id"
    # ...and NOT under the retired (old) key alone.
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = old_key
    connection_crypto.reset_key_cache()
    with pytest.raises(connection_crypto.ConnectionSecretError):
        connection_crypto.decrypt_secret(token)


def test_rotation_round_trip_with_multiple_keys() -> None:
    keys = ",".join(Fernet.generate_key().decode("ascii") for _ in range(3))
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = keys
    connection_crypto.reset_key_cache()

    token = connection_crypto.encrypt_secret("value-123")
    assert token != "value-123"
    assert connection_crypto.decrypt_secret(token) == "value-123"


def test_single_key_unchanged_is_plain_fernet() -> None:
    from cryptography.fernet import Fernet as _Fernet
    from cryptography.fernet import MultiFernet as _MultiFernet

    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = _TEST_KEY
    connection_crypto.reset_key_cache()
    cipher = connection_crypto._fernet()
    assert isinstance(cipher, _Fernet)
    assert not isinstance(cipher, _MultiFernet)


def test_rotation_via_vault_resolved_list(monkeypatch: Any) -> None:
    old_key = _TEST_KEY
    new_key = Fernet.generate_key().decode("ascii")

    # Vault returns a comma-separated rotation list in the single KV field.
    _configure_vault(monkeypatch)
    _patch_vault_get(monkeypatch, _FakeVaultResponse(payload=_vault_payload(f"{new_key},{old_key}")))

    token = connection_crypto.encrypt_secret("ext-id")
    # Primary (new) key encrypts; round-trips through the MultiFernet.
    assert connection_crypto.decrypt_secret(token) == "ext-id"
    assert Fernet(new_key.encode("ascii")).decrypt(token.encode("ascii")).decode() == "ext-id"


# --------------------------------------------------------------------------- #
# API: RBAC, no-secret responses, tenant scoping
# --------------------------------------------------------------------------- #


def _app() -> Any:
    # Trusted-proxy auth + tenant are resolved per request by the middleware, so
    # the module-level app singleton is sufficient (matches the cloud parity tests).
    from agent_bom.api.server import app

    return app


def _create_body() -> dict[str, Any]:
    return {
        "provider": "aws",
        "display_name": "prod-readonly",
        "role_ref": "arn:aws:iam::123456789012:role/agent-bom-readonly",
        "external_id": "super-secret-external-id",
        "regions": ["us-east-1"],
    }


def test_api_requires_authentication() -> None:
    client = TestClient(_app())
    assert client.get("/v1/cloud/connections").status_code == 401
    assert client.post("/v1/cloud/connections", json=_create_body()).status_code == 401


def test_api_rejects_underprivileged_role() -> None:
    client = TestClient(_app())
    resp = client.post("/v1/cloud/connections", json=_create_body(), headers=_proxy_headers(role="viewer"))
    assert resp.status_code == 403


def test_api_create_response_never_contains_secret() -> None:
    client = TestClient(_app())
    resp = client.post("/v1/cloud/connections", json=_create_body(), headers=_proxy_headers())
    assert resp.status_code == 201
    body = resp.json()
    flat = str(body)
    assert "super-secret-external-id" not in flat
    assert "external_id" not in body
    assert "external_id_encrypted" not in body
    assert body["has_external_id"] is True
    assert body["provider"] == "aws"
    assert body["status"] == STATUS_PENDING
    assert body["last_scan_id"] is None


def test_api_list_get_include_last_scan_id_and_never_contain_secret() -> None:
    store = InMemoryConnectionStore()
    record = _record("tenant-alpha")
    record.status = "active"
    record.last_scan_at = "2026-06-27T01:00:00+00:00"
    record.last_scan_id = "scan-123"
    store.put(record)
    set_connection_store(store)

    client = TestClient(_app())
    get_body = client.get(f"/v1/cloud/connections/{record.id}", headers=_proxy_headers()).json()
    list_body = client.get("/v1/cloud/connections", headers=_proxy_headers()).json()
    listed = list_body["connections"][0]

    assert get_body["last_scan_id"] == "scan-123"
    assert listed["last_scan_id"] == "scan-123"
    for body in (get_body, listed):
        flat = str(body)
        assert "super-secret-external-id" not in flat
        assert "external_id" not in body
        assert "external_id_encrypted" not in body
        assert body["has_external_id"] is True


def test_api_list_get_delete_tenant_scoped() -> None:
    client = TestClient(_app())
    created = client.post("/v1/cloud/connections", json=_create_body(), headers=_proxy_headers(tenant="tenant-alpha")).json()
    cid = created["id"]

    # Same tenant can read it; another tenant cannot.
    assert client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).status_code == 200
    assert client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-beta")).status_code == 404

    listing = client.get("/v1/cloud/connections", headers=_proxy_headers(tenant="tenant-beta")).json()
    assert listing["connections"] == []

    # Cross-tenant delete is a 404; same-tenant delete works.
    assert client.delete(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-beta")).status_code == 404
    assert client.delete(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).status_code == 204
    assert client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).status_code == 404


def test_api_unsupported_provider_400() -> None:
    client = TestClient(_app())
    body = _create_body()
    body["provider"] = "digitalocean"
    resp = client.post("/v1/cloud/connections", json=body, headers=_proxy_headers())
    assert resp.status_code == 400


def test_api_missing_key_fails_closed_503() -> None:
    os.environ.pop(connection_crypto.CONNECTIONS_KEY_ENV, None)
    client = TestClient(_app())
    resp = client.post("/v1/cloud/connections", json=_create_body(), headers=_proxy_headers())
    assert resp.status_code == 503
    # And nothing was persisted.
    listing = client.get("/v1/cloud/connections", headers=_proxy_headers()).json()
    assert listing["connections"] == []


# --------------------------------------------------------------------------- #
# API: recurring scan schedule (scan_interval_minutes) — Phase B.2
# --------------------------------------------------------------------------- #


def test_api_create_default_interval_is_manual_only() -> None:
    client = TestClient(_app())
    created = client.post("/v1/cloud/connections", json=_create_body(), headers=_proxy_headers()).json()
    assert created["scan_interval_minutes"] is None


def test_api_create_with_interval_persists() -> None:
    client = TestClient(_app())
    body = _create_body()
    body["scan_interval_minutes"] = 60
    created = client.post("/v1/cloud/connections", json=body, headers=_proxy_headers()).json()
    assert created["scan_interval_minutes"] == 60


def test_api_create_rejects_interval_below_minimum() -> None:
    client = TestClient(_app())
    body = _create_body()
    body["scan_interval_minutes"] = 5
    resp = client.post("/v1/cloud/connections", json=body, headers=_proxy_headers())
    assert resp.status_code == 400


def test_api_patch_sets_and_clears_interval() -> None:
    client = TestClient(_app())
    cid = client.post("/v1/cloud/connections", json=_create_body(), headers=_proxy_headers()).json()["id"]

    set_resp = client.patch(
        f"/v1/cloud/connections/{cid}",
        json={"scan_interval_minutes": 120},
        headers=_proxy_headers(),
    )
    assert set_resp.status_code == 200
    assert set_resp.json()["scan_interval_minutes"] == 120

    clear_resp = client.patch(
        f"/v1/cloud/connections/{cid}",
        json={"scan_interval_minutes": None},
        headers=_proxy_headers(),
    )
    assert clear_resp.status_code == 200
    assert clear_resp.json()["scan_interval_minutes"] is None


def test_api_patch_rejects_interval_below_minimum() -> None:
    client = TestClient(_app())
    cid = client.post("/v1/cloud/connections", json=_create_body(), headers=_proxy_headers()).json()["id"]
    resp = client.patch(f"/v1/cloud/connections/{cid}", json={"scan_interval_minutes": 1}, headers=_proxy_headers())
    assert resp.status_code == 400


def test_api_patch_requires_scan_permission() -> None:
    client = TestClient(_app())
    cid = client.post("/v1/cloud/connections", json=_create_body(), headers=_proxy_headers()).json()["id"]
    resp = client.patch(
        f"/v1/cloud/connections/{cid}",
        json={"scan_interval_minutes": 60},
        headers=_proxy_headers(role="viewer"),
    )
    assert resp.status_code == 403


# --------------------------------------------------------------------------- #
# Broker: AWS AssumeRole with the decrypted ExternalId; non-AWS planned
# --------------------------------------------------------------------------- #


def test_broker_aws_assume_role_uses_decrypted_external_id(monkeypatch: pytest.MonkeyPatch) -> None:
    boto3 = pytest.importorskip("boto3")
    from agent_bom.cloud import connection_broker

    captured: dict[str, Any] = {}

    class _FakeSTS:
        def assume_role(self, **kwargs: Any) -> dict[str, Any]:
            captured.update(kwargs)
            return {
                "Credentials": {
                    "AccessKeyId": "ASIA-TEST",
                    "SecretAccessKey": "secret",
                    "SessionToken": "token",
                }
            }

    sessions: dict[str, Any] = {}

    def _fake_client(service: str, *args: Any, **kwargs: Any) -> Any:
        assert service == "sts"
        return _FakeSTS()

    def _fake_session(**kwargs: Any) -> Any:
        sessions.update(kwargs)
        return object()

    monkeypatch.setattr(boto3, "client", _fake_client)
    monkeypatch.setattr(boto3, "Session", _fake_session)

    record = _record("tenant-a")
    connection_broker.broker_session(record)

    assert captured["RoleArn"] == record.role_ref
    assert captured["ExternalId"] == "super-secret-external-id"
    assert sessions["aws_access_key_id"] == "ASIA-TEST"
    assert sessions["aws_session_token"] == "token"
    assert sessions["region_name"] == "us-east-1"


def _install_fake_module(monkeypatch: pytest.MonkeyPatch, dotted: str, leaf: types.ModuleType) -> None:
    """Inject a fake module (and any missing parent packages) into sys.modules.

    Lets the broker's lazy ``from x.y import z`` resolve a fake SDK whether or not
    the real SDK is installed; monkeypatch restores sys.modules afterwards.
    """
    parts = dotted.split(".")
    for i in range(1, len(parts) + 1):
        name = ".".join(parts[:i])
        module = leaf if name == dotted else sys.modules.get(name) or types.ModuleType(name)
        monkeypatch.setitem(sys.modules, name, module)
    for i in range(1, len(parts)):
        parent = sys.modules[".".join(parts[:i])]
        monkeypatch.setattr(parent, parts[i], sys.modules[".".join(parts[: i + 1])], raising=False)


def _azure_record() -> CloudConnectionRecord:
    record = _record("tenant-a", provider="azure")
    record.role_ref = "app-client-id-123"
    record.external_id_encrypted = connection_crypto.encrypt_secret("super-secret-client-secret")
    record.auth_params = {"tenant_id": "tenant-guid", "subscription_id": "sub-guid"}
    return record


def _gcp_record() -> CloudConnectionRecord:
    record = _record("tenant-a", provider="gcp")
    record.role_ref = "sa@project.iam.gserviceaccount.com"
    record.external_id_encrypted = connection_crypto.encrypt_secret('{"type": "service_account", "project_id": "proj"}')
    record.auth_params = {"project_id": "proj"}
    return record


def _snowflake_record(pem: str) -> CloudConnectionRecord:
    record = _record("tenant-a", provider="snowflake")
    record.role_ref = "ACME-ACCT"
    record.external_id_encrypted = connection_crypto.encrypt_secret(pem)
    record.auth_params = {"user": "ABOM_SVC", "role": "ABOM_READONLY", "warehouse": "ABOM_WH"}
    return record


def test_broker_azure_uses_decrypted_client_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cloud import connection_broker

    captured: dict[str, Any] = {}
    sentinel = object()

    class _FakeClientSecretCredential:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    def _factory(**kwargs: Any) -> Any:
        captured.update(kwargs)
        return sentinel

    fake = types.ModuleType("azure.identity")
    fake.ClientSecretCredential = _factory  # type: ignore[attr-defined]
    _install_fake_module(monkeypatch, "azure.identity", fake)

    result = connection_broker.broker_session(_azure_record())
    assert result is sentinel
    assert captured["tenant_id"] == "tenant-guid"
    assert captured["client_id"] == "app-client-id-123"
    assert captured["client_secret"] == "super-secret-client-secret"


def test_broker_azure_missing_tenant_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cloud import connection_broker

    fake = types.ModuleType("azure.identity")
    fake.ClientSecretCredential = lambda **kwargs: object()  # type: ignore[attr-defined]
    _install_fake_module(monkeypatch, "azure.identity", fake)

    record = _azure_record()
    record.auth_params = {}
    with pytest.raises(connection_broker.ConnectionBrokerError):
        connection_broker.broker_session(record)


def test_broker_gcp_builds_readonly_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cloud import connection_broker

    captured: dict[str, Any] = {}
    sentinel = object()

    class _FakeCreds:
        @classmethod
        def from_service_account_info(cls, info: Any, scopes: Any = None) -> Any:
            captured["info"] = info
            captured["scopes"] = scopes
            return sentinel

    sa_mod = types.ModuleType("google.oauth2.service_account")
    sa_mod.Credentials = _FakeCreds  # type: ignore[attr-defined]
    _install_fake_module(monkeypatch, "google.oauth2.service_account", sa_mod)
    oauth2 = sys.modules["google.oauth2"]
    monkeypatch.setattr(oauth2, "service_account", sa_mod, raising=False)

    result = connection_broker.broker_session(_gcp_record())
    assert result is sentinel
    assert captured["info"]["project_id"] == "proj"
    # Scoped to the read-only cloud-platform scope so it cannot authorize a write.
    assert captured["scopes"] == [connection_broker._GCP_READONLY_SCOPE]


def test_broker_gcp_bad_key_json_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cloud import connection_broker

    sa_mod = types.ModuleType("google.oauth2.service_account")
    sa_mod.Credentials = type("C", (), {"from_service_account_info": staticmethod(lambda *a, **k: object())})  # type: ignore[attr-defined]
    _install_fake_module(monkeypatch, "google.oauth2.service_account", sa_mod)
    monkeypatch.setattr(sys.modules["google.oauth2"], "service_account", sa_mod, raising=False)

    record = _gcp_record()
    record.external_id_encrypted = connection_crypto.encrypt_secret("not-json-at-all")
    with pytest.raises(connection_broker.ConnectionBrokerError) as exc:
        connection_broker.broker_session(record)
    assert "not-json-at-all" not in str(exc.value)


def _generate_test_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def test_broker_snowflake_keypair_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cloud import connection_broker

    captured: dict[str, Any] = {}
    sentinel = object()

    def _fake_connect(**kwargs: Any) -> Any:
        captured.update(kwargs)
        return sentinel

    connector = types.ModuleType("snowflake.connector")
    connector.connect = _fake_connect  # type: ignore[attr-defined]
    _install_fake_module(monkeypatch, "snowflake.connector", connector)

    result = connection_broker.broker_session(_snowflake_record(_generate_test_pem()))
    assert result is sentinel
    assert captured["account"] == "ACME-ACCT"
    assert captured["user"] == "ABOM_SVC"
    assert captured["role"] == "ABOM_READONLY"
    assert captured["warehouse"] == "ABOM_WH"
    # Key-pair auth: the private key is presented as DER bytes, never a password.
    assert isinstance(captured["private_key"], bytes)
    assert "password" not in captured


def test_broker_snowflake_bad_pem_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cloud import connection_broker

    connector = types.ModuleType("snowflake.connector")
    connector.connect = lambda **kwargs: object()  # type: ignore[attr-defined]
    _install_fake_module(monkeypatch, "snowflake.connector", connector)

    record = _snowflake_record("-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----")
    with pytest.raises(connection_broker.ConnectionBrokerError) as exc:
        connection_broker.broker_session(record)
    assert "not-a-real-key" not in str(exc.value)


@pytest.mark.parametrize("provider", ["azure", "gcp", "snowflake"])
def test_broker_secret_decrypt_failure_never_leaks(provider: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """A decrypt failure fails closed with no plaintext, for every provider.

    SDKs are faked so the broker reaches the decrypt step regardless of which
    extras are installed.
    """
    from agent_bom.cloud import connection_broker

    azure_mod = types.ModuleType("azure.identity")
    azure_mod.ClientSecretCredential = lambda **kwargs: object()  # type: ignore[attr-defined]
    _install_fake_module(monkeypatch, "azure.identity", azure_mod)
    sa_mod = types.ModuleType("google.oauth2.service_account")
    sa_mod.Credentials = type("C", (), {"from_service_account_info": staticmethod(lambda *a, **k: object())})  # type: ignore[attr-defined]
    _install_fake_module(monkeypatch, "google.oauth2.service_account", sa_mod)
    monkeypatch.setattr(sys.modules["google.oauth2"], "service_account", sa_mod, raising=False)
    connector = types.ModuleType("snowflake.connector")
    connector.connect = lambda **kwargs: object()  # type: ignore[attr-defined]
    _install_fake_module(monkeypatch, "snowflake.connector", connector)

    builders = {"azure": _azure_record, "gcp": _gcp_record, "snowflake": lambda: _snowflake_record(_generate_test_pem())}
    record = builders[provider]()
    # Corrupt the ciphertext so decryption fails closed.
    record.external_id_encrypted = "garbage-token"
    with pytest.raises(connection_broker.ConnectionBrokerError) as exc:
        connection_broker.broker_session(record)
    assert "garbage-token" not in str(exc.value)


def test_broker_unknown_provider_value_error() -> None:
    from agent_bom.cloud import connection_broker

    record = _record("tenant-a", provider="bogus")
    with pytest.raises(ValueError):
        connection_broker.broker_session(record)


def test_broker_secret_failure_does_not_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("boto3")
    from agent_bom.cloud import connection_broker

    record = _record("tenant-a")
    # Corrupt the ciphertext so decryption fails; error must not contain plaintext.
    record.external_id_encrypted = "garbage-token"
    with pytest.raises(connection_broker.ConnectionBrokerError) as exc:
        connection_broker.broker_session(record)
    assert "super-secret-external-id" not in str(exc.value)


# --------------------------------------------------------------------------- #
# Phase B: launch a read-only scan from a stored connection via the broker
# --------------------------------------------------------------------------- #


_BROKER_SESSION_SENTINEL = object()


def _install_scan_mocks(monkeypatch: pytest.MonkeyPatch, *, fail: bool = False) -> dict[str, Any]:
    """Patch the broker + AWS inventory/CIS the scan route reuses.

    Captures the session each discovery call receives so a test can assert the
    brokered session (not the local default chain) is what runs the scan.
    """
    from agent_bom.cloud import aws_cis_benchmark, aws_inventory, connection_broker

    calls: dict[str, Any] = {}

    def _fake_broker(record: CloudConnectionRecord, **kwargs: Any) -> Any:
        calls["broker_record_id"] = record.id
        if fail:
            raise connection_broker.ConnectionBrokerError(f"AssumeRole failed for connection {record.id}.")
        return _BROKER_SESSION_SENTINEL

    def _fake_inventory(region: str | None = None, force: bool = False, session: Any = None, **kwargs: Any) -> dict[str, Any]:
        calls["inventory_session"] = session
        calls["inventory_force"] = force
        return {
            "provider": "aws",
            "status": "ok",
            "account_id": "123456789012",
            "region": region or "us-east-1",
            "buckets": [],
            "instances": [],
            "security_groups": [],
            "roles": [],
            "users": [],
            "warnings": [],
        }

    class _FakeCISReport:
        def to_dict(self) -> dict[str, Any]:
            return {
                "benchmark": "CIS AWS Foundations",
                "benchmark_version": "3.0.0",
                "account_id": "123456789012",
                "region": "us-east-1",
                "pass_rate": 50.0,
                "passed": 1,
                "failed": 1,
                "total": 2,
                "checks": [],
            }

    def _fake_cis(region: str | None = None, session: Any = None, **kwargs: Any) -> Any:
        calls["cis_session"] = session
        return _FakeCISReport()

    monkeypatch.setattr(connection_broker, "broker_session", _fake_broker)
    monkeypatch.setattr(aws_inventory, "discover_inventory", _fake_inventory)
    monkeypatch.setattr(aws_cis_benchmark, "run_benchmark", _fake_cis)
    return calls


def _seed_connection(tenant: str = "tenant-alpha", *, provider: str = "aws") -> str:
    """Create a connection through the API and return its id."""
    client = TestClient(_app())
    body = _create_body()
    body["provider"] = provider
    created = client.post("/v1/cloud/connections", json=body, headers=_proxy_headers(tenant=tenant)).json()
    return str(created["id"])


def test_scan_launch_brokers_runs_persists_and_marks_active(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_scan_mocks(monkeypatch)
    client = TestClient(_app())
    cid = _seed_connection("tenant-alpha")

    resp = client.post(f"/v1/cloud/connections/{cid}/scan", headers=_proxy_headers(tenant="tenant-alpha"))
    assert resp.status_code == 200
    body = resp.json()

    # The broker was used and the brokered session (not the default chain) ran both scans.
    assert calls["broker_record_id"] == cid
    assert calls["inventory_session"] is _BROKER_SESSION_SENTINEL
    assert calls["cis_session"] is _BROKER_SESSION_SENTINEL
    assert calls["inventory_force"] is True

    assert body["provider"] == "aws"
    scan_id = body["scan_id"]
    assert scan_id
    assert body["connection"]["last_scan_id"] == scan_id
    assert body["cis_benchmark"]["total"] == 2
    assert body["inventory"]["status"] == "ok"

    # Results persisted through the existing scan store (no parallel path).
    from agent_bom.api.stores import _get_store

    job = _get_store().get(scan_id, "tenant-alpha")
    assert job is not None
    assert job.result is not None
    assert job.result.get("cloud_inventory", {}).get("provider") == "aws"
    assert job.result.get("cis_benchmark", {}).get("total") == 2
    assert job.result.get("scan_sources") == ["cloud_connection", "cloud:aws"]

    # Connection status flipped to active with last_scan_at set, no error detail.
    fetched = client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).json()
    assert fetched["status"] == "active"
    assert fetched["last_scan_at"]
    assert fetched["last_scan_id"] == scan_id
    assert fetched["status_detail"] == ""
    listing = client.get("/v1/cloud/connections", headers=_proxy_headers(tenant="tenant-alpha")).json()
    assert listing["connections"][0]["last_scan_id"] == scan_id
    # No secret anywhere in the response surface.
    assert "super-secret-external-id" not in str(body)


def test_scan_failure_marks_error_without_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_scan_mocks(monkeypatch, fail=True)
    client = TestClient(_app())
    cid = _seed_connection("tenant-alpha")

    resp = client.post(f"/v1/cloud/connections/{cid}/scan", headers=_proxy_headers(tenant="tenant-alpha"))
    assert resp.status_code == 502
    assert "super-secret-external-id" not in str(resp.json())

    fetched = client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).json()
    assert fetched["status"] == "error"
    assert fetched["status_detail"]
    assert "super-secret-external-id" not in fetched["status_detail"]
    assert fetched["last_scan_at"] is None
    assert fetched["last_scan_id"] is None


def test_scan_requires_scan_permission(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_scan_mocks(monkeypatch)
    cid = _seed_connection("tenant-alpha")
    client = TestClient(_app())
    resp = client.post(f"/v1/cloud/connections/{cid}/scan", headers=_proxy_headers(role="viewer", tenant="tenant-alpha"))
    assert resp.status_code == 403


def test_scan_is_tenant_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_scan_mocks(monkeypatch)
    cid = _seed_connection("tenant-alpha")
    client = TestClient(_app())
    # Another tenant cannot scan (or even resolve) this connection.
    resp = client.post(f"/v1/cloud/connections/{cid}/scan", headers=_proxy_headers(tenant="tenant-beta"))
    assert resp.status_code == 404


def test_scan_missing_connection_404(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_scan_mocks(monkeypatch)
    client = TestClient(_app())
    resp = client.post(f"/v1/cloud/connections/{uuid.uuid4()}/scan", headers=_proxy_headers(tenant="tenant-alpha"))
    assert resp.status_code == 404


def test_connection_test_brokers_without_scan_persistence(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.store import InMemoryJobStore
    from agent_bom.api.stores import _get_store, set_job_store
    from agent_bom.cloud import connection_broker

    calls: dict[str, Any] = {}
    set_job_store(InMemoryJobStore())

    def _fake_broker(record: CloudConnectionRecord, **kwargs: Any) -> Any:
        calls["broker_record_id"] = record.id
        calls["session_name"] = kwargs.get("session_name")
        return _BROKER_SESSION_SENTINEL

    monkeypatch.setattr(connection_broker, "broker_session", _fake_broker)
    client = TestClient(_app())
    cid = _seed_connection("tenant-alpha")

    resp = client.post(f"/v1/cloud/connections/{cid}/test", headers=_proxy_headers(tenant="tenant-alpha"))

    assert resp.status_code == 200
    body = resp.json()
    assert body["schema_version"] == "cloud.connections.test.v1"
    assert body["provider"] == "aws"
    assert body["status"] == "ok"
    assert "scan_id" not in body
    assert calls["broker_record_id"] == cid
    assert str(calls["session_name"]).startswith("agent-bom-test-")

    assert _get_store().list_all("tenant-alpha") == []
    fetched = client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).json()
    assert fetched["status"] == "active"
    assert fetched["last_scan_at"] is None
    assert fetched["last_scan_id"] is None
    assert "super-secret-external-id" not in str(body)


def test_connection_test_failure_marks_error_without_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cloud import connection_broker

    def _fake_broker(record: CloudConnectionRecord, **kwargs: Any) -> Any:
        raise connection_broker.ConnectionBrokerError("failed for super-secret-external-id")

    monkeypatch.setattr(connection_broker, "broker_session", _fake_broker)
    cid = _seed_connection("tenant-alpha")
    client = TestClient(_app())

    resp = client.post(f"/v1/cloud/connections/{cid}/test", headers=_proxy_headers(tenant="tenant-alpha"))

    assert resp.status_code == 502
    assert "super-secret-external-id" not in str(resp.json())
    fetched = client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).json()
    assert fetched["status"] == "error"
    assert "super-secret-external-id" not in fetched["status_detail"]
    assert fetched["last_scan_id"] is None


def test_connection_test_is_tenant_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cloud import connection_broker

    monkeypatch.setattr(connection_broker, "broker_session", lambda record, **kwargs: _BROKER_SESSION_SENTINEL)
    cid = _seed_connection("tenant-alpha")
    client = TestClient(_app())

    resp = client.post(f"/v1/cloud/connections/{cid}/test", headers=_proxy_headers(tenant="tenant-beta"))

    assert resp.status_code == 404


class _FakeProviderCIS:
    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark": "CIS Provider",
            "benchmark_version": "1.0",
            "pass_rate": 50.0,
            "passed": 1,
            "failed": 1,
            "total": 2,
            "checks": [],
        }


def _fake_inventory_payload(provider: str) -> dict[str, Any]:
    return {
        "provider": provider,
        "status": "ok",
        "account_id": "acct",
        "subscription_id": "acct",
        "project_id": "acct",
        "region": "",
        "buckets": [],
        "instances": [],
        "security_groups": [],
        "roles": [],
        "users": [],
        "warnings": [],
    }


class _FakeSnowflakeConn:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_scan_azure_brokers_runs_persists_and_marks_active(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cloud import azure_cis_benchmark, azure_inventory, connection_broker

    calls: dict[str, Any] = {}
    monkeypatch.setattr(connection_broker, "broker_session", lambda record, **k: _BROKER_SESSION_SENTINEL)

    def _inv(subscription_id: Any = None, credential: Any = None, force: bool = False, **k: Any) -> dict[str, Any]:
        calls["inv_cred"] = credential
        calls["inv_force"] = force
        return _fake_inventory_payload("azure")

    def _cis(subscription_id: Any = None, credential: Any = None, **k: Any) -> Any:
        calls["cis_cred"] = credential
        return _FakeProviderCIS()

    monkeypatch.setattr(azure_inventory, "discover_inventory", _inv)
    monkeypatch.setattr(azure_cis_benchmark, "run_benchmark", _cis)

    cid = _seed_connection("tenant-alpha", provider="azure")
    client = TestClient(_app())
    resp = client.post(f"/v1/cloud/connections/{cid}/scan", headers=_proxy_headers(tenant="tenant-alpha"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["provider"] == "azure"
    assert calls["inv_cred"] is _BROKER_SESSION_SENTINEL
    assert calls["cis_cred"] is _BROKER_SESSION_SENTINEL
    assert calls["inv_force"] is True
    assert body["inventory"]["status"] == "ok"
    assert body["cis_benchmark"]["total"] == 2

    from agent_bom.api.stores import _get_store

    job = _get_store().get(body["scan_id"], "tenant-alpha")
    assert job is not None
    assert job.result is not None
    assert job.result.get("scan_sources") == ["cloud_connection", "cloud:azure"]
    fetched = client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).json()
    assert fetched["status"] == "active"
    assert fetched["last_scan_at"]


def test_scan_gcp_brokers_runs_persists_and_marks_active(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cloud import connection_broker, gcp_cis_benchmark, gcp_inventory

    calls: dict[str, Any] = {}
    monkeypatch.setattr(connection_broker, "broker_session", lambda record, **k: _BROKER_SESSION_SENTINEL)

    def _inv(project_id: Any = None, credentials: Any = None, force: bool = False, **k: Any) -> dict[str, Any]:
        calls["inv_creds"] = credentials
        calls["inv_force"] = force
        return _fake_inventory_payload("gcp")

    def _cis(project_id: Any = None, credentials: Any = None, **k: Any) -> Any:
        calls["cis_creds"] = credentials
        return _FakeProviderCIS()

    monkeypatch.setattr(gcp_inventory, "discover_inventory", _inv)
    monkeypatch.setattr(gcp_cis_benchmark, "run_benchmark", _cis)

    cid = _seed_connection("tenant-alpha", provider="gcp")
    client = TestClient(_app())
    resp = client.post(f"/v1/cloud/connections/{cid}/scan", headers=_proxy_headers(tenant="tenant-alpha"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["provider"] == "gcp"
    assert calls["inv_creds"] is _BROKER_SESSION_SENTINEL
    assert calls["cis_creds"] is _BROKER_SESSION_SENTINEL
    assert calls["inv_force"] is True
    assert body["cis_benchmark"]["total"] == 2
    from agent_bom.api.stores import _get_store

    job = _get_store().get(body["scan_id"], "tenant-alpha")
    assert job is not None
    assert job.result is not None
    assert job.result.get("scan_sources") == ["cloud_connection", "cloud:gcp"]
    fetched = client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).json()
    assert fetched["status"] == "active"


def test_scan_snowflake_brokers_runs_persists_and_marks_active(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cloud import connection_broker, snowflake_cis_benchmark
    from agent_bom.cloud import snowflake as snowflake_discovery

    calls: dict[str, Any] = {}
    conn = _FakeSnowflakeConn()
    monkeypatch.setattr(connection_broker, "broker_session", lambda record, **k: conn)

    def _disc(conn: Any = None, **k: Any) -> Any:
        calls["disc_conn"] = conn
        return ([], [])

    def _cis(conn: Any = None, **k: Any) -> Any:
        calls["cis_conn"] = conn
        return _FakeProviderCIS()

    monkeypatch.setattr(snowflake_discovery, "discover", _disc)
    monkeypatch.setattr(snowflake_cis_benchmark, "run_benchmark", _cis)

    cid = _seed_connection("tenant-alpha", provider="snowflake")
    client = TestClient(_app())
    resp = client.post(f"/v1/cloud/connections/{cid}/scan", headers=_proxy_headers(tenant="tenant-alpha"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["provider"] == "snowflake"
    # The single brokered connection backs both discovery and CIS, and the route
    # closes it afterwards (discover/CIS do not close an injected connection).
    assert calls["disc_conn"] is conn
    assert calls["cis_conn"] is conn
    assert conn.closed is True
    assert body["inventory"]["agent_count"] == 0
    assert body["cis_benchmark"]["total"] == 2
    from agent_bom.api.stores import _get_store

    job = _get_store().get(body["scan_id"], "tenant-alpha")
    assert job is not None
    assert job.result is not None
    assert job.result.get("scan_sources") == ["cloud_connection", "cloud:snowflake"]
    assert job.result.get("cloud_inventory", {}).get("agent_count") == 0
    fetched = client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).json()
    assert fetched["status"] == "active"


def test_scan_sdk_missing_returns_clean_error_without_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """A provider whose SDK extra is not installed surfaces a clean error, no secret."""
    from agent_bom.cloud import connection_broker
    from agent_bom.cloud.base import CloudDiscoveryError

    def _broker(record: CloudConnectionRecord, **k: Any) -> Any:
        raise CloudDiscoveryError("azure-identity is required to broker Azure connections. Install with: pip install 'agent-bom[azure]'")

    monkeypatch.setattr(connection_broker, "broker_session", _broker)

    cid = _seed_connection("tenant-alpha", provider="azure")
    client = TestClient(_app())
    resp = client.post(f"/v1/cloud/connections/{cid}/scan", headers=_proxy_headers(tenant="tenant-alpha"))
    assert resp.status_code == 502
    assert "super-secret-external-id" not in str(resp.json())
    fetched = client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).json()
    assert fetched["status"] == "error"


def test_api_auth_params_round_trip_non_secret() -> None:
    client = TestClient(_app())
    body = _create_body()
    body["provider"] = "azure"
    body["auth_params"] = {"tenant_id": "t-guid", "subscription_id": "s-guid"}
    created = client.post("/v1/cloud/connections", json=body, headers=_proxy_headers()).json()
    assert created["auth_params"] == {"tenant_id": "t-guid", "subscription_id": "s-guid"}
    # Round-trips through GET unchanged and never carries the secret.
    fetched = client.get(f"/v1/cloud/connections/{created['id']}", headers=_proxy_headers()).json()
    assert fetched["auth_params"] == {"tenant_id": "t-guid", "subscription_id": "s-guid"}
    assert "external_id" not in fetched


def test_summarize_inventory_payload_redacts_raw_warnings() -> None:
    """Inventory summary must not echo exception-derived warnings (py/stack-trace-exposure)."""
    from agent_bom.mcp_tools.posture import _summarize_inventory_payload

    payload = {
        "status": "ok",
        "account_id": "030225640638",
        "warnings": [
            "Could not list roles: Traceback (most recent call last): RuntimeError boom",
            "AccessDenied: arn:aws:iam::...:user/x — assume failed: <stack>",
        ],
    }
    summary = _summarize_inventory_payload("aws", payload)
    warnings = summary["warnings"]
    assert warnings == ["2 provider discovery warning(s) — see server logs for detail."]
    blob = " ".join(warnings)
    assert "Traceback" not in blob and "AccessDenied" not in blob and "arn:aws:iam" not in blob


# Sensitive raw exception text (KMS broker / encryption path) must never reach the
# HTTP 503 body. The encryption failure mode is HIGH sensitivity, so the route
# uses sanitize_error(exc, generic=True): a fixed, non-diagnostic message.
_LEAKY_SECRET = "kms-key-id=arn:aws:kms:us-east-1:123456789012:key/abcd token=AKIASECRETVALUE at /etc/agent-bom/master.pem"


def test_create_503_on_encryption_failure_never_leaks_exception(monkeypatch: Any) -> None:
    from agent_bom.api.connection_crypto import ConnectionSecretError
    from agent_bom.api.routes import cloud_connections as routes

    def _boom(_value: str) -> str:
        raise ConnectionSecretError(_LEAKY_SECRET)

    monkeypatch.setattr(routes, "encrypt_secret", _boom)

    client = TestClient(_app())
    resp = client.post("/v1/cloud/connections", json=_create_body(), headers=_proxy_headers())

    assert resp.status_code == 503
    detail = resp.json()["detail"]
    # Generic, non-diagnostic message — and none of the leaky fragments survive.
    assert detail == "An internal error occurred. Please contact support."
    blob = str(resp.json())
    assert "arn:aws:kms" not in blob
    assert "AKIASECRETVALUE" not in blob
    assert "master.pem" not in blob
    assert "kms-key-id" not in blob
