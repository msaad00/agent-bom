"""Tests for the per-tenant cloud connections plane (Phase A).

Covers the store (CRUD + tenant isolation), at-rest encryption (ciphertext in
the DB column, decrypt round-trip, missing-key refuses to persist), the CRUD API
(RBAC, no-secret responses, tenant scoping), and the credential broker (AWS
AssumeRole with the decrypted ExternalId; non-AWS providers raise the planned
error).
"""

from __future__ import annotations

import base64
import os
import sqlite3
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


def test_broker_non_aws_provider_planned_error() -> None:
    from agent_bom.cloud import connection_broker

    for provider in ("azure", "gcp", "snowflake"):
        record = _record("tenant-a", provider=provider)
        with pytest.raises(NotImplementedError):
            connection_broker.broker_session(record)


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
    assert body["cis_benchmark"]["total"] == 2
    assert body["inventory"]["status"] == "ok"

    # Results persisted through the existing scan store (no parallel path).
    from agent_bom.api.stores import _get_store

    job = _get_store().get(scan_id, "tenant-alpha")
    assert job is not None
    assert job.result is not None
    assert job.result.get("cloud_inventory", {}).get("provider") == "aws"
    assert job.result.get("cis_benchmark", {}).get("total") == 2

    # Connection status flipped to active with last_scan_at set, no error detail.
    fetched = client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).json()
    assert fetched["status"] == "active"
    assert fetched["last_scan_at"]
    assert fetched["status_detail"] == ""
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


@pytest.mark.parametrize("provider", ["azure", "gcp", "snowflake"])
def test_scan_non_aws_provider_returns_planned(provider: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_scan_mocks(monkeypatch)
    cid = _seed_connection("tenant-alpha", provider=provider)
    client = TestClient(_app())
    resp = client.post(f"/v1/cloud/connections/{cid}/scan", headers=_proxy_headers(tenant="tenant-alpha"))
    assert resp.status_code == 501
    assert "planned" in resp.json()["detail"].lower()
    # The connection was not touched (still pending, no scan).
    fetched = client.get(f"/v1/cloud/connections/{cid}", headers=_proxy_headers(tenant="tenant-alpha")).json()
    assert fetched["status"] == STATUS_PENDING


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
